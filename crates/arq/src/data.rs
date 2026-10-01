//! Port of the "Data Plane" section of `internal/arq/arq.go`.

use crate::arq::Arq;
use crate::state::ArqState;
use crate::util::seq_behind;
use std::time::{Duration, Instant};

/// How long after storing a fresh STREAM_DATA packet we send one extra
/// STREAM_DATA_ACK for it, on top of the immediate one.
///
/// Forensics on the Go client (see task notes) measured its RTO for a lost
/// ACK at a median of ~0.3s and a max of ~1-2s under load. 150ms leaves
/// roughly half of that median as margin: it is late enough that almost all
/// deliveries only ever see the immediate ACK (the client's `ReceiveAck`
/// treats a re-ACK for a sequence number it has already retired as a pure
/// no-op — see the Go client citation in the task report), but early enough
/// to reliably land before the client's RTO fires and it retransmits a
/// packet whose sequence number may collide with new data a 16-bit wrap
/// later. Combined with `retransmit_loop` waking at least as often as
/// `REACK_DELAY` while any re-ACK is pending (see `loops.rs`), the worst-case
/// extra latency on top of this constant is one wake-up quantum, not a whole
/// idle-interval sleep.
pub(crate) const REACK_DELAY: Duration = Duration::from_millis(150);

/// Upper bound on `ArqState::pending_reacks`. This is deliberately much
/// bigger than any per-stream window: the FIFO holds one entry per *stored*
/// packet for `REACK_DELAY`, and a fast upload can sustain tens of thousands
/// of packets per second (measured well above 32768/0.15s), so bounding it by
/// `receive_window_size` (a few thousand) caused the front of the queue —
/// i.e. entries about to become due — to be evicted before they ever fired,
/// silently defeating the fix under exactly the high-throughput load it
/// targets. Sequence numbers only span 65536 values, so this caps the queue
/// at four full wraps' worth of entries: generous enough that eviction should
/// never happen in practice (each entry is 10 bytes, so the cap is a hard
/// ceiling of ~2.5MB per stream, not a real memory concern), while still
/// being a real, finite bound rather than unbounded growth if a stream is
/// ever abandoned without its retransmit loop draining the queue.
pub(crate) const REACK_QUEUE_CAP: usize = 4 * 65536;

/// Queue priority used for the *delayed* re-ACK copy emitted by
/// `emit_due_reacks` — deliberately `PACKET_PRIORITY_LOW`, not
/// `default_packet_priority(PACKET_STREAM_DATA_ACK)` (which is
/// `PACKET_PRIORITY_CRITICAL`, still used for the immediate ACK sent
/// synchronously in `store_received_data`).
///
/// Root cause of the duplex-throughput regression this constant fixes: a DNS
/// response carries at most one item pulled from a stream's own priority
/// queue (`udpserver::postsession::dequeue_session_response`), so within one
/// stream CRITICAL always beats the NORMAL priority `STREAM_DATA` uses. Under
/// sustained receive traffic a stream's re-ACK FIFO is essentially always
/// non-empty (a new entry lands every `REACK_DELAY` window's worth of
/// arrivals), so at CRITICAL priority the re-ACK copy permanently outranks
/// that same stream's own *outbound* STREAM_DATA — i.e. an upload keeps the
/// download direction of a duplex stream starved for as long as the upload
/// runs, not just for one packet. Measured on macOS: `socks-echo-multi` (8
/// duplex SOCKS streams) went from ~1.2s to 70-90s with re-ACKs at CRITICAL.
///
/// LOW sits below `STREAM_DATA`'s NORMAL, so a stream's own pending outbound
/// data is always chosen over a re-ACK copy when both are queued, restoring
/// the download direction. It stays above `PACKET_PRIORITY_IDLE` (PING/PONG)
/// so re-ACKs are not starved indefinitely by idle traffic, and — combined
/// with widening `postsession::pack_control_blocks`'s opportunistic
/// cross-stream draining to include this priority (see its `PACKET_PRIORITY_LOW`
/// cap) — LOW-priority re-ACKs still batch efficiently into one
/// PACKED_CONTROL_BLOCKS reply instead of needing one whole round-robin turn
/// each. This only affects *scheduling* order on the server, not the wire:
/// the packet is still the same STREAM_DATA_ACK type carrying the same
/// sequence number: a plain unmodified Go client cannot tell the difference.
/// The immediate ACK (CRITICAL, unchanged) still reaches the peer with its
/// original low latency, so the corruption fix's effectiveness is unchanged:
/// it only ever depended on the *delayed* copy arriving within the client's
/// RTO window (hundreds of ms), and LOW priority still clears well inside
/// that margin because a stream's own pending-send backlog is small (bounded
/// by `loops::READ_AHEAD_DATA_PACKETS`).
pub(crate) const REACK_PRIORITY: i32 = enums::PACKET_PRIORITY_LOW;

/// How long `store_received_data` waits before sending a "fast ACK" for a
/// freshly-stored packet *instead of* the immediate synchronous one, when
/// `has_queued_download_data` reports this stream already has NORMAL-
/// priority download data waiting.
///
/// Root cause this addresses (distinct from, but analogous to,
/// `REACK_PRIORITY` above): a DNS reply carries at most one item from a
/// stream's queue (`udpserver::postsession::dequeue_session_response`), so a
/// CRITICAL-priority ACK queued while handling an upload query always
/// outranks that same stream's own queued download STREAM_DATA (NORMAL) —
/// the reply to that query spends its one packet slot on the bare ACK even
/// when download data was sitting right behind it. A forensic capture of a
/// real duplication-2 client running a 30s duplex speedtest (both upload and
/// download phases) found 37% of all server replies were exactly this: a
/// single lone STREAM_DATA_ACK.
///
/// Two earlier designs were tried and rejected before this one:
///
/// 1. Queue the immediate ACK anyway, just at `PACKET_PRIORITY_LOW`
///    (`REACK_PRIORITY`'s tier) instead of CRITICAL, plus a dequeue-time
///    check that force-released a LOW-priority ACK once it had waited past a
///    short bound. That check could not tell a freshly-demoted immediate ACK
///    apart from an ordinary already-scheduled `REACK_PRIORITY` duplicate
///    sitting at the front of the same LOW level - and since a re-ACK is by
///    construction already `REACK_DELAY` (150ms) old by the time it's
///    pushed, it was "aged past the bound" the instant it became visible.
///    The check then force-released it *ahead of any waiting NORMAL data
///    too*, on every single call, inverting the priority order it was
///    supposed to only bend as a last resort: measured on `socks-echo-multi`
///    (8 duplex SOCKS streams, `-client-dup 2 -client-setup-dup 2
///    -client-batch 1`), this starved download data almost completely and
///    made most runs time out entirely instead of completing in ~1-3s.
///
/// 2. Skip the immediate ACK entirely and rely solely on the delayed re-ACK
///    `schedule_reack_locked` already unconditionally schedules for the same
///    `sn` (next `REACK_DELAY`/150ms) as a safety net regardless of whether
///    the immediate copy is sent. Simple and safe (no priority-order
///    interaction at all), but measurably *slower* on the same
///    `socks-echo-multi` benchmark (interleaved runs: ~11.4 MiB/s median vs
///    ~15.2 MiB/s for the unfixed baseline) - on this benchmark's
///    near-zero-latency local network, the Go client's own adaptively-
///    estimated upload RTO is apparently well under REACK_DELAY's 150ms, so
///    relying on it alone was already routinely causing the client to
///    retransmit before ever seeing an ACK.
///
/// This version keeps design 2's *skip the immediate copy* half (still no
/// priority-order interaction: nothing at LOW is touched) but replaces
/// "wait for REACK_DELAY" with a dedicated, short, fixed delay - scheduled
/// in its own FIFO (`ArqState::pending_fast_acks`, drained by
/// `emit_due_fast_acks`) entirely separate from `pending_reacks`, and
/// emitted at the ACK's normal CRITICAL priority (not LOW), so once it fires
/// it behaves exactly like the original synchronous immediate ACK always
/// did - no new interaction with `REACK_PRIORITY`'s LOW-priority items is
/// possible. `loops::retransmit_loop`'s wake-up floor for pending timers is
/// 20ms (see its doc comment, tuned against exactly this kind of sustained-
/// traffic busy-loop risk), so this typically lands ~25-45ms after the data
/// was stored: comfortably batched into that same query's or the next
/// query's reply, and - per the client RTO figures in the task notes
/// (median ~0.3s, "as low as" ~0.25s even under load) - still generous
/// margin under the client's *documented* worst-case RTO floor, even though
/// this benchmark's effective RTO on an idle local Docker network runs
/// lower than that floor. The delayed re-ACK safety net from
/// `schedule_reack_locked` is still scheduled unconditionally on top of
/// this, unchanged, in case the fast ACK's own UDP datagram is lost. When
/// there is no download backlog, the immediate ACK is still sent
/// synchronously at CRITICAL exactly as before - this only changes behavior
/// when the immediate copy would otherwise have displaced data.
pub(crate) const FAST_ACK_DELAY: Duration = Duration::from_millis(25);

impl Arq {
    /// Handles inbound `STREAM_DATA`: stores it, queues its ACK and wakes the
    /// writer, all before returning. Go hands this to a separate rx goroutine;
    /// doing it inline means the ACK is already queued when the server builds
    /// the reply to the very query that carried the data, instead of waiting
    /// for the peer's next query. Returns `true` if the packet was accepted.
    pub fn receive_data(&self, sn: u16, data: &[u8]) -> bool {
        {
            let mut s = self.inner.lock().unwrap();
            if s.closed || s.rst_received || s.rst_sent {
                return false;
            }

            if s.local_writer_broken {
                let need_close_write = s.local_writer_broken
                    && !s.close_write_sent
                    && !(s.waiting_ack && s.waiting_ack_for == enums::PACKET_STREAM_CLOSE_WRITE)
                    && !s.closed
                    && !s.rst_received
                    && !s.rst_sent;
                drop(s);
                if need_close_write {
                    self.close(
                        "Inbound data received after local writer closed",
                        crate::types::CloseOptions { send_close_write: true, ..Default::default() },
                    );
                }
                return false;
            }

            s.pending_inbound += 1;
        }

        self.process_received_data(sn, data);
        true
    }

    /// Stores one inbound data packet and queues its ACK/NACKs. Only copies
    /// the payload when it is actually buffered.
    ///
    /// Always wakes the writer afterwards, including when the packet is a
    /// duplicate or out of window: `write_loop` half-closes the local
    /// connection only once `pending_inbound` is back to 0, and a skipped
    /// wake-up left it asleep with CLOSE_READ already received until the
    /// terminal drain timeout (120 s by default) ended the stream.
    pub(crate) fn process_received_data(&self, sn: u16, data: &[u8]) {
        self.store_received_data(sn, data);
        self.signal_flush_ready();
    }

    fn store_received_data(&self, sn: u16, data: &[u8]) {
        let now = Instant::now();
        let exists;
        // Read once and reused below for both the fast-ACK scheduling
        // decision (inside the lock) and the immediate-send decision
        // (outside it): the enqueuer's own lock is independent of `self.
        // inner`, so this is safe to call either place, and a single read
        // avoids acting on two different snapshots of the same signal.
        let backlogged = self.enqueuer.has_queued_download_data();

        {
            let mut s = self.inner.lock().unwrap();
            if s.pending_inbound > 0 {
                s.pending_inbound -= 1;
            }

            if s.local_writer_broken || s.close_write_sent || s.close_write_acked {
                let need_close_write = s.local_writer_broken
                    && !s.close_write_sent
                    && !(s.waiting_ack && s.waiting_ack_for == enums::PACKET_STREAM_CLOSE_WRITE)
                    && !s.closed
                    && !s.rst_received
                    && !s.rst_sent;
                drop(s);
                if need_close_write {
                    self.close(
                        "Inbound data received after local writer closed",
                        crate::types::CloseOptions { send_close_write: true, ..Default::default() },
                    );
                }
                return;
            }

            s.last_activity = now;
            let diff = sn.wrapping_sub(s.rcv_nxt);

            // Sequence numbers are 16-bit, so "behind" and "ahead" are only
            // told apart by distance. The peer sends in order and everything
            // it sent that we have not seen yet is still unacknowledged, so
            // it is never more than MAX_WINDOW_SIZE past the highest sequence
            // we have seen (ACKs are per packet, so that can itself be well
            // past rcv_nxt). Anything further "ahead" is really an old
            // duplicate from more than 32768 back whose ACK was lost: re-ACK
            // it like any old packet. Dropping it silently left the peer
            // retransmitting until its drain timeout, since a fast upload
            // moves >32768 packets within one retransmission timeout.
            let mut highest_ahead = s.rcv_highest.wrapping_sub(s.rcv_nxt);
            if highest_ahead >= 32768 {
                s.rcv_highest = s.rcv_nxt;
                highest_ahead = 0;
            }
            if diff < 32768 && diff > highest_ahead && diff as usize <= highest_ahead as usize + crate::MAX_WINDOW_SIZE {
                s.rcv_highest = sn;
            }
            if diff >= 32768 || diff as usize > highest_ahead as usize + crate::MAX_WINDOW_SIZE {
                drop(s);
                self.enqueuer.push_tx_packet(
                    enums::default_packet_priority(enums::PACKET_STREAM_DATA_ACK),
                    enums::PACKET_STREAM_DATA_ACK,
                    sn,
                    0,
                    0,
                    0,
                    std::time::Duration::ZERO,
                    &[],
                );
                return;
            }

            if diff as usize > self.receive_window_size {
                return;
            }

            exists = s.rcv_buf.contains_key(&sn);
            if !exists && s.rcv_buf.len() >= self.receive_window_size && sn != s.rcv_nxt {
                return;
            }

            if !exists {
                s.rcv_buf.insert(sn, data.to_vec());
            }

            // We are about to ACK `sn` (immediately or via the fast-ACK path
            // below) and it is actually stored (either just now or already,
            // on a duplicate): schedule one extra ACK for it a bit later, in
            // case that one is the one that gets lost at the peer's socket.
            // Never do this for data we return early without storing/ACKing
            // above (out-of-window, too far ahead, or the receive buffer is
            // full) — ACKing data we didn't keep would make the peer think
            // it was delivered.
            self.schedule_reack_locked(&mut s, sn, now);

            // See `FAST_ACK_DELAY`'s doc comment: when this stream's own
            // download data would otherwise be displaced by the immediate
            // ACK in the next reply, schedule a short-delay CRITICAL-
            // priority "fast ACK" instead of sending it synchronously now.
            if backlogged {
                self.schedule_fast_ack_locked(&mut s, sn, now);
            }
        }

        if !backlogged {
            self.enqueuer.push_tx_packet(
                enums::default_packet_priority(enums::PACKET_STREAM_DATA_ACK),
                enums::PACKET_STREAM_DATA_ACK,
                sn,
                0,
                0,
                0,
                std::time::Duration::ZERO,
                &[],
            );
        }

        if !exists {
            self.clear_sent_data_nack(sn);
        }
        self.maybe_send_data_nacks(sn);
    }

    /// Appends `(sn, now + REACK_DELAY)` to the pending re-ACK FIFO, dropping
    /// the oldest entry first if it is already at capacity. Must be called
    /// with `s` already locked; wakes `retransmit_loop` so it re-evaluates
    /// its sleep interval instead of possibly sleeping through the whole
    /// "nothing pending" interval before noticing this entry.
    fn schedule_reack_locked(&self, s: &mut ArqState, sn: u16, now: Instant) {
        if s.pending_reacks.len() >= REACK_QUEUE_CAP {
            s.pending_reacks.pop_front();
        }
        s.pending_reacks.push_back((sn, now + REACK_DELAY));
        self.reack_scheduled.notify_one();
    }

    /// Emits every scheduled re-ACK whose delay has elapsed. Called from
    /// `retransmit_loop` (see `loops.rs`) instead of its own timer so it
    /// shares that loop's wake-ups.
    pub(crate) fn emit_due_reacks(&self, now: Instant) {
        let due: Vec<u16> = {
            let mut s = self.inner.lock().unwrap();
            let mut due = Vec::new();
            while let Some(&(sn, at)) = s.pending_reacks.front() {
                if at > now {
                    break;
                }
                s.pending_reacks.pop_front();
                due.push(sn);
            }
            due
        };

        for sn in due {
            self.enqueuer.push_tx_packet(
                // Deliberately *not* `default_packet_priority` (CRITICAL):
                // see the doc comment on `REACK_PRIORITY` for why the extra
                // copy must never outrank a stream's own outbound STREAM_DATA.
                REACK_PRIORITY,
                enums::PACKET_STREAM_DATA_ACK,
                sn,
                0,
                0,
                0,
                std::time::Duration::ZERO,
                &[],
            );
        }
    }

    /// The instant the next scheduled re-ACK (if any) becomes due, for
    /// `retransmit_loop` to size its sleep so it wakes in time rather than
    /// discovering the due entry late. Also doubles as "is any re-ACK
    /// pending", which `retransmit_loop` counts as pending work so an
    /// upload-only stream (no outbound send data) still gets the fast
    /// wake-up interval while a re-ACK is in flight.
    pub(crate) fn next_reack_due(&self) -> Option<Instant> {
        self.inner.lock().unwrap().pending_reacks.front().map(|&(_, at)| at)
    }

    /// Appends `(sn, now + FAST_ACK_DELAY)` to the pending fast-ACK FIFO,
    /// dropping the oldest entry first if it is already at capacity (same
    /// cap as `pending_reacks` - see `REACK_QUEUE_CAP`'s doc comment; it
    /// applies equally here since a fast ACK is scheduled at most as often as
    /// a re-ACK is). Must be called with `s` already locked; wakes
    /// `retransmit_loop` the same way `schedule_reack_locked` does.
    fn schedule_fast_ack_locked(&self, s: &mut ArqState, sn: u16, now: Instant) {
        if s.pending_fast_acks.len() >= REACK_QUEUE_CAP {
            s.pending_fast_acks.pop_front();
        }
        s.pending_fast_acks.push_back((sn, now + FAST_ACK_DELAY));
        self.reack_scheduled.notify_one();
    }

    /// Emits every scheduled fast ACK whose delay has elapsed, at the ACK's
    /// normal CRITICAL priority (see `FAST_ACK_DELAY`'s doc comment for why
    /// this is deliberately not `REACK_PRIORITY`/LOW like `emit_due_reacks`).
    /// Called from `retransmit_loop` alongside `emit_due_reacks`.
    pub(crate) fn emit_due_fast_acks(&self, now: Instant) {
        let due: Vec<u16> = {
            let mut s = self.inner.lock().unwrap();
            let mut due = Vec::new();
            while let Some(&(sn, at)) = s.pending_fast_acks.front() {
                if at > now {
                    break;
                }
                s.pending_fast_acks.pop_front();
                due.push(sn);
            }
            due
        };

        for sn in due {
            self.enqueuer.push_tx_packet(
                enums::default_packet_priority(enums::PACKET_STREAM_DATA_ACK),
                enums::PACKET_STREAM_DATA_ACK,
                sn,
                0,
                0,
                0,
                std::time::Duration::ZERO,
                &[],
            );
        }
    }

    /// The instant the next scheduled fast ACK (if any) becomes due; see
    /// `next_reack_due`'s doc comment, same purpose for the fast-ACK FIFO.
    pub(crate) fn next_fast_ack_due(&self) -> Option<Instant> {
        self.inner.lock().unwrap().pending_fast_acks.front().map(|&(_, at)| at)
    }

    /// Resolves inbound `STREAM_DATA_ACK` and frees send-window backpressure slots.
    /// Returns `true` only when this ARQ instance was actually tracking the data packet.
    pub fn receive_ack(&self, _packet_type: u8, sn: u16) -> bool {
        let now = Instant::now();
        let mut handled = false;
        let mut should_signal_window = false;
        let mut was_queued = false;
        let mut sample = std::time::Duration::ZERO;
        let mut sample_eligible = false;
        let mut recovery_ready = false;

        {
            let mut s = self.inner.lock().unwrap();
            s.last_activity = now;

            if let Some(info) = s.snd_buf.get(&sn) {
                if info.sample_eligible && info.dispatched {
                    if let Some(last_sent_at) = info.last_sent_at {
                        sample = now.duration_since(last_sent_at);
                        sample_eligible = true;
                    }
                }
                was_queued = !info.dispatched;
                let acked_created_at = info.created_at;
                let acked_sent_at = if info.dispatched && info.sample_eligible { info.last_sent_at } else { None };
                s.snd_buf.remove(&sn);
                // Only newly consumed ACKs count. Duplicates have no send-buffer
                // entry and cannot manufacture loss evidence. Compare send
                // times as well as wrapping sequence numbers to avoid treating
                // a late ACK of a retransmission as evidence against new data.
                if let Some(acked_sent_at) = acked_sent_at {
                    for (&missing, item) in s.snd_buf.iter_mut() {
                        if item.dispatched
                            && crate::util::seq_behind(sn, missing)
                            && item.created_at <= acked_created_at
                            && item.last_sent_at.is_some_and(|at| at <= acked_sent_at)
                        {
                            recovery_ready |= item.later_acks == 3;
                            item.later_acks = item.later_acks.saturating_add(1).min(4);
                        }
                    }
                }
                if was_queued {
                    s.queued_data = s.queued_data.saturating_sub(1);
                }
                if s.deferred_close || matches!(s.state, crate::types::StreamState::Draining) {
                    Arq::note_drain_progress_locked(&mut s, now);
                }
                if s.snd_buf.len() < self.limit {
                    should_signal_window = true;
                }
                handled = true;
            }
        }

        if recovery_ready {
            self.reack_scheduled.notify_one();
        }
        if should_signal_window {
            self.window_not_full.notify_one();
        }
        if was_queued {
            self.data_dequeued.notify_one();
        }

        if handled {
            if sample_eligible {
                self.note_successful_data_sample(sample);
            }
            self.enqueuer.remove_queued_data(sn);

            if self.close_read_received() {
                self.try_finalize_remote_eof();
            }
            self.settle_terminal_drain();
        }

        handled
    }

    fn close_read_received(&self) -> bool {
        self.inner.lock().unwrap().close_read_received
    }

    pub fn handle_data_nack(&self, sn: u16) -> bool {
        self.queue_data_retry(sn, Instant::now(), None, false, true)
    }

    pub(crate) fn maybe_send_data_nacks(&self, sn: u16) {
        if self.data_nack_max_gap == 0 {
            return;
        }

        let (rcv_nxt, closed) = {
            let s = self.inner.lock().unwrap();
            (s.rcv_nxt, s.closed)
        };
        if closed {
            return;
        }

        let diff = sn.wrapping_sub(rcv_nxt);
        if diff == 0 || diff >= 32768 {
            return;
        }

        {
            let mut s = self.inner.lock().unwrap();
            prune_data_nack_state_locked(&mut s, rcv_nxt);
        }

        let window_span = self.data_nack_max_gap as u16;
        let mut missing_seqs: Vec<u16> = Vec::with_capacity(self.data_nack_max_gap);
        {
            let s = self.inner.lock().unwrap();
            if diff <= window_span {
                let mut missing = rcv_nxt;
                while missing != sn {
                    if !s.rcv_buf.contains_key(&missing) {
                        missing_seqs.push(missing);
                    }
                    missing = missing.wrapping_add(1);
                }
            } else {
                let sample_count = ((self.data_nack_max_gap + 19) / 20).max(1);
                let mut seen = rustc_hash::FxHashSet::with_capacity_and_hasher((self.data_nack_max_gap / 20 + 1).max(2), Default::default());

                let mut missing = rcv_nxt;
                let mut added = 0usize;
                while missing != sn && added < sample_count {
                    if !s.rcv_buf.contains_key(&missing) {
                        missing_seqs.push(missing);
                        seen.insert(missing);
                        added += 1;
                    }
                    missing = missing.wrapping_add(1);
                }

                let mut candidate = rcv_nxt.wrapping_add(window_span).wrapping_sub(1);
                loop {
                    if !s.rcv_buf.contains_key(&candidate) {
                        if !seen.contains(&candidate) {
                            missing_seqs.push(candidate);
                        }
                        break;
                    }
                    if candidate == rcv_nxt {
                        break;
                    }
                    candidate = candidate.wrapping_sub(1);
                }
            }
        }

        let now = Instant::now();
        for missing in missing_seqs {
            if !self.should_send_data_nack(missing, now) {
                continue;
            }
            if !self.enqueuer.push_tx_packet(
                enums::default_packet_priority(enums::PACKET_STREAM_DATA_NACK),
                enums::PACKET_STREAM_DATA_NACK,
                missing,
                0,
                0,
                0,
                std::time::Duration::ZERO,
                &[],
            ) {
                self.note_drain_queue_failure(now);
                continue;
            }
            self.note_data_nack_sent(missing, now);
        }
    }

    fn should_send_data_nack(&self, sn: u16, now: Instant) -> bool {
        let mut s = self.inner.lock().unwrap();

        let first_seen_at = s.first_data_nack_seen.get(&sn).copied();
        if first_seen_at.is_none() {
            s.first_data_nack_seen.insert(sn, now);
            return self.data_nack_initial_delay.is_zero();
        }
        let first_seen_at = first_seen_at.unwrap();
        if !self.data_nack_initial_delay.is_zero() && now.duration_since(first_seen_at) < self.data_nack_initial_delay {
            return false;
        }

        match s.last_data_nack_sent.get(&sn).copied() {
            None => true,
            Some(last_sent_at) => now.duration_since(last_sent_at) >= self.data_nack_repeat_interval,
        }
    }

    fn note_data_nack_sent(&self, sn: u16, now: Instant) {
        let mut s = self.inner.lock().unwrap();
        s.last_data_nack_sent.insert(sn, now);
    }

    fn clear_sent_data_nack(&self, sn: u16) {
        {
            let mut s = self.inner.lock().unwrap();
            s.first_data_nack_seen.remove(&sn);
            s.last_data_nack_sent.remove(&sn);
        }
        self.enqueuer.remove_queued_data_nack(sn);
    }

    fn gap_recovery_candidates_locked(state: &ArqState, data_nack_max_gap: usize) -> Vec<u16> {
        if data_nack_max_gap == 0 || state.rcv_buf.is_empty() {
            return Vec::new();
        }
        if state.rcv_buf.contains_key(&state.rcv_nxt) {
            return Vec::new();
        }

        let highest_received = state.rcv_buf.keys().filter_map(|sn| {
            let distance = sn.wrapping_sub(state.rcv_nxt);
            (distance < 32768).then_some(distance as usize)
        }).max().unwrap_or(0);
        // Only holes preceding observed data are evidence of loss. Requesting
        // future, unobserved sequences manufactures unnecessary retransmits.
        let max_gap = data_nack_max_gap.min(highest_received).min(crate::MAX_WINDOW_SIZE) as u16;
        let mut missing_seqs = Vec::with_capacity(max_gap as usize);
        let mut candidate = state.rcv_nxt;
        loop {
            if candidate.wrapping_sub(state.rcv_nxt) >= max_gap {
                break;
            }
            if !state.rcv_buf.contains_key(&candidate) {
                missing_seqs.push(candidate);
            }
            candidate = candidate.wrapping_add(1);
        }
        missing_seqs
    }

    pub(crate) fn run_gap_recovery_watchdog(&self, now: Instant) {
        if self.data_nack_max_gap == 0 || self.is_closed() {
            return;
        }

        let (closed, missing_seqs, rcv_nxt) = {
            let s = self.inner.lock().unwrap();
            let missing = Self::gap_recovery_candidates_locked(&s, self.data_nack_max_gap);
            (s.closed, missing, s.rcv_nxt)
        };

        if closed || missing_seqs.is_empty() {
            return;
        }

        // An unresolved receive hole is independent of unrelated ACKs or
        // control activity. Per-hole initial delay and repeat cooldown below
        // already bound recovery without requiring the entire stream to idle.

        {
            let mut s = self.inner.lock().unwrap();
            prune_data_nack_state_locked(&mut s, rcv_nxt);
        }

        for missing in missing_seqs {
            if !self.should_send_data_nack(missing, now) {
                continue;
            }
            if !self.enqueuer.push_tx_packet(
                enums::default_packet_priority(enums::PACKET_STREAM_DATA_NACK),
                enums::PACKET_STREAM_DATA_NACK,
                missing,
                0,
                0,
                0,
                std::time::Duration::ZERO,
                &[],
            ) {
                continue;
            }
            self.note_data_nack_sent(missing, now);
        }
    }
}

fn prune_data_nack_state_locked(state: &mut ArqState, rcv_nxt: u16) {
    state.first_data_nack_seen.retain(|&sn, _| !seq_behind(rcv_nxt, sn));
    state.last_data_nack_sent.retain(|&sn, _| !seq_behind(rcv_nxt, sn));
}
