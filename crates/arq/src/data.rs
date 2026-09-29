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

            // We are about to ACK `sn` immediately below, and it is actually
            // stored (either just now or already, on a duplicate): schedule
            // one extra ACK for it a bit later, in case the immediate one is
            // the one that gets lost at the peer's socket. Never do this for
            // data we return early without storing/ACKing above (out-of-
            // window, too far ahead, or the receive buffer is full) — ACKing
            // data we didn't keep would make the peer think it was delivered.
            self.schedule_reack_locked(&mut s, sn, now);
        }

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
        if s.pending_reacks.len() >= self.receive_window_size.max(1) {
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

    /// The instant the next scheduled re-ACK (if any) becomes due, for
    /// `retransmit_loop` to size its sleep so it wakes in time rather than
    /// discovering the due entry late. Also doubles as "is any re-ACK
    /// pending", which `retransmit_loop` counts as pending work so an
    /// upload-only stream (no outbound send data) still gets the fast
    /// wake-up interval while a re-ACK is in flight.
    pub(crate) fn next_reack_due(&self) -> Option<Instant> {
        self.inner.lock().unwrap().pending_reacks.front().map(|&(_, at)| at)
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
                s.snd_buf.remove(&sn);
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
        if self.is_closed() || self.is_reset() {
            return false;
        }

        let now = Instant::now();
        let data;
        let compression_type;
        let ttl;
        let prev_nack_sent_at;
        {
            let mut s = self.inner.lock().unwrap();
            s.last_activity = now;
            let info = match s.snd_buf.get_mut(&sn) {
                Some(i) => i,
                None => return false,
            };
            prev_nack_sent_at = info.last_nack_sent_at;
            if let Some(prev) = prev_nack_sent_at {
                if now.duration_since(prev) < self.data_nack_repeat_interval {
                    return false;
                }
            }
            info.last_nack_sent_at = Some(now);
            data = info.data.clone();
            compression_type = info.compression_type;
            ttl = info.ttl;
        }

        let ok = self.enqueuer.push_tx_packet(
            enums::default_packet_priority(enums::PACKET_STREAM_RESEND),
            enums::PACKET_STREAM_RESEND,
            sn,
            0,
            0,
            compression_type,
            ttl,
            &data,
        );

        if !ok {
            let mut s = self.inner.lock().unwrap();
            if let Some(info) = s.snd_buf.get_mut(&sn) {
                if info.last_nack_sent_at == Some(now) {
                    info.last_nack_sent_at = prev_nack_sent_at;
                }
            }
            return false;
        }

        let mut s = self.inner.lock().unwrap();
        if let Some(info) = s.snd_buf.get_mut(&sn) {
            info.sample_eligible = false;
        }
        true
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

        let max_gap = data_nack_max_gap as u16;
        let mut missing_seqs = Vec::with_capacity(data_nack_max_gap);
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

        let (closed, last_activity, missing_seqs, rcv_nxt) = {
            let s = self.inner.lock().unwrap();
            let missing = Self::gap_recovery_candidates_locked(&s, self.data_nack_max_gap);
            (s.closed, s.last_activity, missing, s.rcv_nxt)
        };

        if closed || missing_seqs.is_empty() {
            return;
        }

        if now.duration_since(last_activity) < self.data_nack_repeat_interval {
            return;
        }

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
