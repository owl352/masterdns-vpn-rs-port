//! Core `Arq` struct: construction, accessors, and the synchronous state-machine
//! logic ported from `internal/arq/arq.go`. The four background loops
//! (io/write/rx/retransmit) live in [`crate::loops`].

use crate::state::ArqState;
use crate::types::*;
use crate::util::*;
use rustc_hash::FxHashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub(crate) type BoxedRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
pub(crate) type BoxedWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

pub struct Arq {
    pub(crate) stream_id: u16,
    pub(crate) session_id: u8,
    pub(crate) enqueuer: Arc<dyn PacketEnqueuer>,
    pub(crate) logger: Arc<dyn ArqLogger>,
    pub(crate) mtu: usize,

    pub(crate) window_size: usize,
    pub(crate) receive_window_size: usize,
    pub(crate) limit: usize,

    pub(crate) rto: Duration,
    pub(crate) max_rto: Duration,
    pub(crate) inactivity_timeout: Duration,
    pub(crate) data_packet_ttl: Duration,
    pub(crate) max_data_retries: u32,
    pub(crate) terminal_drain_timeout: Duration,
    pub(crate) terminal_ack_wait: Duration,

    pub(crate) enable_control_reliability: bool,
    pub(crate) control_rto: Duration,
    pub(crate) control_max_rto: Duration,
    pub(crate) control_max_retries: u32,
    pub(crate) control_packet_ttl: Duration,
    pub(crate) data_nack_max_gap: usize,
    pub(crate) data_nack_initial_delay: Duration,
    pub(crate) data_nack_repeat_interval: Duration,

    pub is_client: bool,
    pub(crate) compression_type: u8,

    pub(crate) inner: Mutex<ArqState>,
    pub(crate) window_not_full: Notify,
    /// Signalled whenever `queued_data` drops (a queued DATA packet was pulled,
    /// acked or cleared) so a paced `io_loop` can read again.
    pub(crate) data_dequeued: Notify,
    pub(crate) flush_signal: Notify,
    /// Notified whenever a delayed re-ACK is scheduled (see
    /// `Arq::schedule_reack`) so `loops::retransmit_loop` wakes promptly
    /// instead of possibly sleeping through the whole "no pending send data"
    /// interval before it notices there is now a due-soon re-ACK to emit.
    pub(crate) reack_scheduled: Notify,

    // Plain std mutexes, not tokio's: `finalize_close` (a synchronous, non-async
    // method mirroring the Go original) must be able to drop these — and so
    // force-close the underlying socket — without an executor. The io/write
    // loops use a take-out/put-back pattern around their `.await` calls so
    // they never hold the lock across an await point (see `loops.rs`); each
    // read/write is additionally bounded by a short timeout, so a connection
    // that finalize_close couldn't reach because it was mid-flight is noticed
    // and dropped by the owning loop on its next iteration anyway.
    pub(crate) local_conn_read: Mutex<Option<BoxedRead>>,
    pub(crate) local_conn_write: Mutex<Option<BoxedWrite>>,
    pub(crate) has_local_conn: AtomicBool,

    pub(crate) cancel_token: CancellationToken,
}

impl Arq {
    /// Instantiates a pristine reliable streaming overlay suitable for client or server.
    pub fn new(
        stream_id: u16,
        session_id: u8,
        enqueuer: Arc<dyn PacketEnqueuer>,
        mtu: usize,
        logger: Option<Arc<dyn ArqLogger>>,
        cfg: Config,
    ) -> Arc<Self> {
        let logger = logger.unwrap_or_else(|| Arc::new(DummyLogger));

        let window_size = cfg.window_size.max(300).min(crate::MAX_WINDOW_SIZE);
        let receive_window_size = window_size.max(window_size * 2);
        let limit = ((window_size as f64) * 0.8).max(50.0) as usize;

        let max_rto = Duration::from_secs_f64(cfg.max_rto.max(0.05));
        let rto = Duration::from_secs_f64(cfg.rto.max(0.05)).min(max_rto);
        let control_max_rto = Duration::from_secs_f64(cfg.control_max_rto.max(0.05));
        let control_rto = Duration::from_secs_f64(cfg.control_rto.max(0.05)).min(control_max_rto);

        let state = ArqState::new(cfg.is_virtual, !cfg.start_paused, rto, control_rto);

        let arq = Arc::new(Arq {
            stream_id,
            session_id,
            enqueuer,
            logger,
            mtu: mtu.max(1),
            window_size,
            receive_window_size,
            limit,
            rto,
            max_rto,
            inactivity_timeout: Duration::from_secs_f64(cfg.inactivity_timeout.max(120.0)),
            data_packet_ttl: Duration::from_secs_f64(cfg.data_packet_ttl.max(120.0)),
            max_data_retries: cfg.max_data_retries.max(60),
            terminal_drain_timeout: Duration::from_secs_f64(cfg.terminal_drain_timeout.max(60.0)),
            terminal_ack_wait: Duration::from_secs_f64(cfg.terminal_ack_wait_timeout.max(30.0)),
            enable_control_reliability: cfg.enable_control_reliability,
            control_rto,
            control_max_rto,
            control_max_retries: cfg.control_max_retries.max(5),
            control_packet_ttl: Duration::from_secs_f64(cfg.control_packet_ttl.max(120.0)),
            data_nack_max_gap: cfg.data_nack_max_gap,
            data_nack_initial_delay: Duration::from_secs_f64(cfg.data_nack_initial_delay_seconds.max(0.0)),
            data_nack_repeat_interval: Duration::from_secs_f64(cfg.data_nack_repeat_seconds.max(0.1)),
            is_client: cfg.is_client,
            compression_type: cfg.compression_type,
            inner: Mutex::new(state),
            window_not_full: Notify::new(),
            data_dequeued: Notify::new(),
            flush_signal: Notify::new(),
            reack_scheduled: Notify::new(),
            local_conn_read: Mutex::new(None),
            local_conn_write: Mutex::new(None),
            has_local_conn: AtomicBool::new(false),
            cancel_token: CancellationToken::new(),
        });

        arq.window_not_full.notify_one();
        arq
    }

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    pub fn is_closed(&self) -> bool {
        self.inner.lock().unwrap().closed
    }

    pub fn state(&self) -> StreamState {
        self.inner.lock().unwrap().state
    }

    pub fn has_pending_sequence(&self, sn: u16) -> bool {
        self.inner.lock().unwrap().snd_buf.contains_key(&sn)
    }

    pub fn is_reset(&self) -> bool {
        let s = self.inner.lock().unwrap();
        matches!(s.state, StreamState::Reset) || s.rst_received || s.rst_sent
    }

    /// Resolves once the ARQ context is cancelled or the stream is closed.
    pub async fn done(&self) {
        self.cancel_token.cancelled().await;
    }

    pub(crate) fn set_state(state: &mut ArqState, new_state: StreamState) {
        state.state = new_state;
    }

    fn signal_window_not_full(&self) {
        self.window_not_full.notify_one();
    }

    pub(crate) fn signal_flush_ready(&self) {
        self.flush_signal.notify_one();
    }

    pub(crate) fn current_data_base_rto(&self, state: &ArqState) -> Duration {
        let base = state.data_adaptive_rto.current_base;
        if base.is_zero() {
            self.rto
        } else {
            clamp_duration(base, self.rto, self.max_rto)
        }
    }

    pub(crate) fn current_control_base_rto(&self, state: &ArqState) -> Duration {
        let base = state.control_adaptive_rto.current_base;
        if base.is_zero() {
            self.control_rto
        } else {
            clamp_duration(base, self.control_rto, self.control_max_rto)
        }
    }

    pub(crate) fn note_successful_data_sample(&self, sample: Duration) {
        let mut s = self.inner.lock().unwrap();
        s.data_adaptive_rto = update_adaptive_rto(s.data_adaptive_rto, sample, self.rto, self.max_rto);
    }

    pub(crate) fn note_successful_control_sample(&self, sample: Duration) {
        let mut s = self.inner.lock().unwrap();
        s.control_adaptive_rto = update_adaptive_rto(s.control_adaptive_rto, sample, self.control_rto, self.control_max_rto);
    }

    pub fn note_tx_packet_dequeued(&self, packet_type: u8, sequence_num: u16, fragment_id: u8) {
        let now = Instant::now();
        let mut s = self.inner.lock().unwrap();

        match packet_type {
            enums::PACKET_STREAM_DATA | enums::PACKET_STREAM_RESEND => {
                let mut was_queued = false;
                if let Some(info) = s.snd_buf.get_mut(&sequence_num) {
                    info.last_sent_at = Some(now);
                    was_queued = !info.dispatched;
                    info.dispatched = true;
                }
                if was_queued {
                    s.queued_data = s.queued_data.saturating_sub(1);
                    drop(s);
                    self.data_dequeued.notify_one();
                }
            }
            _ => {
                if !self.enable_control_reliability {
                    return;
                }
                let key = control_key(packet_type, sequence_num, fragment_id);
                if let Some(info) = s.control_snd_buf.get_mut(&key) {
                    info.last_sent_at = Some(now);
                    info.dispatched = true;
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Transitions & Hooks
    // -----------------------------------------------------------------

    pub fn mark_close_read_sent(&self) {
        {
            let mut s = self.inner.lock().unwrap();
            s.close_read_sent = true;
            if s.close_read_received {
                let ns = StreamState::Closing;
                Self::set_state(&mut s, ns);
            } else {
                let ns = StreamState::HalfClosedLocal;
                Self::set_state(&mut s, ns);
            }
        }
        self.try_finalize_remote_eof();
    }

    pub fn mark_close_read_received(&self) {
        {
            let mut s = self.inner.lock().unwrap();
            if s.is_virtual {
                return;
            }
            s.close_read_received = true;
            if s.close_read_sent {
                let ns = StreamState::Closing;
                Self::set_state(&mut s, ns);
            } else {
                let ns = StreamState::HalfClosedRemote;
                Self::set_state(&mut s, ns);
            }
        }
        self.signal_flush_ready();
        self.try_finalize_remote_eof();
    }

    pub(crate) fn mark_close_read_acked(&self) {
        let mut s = self.inner.lock().unwrap();
        s.close_read_acked = true;
        s.close_read_acked_at = Some(Instant::now());
        if s.close_read_received {
            let ns = StreamState::Closing;
            Self::set_state(&mut s, ns);
        }
    }

    pub fn mark_close_write_sent(&self) {
        let mut s = self.inner.lock().unwrap();
        s.close_write_sent = true;
        s.local_writer_broken = true;
        s.local_write_closed = true;
        s.rcv_buf.clear();
        if s.close_read_received {
            let ns = StreamState::Closing;
            Self::set_state(&mut s, ns);
        }
    }

    pub fn mark_close_write_received(&self) {
        {
            let mut s = self.inner.lock().unwrap();
            if s.is_virtual {
                return;
            }
            s.close_write_received = true;
            s.stop_local_read = true;

            for sn in s.snd_buf.keys().copied().collect::<Vec<_>>() {
                self.enqueuer.remove_queued_data(sn);
            }
            s.snd_buf.clear();
            s.queued_data = 0;
        }
        self.signal_window_not_full();

        // A peer close-write can empty outbound state without passing through ReceiveAck.
        // If we were draining toward a deferred terminal packet, re-evaluate it now.
        self.settle_terminal_drain();
        self.try_finalize_remote_eof();
    }

    pub(crate) fn mark_close_write_acked(&self) {
        let mut s = self.inner.lock().unwrap();
        s.close_write_acked = true;
        s.local_writer_broken = true;
        s.local_write_closed = true;
    }

    pub(crate) fn maybe_initiate_client_close_read_after_writer_break(&self) {
        let should_initiate = {
            let s = self.inner.lock().unwrap();
            self.is_client
                && s.local_writer_broken
                && !s.closed
                && !s.rst_sent
                && !s.rst_received
                && !s.close_read_sent
                && !s.close_read_received
        };
        let pending_outbound = {
            let s = self.inner.lock().unwrap();
            !s.snd_buf.is_empty() || s.local_write_pending
        };

        if !should_initiate {
            return;
        }

        self.close(
            "Client local endpoint disconnected after write side closed",
            CloseOptions {
                send_close_read: true,
                after_drain: pending_outbound,
                ..Default::default()
            },
        );
    }

    fn try_finalize_client_local_disconnect(&self) {
        let should_close = {
            let s = self.inner.lock().unwrap();
            self.is_client
                && !s.closed
                && s.local_writer_broken
                && s.close_write_acked
                && s.close_read_sent
                && s.close_read_acked
                && s.snd_buf.is_empty()
                && s.rcv_buf.is_empty()
                && s.pending_inbound == 0
                && !s.local_write_pending
                && !s.waiting_ack
                && !s.deferred_close
        };

        if should_close {
            self.finalize_close("client local disconnect completed");
        }
    }

    pub(crate) fn mark_local_writer_broken(&self, _reason: &str) {
        let mut s = self.inner.lock().unwrap();
        s.local_writer_broken = true;
        s.local_write_pending = false;
        s.rcv_buf.clear();
    }

    pub(crate) fn note_client_eof(&self, now: Instant) {
        let mut s = self.inner.lock().unwrap();
        if self.is_client && s.client_eof_at.is_none() {
            s.client_eof_at = Some(now);
        }
    }

    /// Half-closes the local writer side of the application connection.
    pub(crate) async fn half_close_local_writer(&self) {
        {
            let mut s = self.inner.lock().unwrap();
            if s.local_write_closed || s.closed {
                return;
            }
            s.local_write_closed = true;
        }

        // Take the writer out so we never hold the (non-async) mutex across
        // an `.await`; `loops::write_loop` uses the same take-out/put-back
        // pattern, so this races harmlessly with it at worst (one side finds
        // `None` and skips).
        let taken = self.local_conn_write.lock().unwrap().take();
        if let Some(mut conn) = taken {
            use tokio::io::AsyncWriteExt;
            let _ = conn.shutdown().await;
            let mut guard = self.local_conn_write.lock().unwrap();
            if guard.is_none() {
                *guard = Some(conn);
            }
        }
    }

    pub(crate) fn clear_waiting_ack(&self, packet_type: u8) {
        let mut s = self.inner.lock().unwrap();
        if s.waiting_ack && s.waiting_ack_for == packet_type {
            s.waiting_ack = false;
            s.waiting_ack_for = 0;
            s.ack_wait_deadline = None;
        }
    }

    pub(crate) fn reset_drain_tracking_locked(state: &mut ArqState, now: Instant) {
        state.drain_progress_at = Some(now);
        state.drain_queue_fail_at = None;
        state.drain_queue_fails = 0;
        state.drain_stall_logged = false;
    }

    pub(crate) fn note_drain_progress_locked(state: &mut ArqState, now: Instant) {
        Self::reset_drain_tracking_locked(state, now);
    }

    pub(crate) fn note_drain_queue_failure(&self, now: Instant) {
        let mut s = self.inner.lock().unwrap();
        if s.deferred_close || matches!(s.state, StreamState::Draining) {
            s.drain_queue_fail_at = Some(now);
            s.drain_queue_fails += 1;
        }
    }

    pub(crate) fn run_final_ack_watchdog(&self, now: Instant) {
        let ack_sn;
        {
            let mut s = self.inner.lock().unwrap();
            let should_ack = !s.closed
                && !s.rst_sent
                && !s.rst_received
                && self.is_client
                && s.close_read_sent
                && s.close_read_acked
                && !s.close_read_received
                && !s.close_write_sent
                && !s.close_write_acked
                && !s.close_write_received
                && !s.local_writer_broken
                && s.rcv_buf.is_empty()
                && s.pending_inbound == 0
                && !s.local_write_pending
                && s.rcv_nxt > 0
                && now.duration_since(s.last_activity) >= Duration::from_secs(2)
                && s.last_duplicate_ack_at
                    .map(|t| now.duration_since(t) >= Duration::from_secs(2))
                    .unwrap_or(true);
            if !should_ack {
                return;
            }

            ack_sn = s.rcv_nxt.wrapping_sub(1);
            s.last_duplicate_ack_at = Some(now);
        }

        self.enqueuer.push_tx_packet(
            enums::default_packet_priority(enums::PACKET_STREAM_DATA_ACK),
            enums::PACKET_STREAM_DATA_ACK,
            ack_sn,
            0,
            0,
            0,
            Duration::ZERO,
            &[],
        );
    }

    /// Not yet called anywhere in Phase 1 (no client/server session layer
    /// exists yet to invoke it) — kept for parity with the Go original, which
    /// exposes the same helper for out-of-band control-packet bookkeeping.
    #[allow(dead_code)]
    pub(crate) fn clear_tracked_control_packet(&self, packet_type: u8, sequence_num: u16, fragment_id: u8) {
        let mut s = self.inner.lock().unwrap();
        s.control_snd_buf.remove(&control_key(packet_type, sequence_num, fragment_id));
    }

    pub(crate) fn try_finalize_remote_eof(&self) {
        let should_close = {
            let s = self.inner.lock().unwrap();
            let waiting_for_close_read_ack = s.waiting_ack && s.waiting_ack_for == enums::PACKET_STREAM_CLOSE_READ;
            let receive_drained = (s.rcv_buf.is_empty() && s.pending_inbound == 0) || s.local_writer_broken;
            let write_side_settled = (!s.local_writer_broken && (!s.close_write_sent || s.close_write_acked))
                || (s.local_writer_broken && (s.close_write_acked || s.close_write_received));
            !s.closed
                && s.close_read_received
                && receive_drained
                && (!s.local_write_pending || s.local_writer_broken)
                && (s.close_read_acked || (s.close_read_sent && !waiting_for_close_read_ack))
                && write_side_settled
        };

        if should_close {
            self.finalize_close("close handshake completed");
            return;
        }

        self.try_finalize_client_local_disconnect();
    }

    pub(crate) fn try_finalize_peer_reset_drain(&self) -> bool {
        let (contiguous_ready, rcv_buf_len, pending_inbound, local_write_pending);
        {
            let s = self.inner.lock().unwrap();
            if !s.rst_received || s.closed {
                return false;
            }
            contiguous_ready = s.contiguous_ready();
            rcv_buf_len = s.rcv_buf.len();
            pending_inbound = s.pending_inbound;
            local_write_pending = s.local_write_pending;
        }

        if contiguous_ready > 0 {
            self.signal_flush_ready();
            return false;
        }

        if local_write_pending || pending_inbound > 0 {
            return false;
        }

        if rcv_buf_len > 0 {
            self.finalize_close("peer reset received with non-contiguous buffered data");
            return true;
        }

        self.finalize_close("peer reset received");
        true
    }

    pub fn mark_rst_sent(&self) {
        let mut s = self.inner.lock().unwrap();
        s.rst_sent = true;
        clear_all_queues(&mut s, true, &self.window_not_full);
        let ns = StreamState::Reset;
        Self::set_state(&mut s, ns);
    }

    pub fn mark_rst_received(&self) {
        {
            let mut s = self.inner.lock().unwrap();
            if s.is_virtual {
                return;
            }
            s.rst_received = true;
            s.stop_local_read = true;
            clear_outbound_state_locked(&mut s, true, &*self.enqueuer, &self.window_not_full);
            let ns = StreamState::Reset;
            Self::set_state(&mut s, ns);
        }
        self.signal_flush_ready();
    }

    pub(crate) fn mark_rst_acked(&self) {
        let mut s = self.inner.lock().unwrap();
        s.rst_acked = true;
        clear_all_queues(&mut s, true, &self.window_not_full);
        let ns = StreamState::Reset;
        Self::set_state(&mut s, ns);
    }
}

pub(crate) fn control_key(packet_type: u8, sequence_num: u16, fragment_id: u8) -> u32 {
    (packet_type as u32) << 24 | (sequence_num as u32) << 8 | (fragment_id as u32)
}

pub(crate) fn clear_all_queues(state: &mut ArqState, clear_control: bool, window_not_full: &Notify) {
    state.snd_buf = FxHashMap::default();
    state.queued_data = 0;
    state.rcv_buf = FxHashMap::default();
    if clear_control {
        state.control_snd_buf = FxHashMap::default();
    }
    state.first_data_nack_seen.clear();
    state.last_data_nack_sent.clear();
    state.pending_reacks.clear();
    state.pending_fast_acks.clear();
    window_not_full.notify_one();
}

pub(crate) fn clear_outbound_state_locked(state: &mut ArqState, clear_control: bool, enqueuer: &dyn PacketEnqueuer, window_not_full: &Notify) {
    for sn in state.snd_buf.keys().copied().collect::<Vec<_>>() {
        enqueuer.remove_queued_data(sn);
    }
    for sn in state.last_data_nack_sent.keys().copied().collect::<Vec<_>>() {
        enqueuer.remove_queued_data_nack(sn);
    }

    state.snd_buf = FxHashMap::default();
    state.queued_data = 0;
    if clear_control {
        state.control_snd_buf = FxHashMap::default();
    }
    state.first_data_nack_seen.clear();
    state.last_data_nack_sent.clear();
    state.pending_reacks.clear();
    state.pending_fast_acks.clear();
    window_not_full.notify_one();
}
