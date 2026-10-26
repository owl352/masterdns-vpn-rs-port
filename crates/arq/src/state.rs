//! Mutable ARQ state, guarded by a single mutex in [`crate::Arq`] (mirrors the
//! fields Go guards with `ARQ.mu`).

use crate::types::{AckEvidence, AdaptiveRtoState, ControlItem, DataItem, RecoveryMetrics, RttBucket, StreamState};
use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::time::Instant;

pub(crate) struct ArqState {
    pub io_ready: bool,
    pub stream_workers_started: bool,

    pub transport: Option<crate::transport::TransportState>,
    pub snd_nxt: u16,
    pub rcv_nxt: u16,
    /// Highest data sequence seen from the peer that was classified as
    /// ahead of `rcv_nxt`; bounds how far ahead a legitimate packet can be.
    pub rcv_highest: u16,
    pub snd_buf: FxHashMap<u16, DataItem>,
    /// Number of `snd_buf` items with `dispatched == false`, i.e. DATA packets
    /// sitting in the TX queue waiting for the peer to pull them. Drives the
    /// read pacing in `loops::io_loop`.
    pub queued_data: usize,
    pub ack_evidence: VecDeque<AckEvidence>,
    pub rtt_tail: VecDeque<RttBucket>,
    pub next_retry_due: Option<Instant>,
    pub recovery: RecoveryMetrics,
    pub rcv_buf: FxHashMap<u16, Vec<u8>>,
    /// key: `ptype << 24 | sn << 8 | fragID`
    pub control_snd_buf: FxHashMap<u32, ControlItem>,

    pub state: StreamState,
    pub closed: bool,
    pub close_reason: String,
    pub last_activity: Instant,

    pub close_read_sent: bool,
    pub close_read_received: bool,
    pub close_read_acked: bool,
    pub close_read_seq_sent: Option<u16>,

    pub close_write_sent: bool,
    pub close_write_received: bool,
    pub close_write_acked: bool,
    pub close_write_seq_sent: Option<u16>,

    pub rst_received: bool,
    pub rst_sent: bool,
    pub rst_acked: bool,
    pub rst_seq_sent: Option<u16>,

    pub local_write_closed: bool,
    pub local_writer_broken: bool,
    pub local_write_pending: bool,
    pub stop_local_read: bool,
    pub deferred_close: bool,
    pub deferred_reason: String,
    pub deferred_deadline: Option<Instant>,
    pub deferred_packet: u8,
    pub client_eof_at: Option<Instant>,
    pub close_read_acked_at: Option<Instant>,
    pub last_duplicate_ack_at: Option<Instant>,
    pub waiting_ack: bool,
    pub waiting_ack_for: u8,
    pub ack_wait_deadline: Option<Instant>,
    pub drain_progress_at: Option<Instant>,
    pub drain_queue_fail_at: Option<Instant>,
    pub drain_queue_fails: u32,
    pub drain_stall_logged: bool,

    pub is_virtual: bool,

    pub data_adaptive_rto: AdaptiveRtoState,
    pub control_adaptive_rto: AdaptiveRtoState,

    pub first_data_nack_seen: FxHashMap<u16, Instant>,
    pub last_data_nack_sent: FxHashMap<u16, Instant>,

    pub pending_inbound: i64,

    /// FIFO of `(sn, due_instant)` for delayed re-ACKs of inbound STREAM_DATA
    /// that this side has actually stored (see `Arq::store_received_data`).
    /// Repairs an ACK the peer's UDP socket dropped before its retransmit
    /// timeout fires. Entries are appended in non-decreasing `due_instant`
    /// order (the delay is a fixed constant), so the front of the queue is
    /// always the next one due. Bounded in `Arq::schedule_reack_locked` so a
    /// chatty peer can't grow this without bound.
    pub pending_reacks: VecDeque<(u16, Instant)>,

    /// FIFO of `(sn, due_instant)` for the short-delay "fast ACK" `Arq::
    /// store_received_data` schedules (via `Arq::schedule_fast_ack_locked`)
    /// instead of sending the immediate ACK synchronously, whenever the
    /// enqueuer reports download data already backlogged - see
    /// `data::FAST_ACK_DELAY`'s doc comment. Kept as its own FIFO, separate
    /// from `pending_reacks`, because the two use different fixed delays
    /// (`FAST_ACK_DELAY` vs `REACK_DELAY`): mixing entries with different
    /// delays into one FIFO would break the "front is always due first"
    /// invariant `Arq::emit_due_reacks`/`Arq::next_reack_due` rely on.
    /// Bounded the same way in `Arq::schedule_fast_ack_locked`.
    pub pending_fast_acks: VecDeque<(u16, Instant)>,
}

impl ArqState {
    pub fn new(is_virtual: bool, io_ready: bool, rto: std::time::Duration, control_rto: std::time::Duration) -> Self {
        let now = Instant::now();
        ArqState {
            io_ready,
            stream_workers_started: false,
            transport: None,
            snd_nxt: 0,
            rcv_nxt: 0,
            rcv_highest: 0,
            snd_buf: FxHashMap::default(),
            queued_data: 0,
            ack_evidence: VecDeque::with_capacity(16),
            rtt_tail: VecDeque::with_capacity(8),
            next_retry_due: None,
            recovery: RecoveryMetrics::default(),
            rcv_buf: FxHashMap::default(),
            control_snd_buf: FxHashMap::default(),
            state: StreamState::Open,
            closed: false,
            close_reason: String::new(),
            last_activity: now,
            close_read_sent: false,
            close_read_received: false,
            close_read_acked: false,
            close_read_seq_sent: None,
            close_write_sent: false,
            close_write_received: false,
            close_write_acked: false,
            close_write_seq_sent: None,
            rst_received: false,
            rst_sent: false,
            rst_acked: false,
            rst_seq_sent: None,
            local_write_closed: false,
            local_writer_broken: false,
            local_write_pending: false,
            stop_local_read: false,
            deferred_close: false,
            deferred_reason: String::new(),
            deferred_deadline: None,
            deferred_packet: 0,
            client_eof_at: None,
            close_read_acked_at: None,
            last_duplicate_ack_at: None,
            waiting_ack: false,
            waiting_ack_for: 0,
            ack_wait_deadline: None,
            drain_progress_at: None,
            drain_queue_fail_at: None,
            drain_queue_fails: 0,
            drain_stall_logged: false,
            is_virtual,
            data_adaptive_rto: AdaptiveRtoState {
                current_base: rto,
                ..Default::default()
            },
            control_adaptive_rto: AdaptiveRtoState {
                current_base: control_rto,
                ..Default::default()
            },
            first_data_nack_seen: FxHashMap::default(),
            last_data_nack_sent: FxHashMap::default(),
            pending_inbound: 0,
            pending_reacks: VecDeque::new(),
            pending_fast_acks: VecDeque::new(),
        }
    }

    pub(crate) fn contiguous_ready(&self) -> usize {
        let mut ready = 0usize;
        let mut sn = self.rcv_nxt;
        loop {
            if !self.rcv_buf.contains_key(&sn) {
                break;
            }
            ready += 1;
            sn = sn.wrapping_add(1);
        }
        ready
    }
}
