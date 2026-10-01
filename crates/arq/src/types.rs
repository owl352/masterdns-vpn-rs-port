//! Shared types ported from the top of `internal/arq/arq.go`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Mirrors Python's `Stream_State` enum (via the Go `StreamState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closing,
    Reset,
    Closed,
    Draining,
    TimeWait,
}

/// Abstracts the transmission layer (client or server stream): a non-blocking
/// attempt to enqueue a packet for transmission. Returns `false` if the queue
/// could not accept it right now (caller should treat the packet as
/// "not yet dispatched" and let the retransmit loop retry it).
pub trait PacketEnqueuer: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn push_tx_packet(
        &self,
        priority: i32,
        packet_type: u8,
        sequence_num: u16,
        fragment_id: u8,
        total_fragments: u8,
        compression_type: u8,
        ttl: Duration,
        payload: &[u8],
    ) -> bool;

    /// Optional: called when the ARQ stream fully closes.
    fn on_arq_closed(&self, _reason: &str) {}
    /// Optional: remove a previously queued DATA packet by sequence number
    /// (e.g. because it was ACKed and no longer needs sending).
    fn remove_queued_data(&self, _sequence_num: u16) -> bool {
        false
    }
    /// Optional: retire a tracked control packet after its ACK or a stale enqueue.
    fn remove_queued_control(&self, _packet_type: u8, _sequence_num: u16, _fragment_id: u8) -> bool {
        false
    }
    /// Optional: remove a previously queued DATA_NACK by sequence number.
    fn remove_queued_data_nack(&self, _sequence_num: u16) -> bool {
        false
    }
    /// Optional: whether this stream currently has outbound (download)
    /// STREAM_DATA queued and not yet dispatched. `store_received_data` in
    /// `data.rs` consults this to decide whether a freshly-stored packet's
    /// immediate ACK should ride at its normal CRITICAL priority or be
    /// queued below download data instead, so replying to an upload query
    /// doesn't spend the DNS reply's one packet slot on a lone ACK while
    /// download data for the same stream sits waiting. Defaults to `false`
    /// (never demote) for enqueuers that don't track this.
    fn has_queued_download_data(&self) -> bool {
        false
    }
}

pub trait ArqLogger: Send + Sync {
    fn debugf(&self, _msg: &str) {}
    fn infof(&self, _msg: &str) {}
    fn errorf(&self, _msg: &str) {}
}

pub struct DummyLogger;
impl ArqLogger for DummyLogger {}

#[derive(Debug, Clone)]
pub(crate) struct DataItem {
    pub data: Vec<u8>,
    pub nack_pending: bool,
    pub retry_cause: Option<RetryCause>,
    pub created_at: Instant,
    pub last_sent_at: Option<Instant>,
    pub dispatched: bool,
    pub last_nack_sent_at: Option<Instant>,
    pub retries: u32,
    pub current_rto: Duration,
    pub sample_eligible: bool,
    pub compression_type: u8,
    pub ttl: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct ControlItem {
    pub packet_type: u8,
    pub sequence_num: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    /// Recorded for parity with the Go original; not currently read back
    /// anywhere (Go computes the expected ack type on demand via
    /// `ReverseControlAckFor` instead of consulting this field either).
    #[allow(dead_code)]
    pub ack_type: u8,
    pub payload: Vec<u8>,
    pub priority: i32,
    pub created_at: Instant,
    pub last_sent_at: Option<Instant>,
    pub dispatched: bool,
    pub retries: u32,
    pub current_rto: Duration,
    pub sample_eligible: bool,
    pub ttl: Duration,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AdaptiveRtoState {
    pub srtt: Duration,
    pub rttvar: Duration,
    pub current_base: Duration,
    pub initialized: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AckEvidence {
    pub sn: u16,
    pub created_at: Instant,
    pub sent_at: Instant,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RttBucket {
    pub at: Instant,
    pub maximum: Duration,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RetryCause { Timeout = 0, Early = 1, Nack = 2 }

#[derive(Debug, Default)]
pub(crate) struct RecoveryMetrics {
    pub requested: [u64; 3],
    pub queued: [u64; 3],
    pub dispatched: [u64; 3],
    pub coalesced: [u64; 3],
    pub original: u64,
    pub scans: u64,
}

pub(crate) struct RtxJob {
    pub sn: u16,
    pub sent_at: Instant,
    pub timed_out: bool,
    pub nack: bool,
}

pub(crate) fn setup_control_packet_types() -> &'static HashMap<u8, ()> {
    static MAP: std::sync::OnceLock<HashMap<u8, ()>> = std::sync::OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(enums::PACKET_STREAM_SYN, ());
        m.insert(enums::PACKET_SOCKS5_SYN, ());
        m
    })
}

/// Extensive ARQ tuning configuration, ported 1:1 from Go's `arq.Config`.
#[derive(Debug, Clone)]
pub struct Config {
    pub window_size: usize,
    pub rto: f64,
    pub max_rto: f64,
    pub is_virtual: bool,
    pub start_paused: bool,
    pub enable_control_reliability: bool,
    pub control_rto: f64,
    pub control_max_rto: f64,
    pub control_max_retries: u32,
    pub inactivity_timeout: f64,
    pub data_packet_ttl: f64,
    pub max_data_retries: u32,
    pub control_packet_ttl: f64,
    pub data_nack_max_gap: usize,
    pub data_nack_initial_delay_seconds: f64,
    pub data_nack_repeat_seconds: f64,
    pub terminal_drain_timeout: f64,
    pub terminal_ack_wait_timeout: f64,
    pub compression_type: u8,
    pub is_client: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            window_size: 300,
            rto: 0.5,
            max_rto: 3.0,
            is_virtual: false,
            start_paused: false,
            enable_control_reliability: false,
            control_rto: 0.5,
            control_max_rto: 2.0,
            control_max_retries: 5,
            inactivity_timeout: 120.0,
            data_packet_ttl: 120.0,
            max_data_retries: 60,
            control_packet_ttl: 120.0,
            data_nack_max_gap: 0,
            data_nack_initial_delay_seconds: 0.0,
            data_nack_repeat_seconds: 0.1,
            terminal_drain_timeout: 60.0,
            terminal_ack_wait_timeout: 30.0,
            compression_type: 0,
            is_client: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CloseOptions {
    pub force: bool,
    pub send_rst: bool,
    pub send_close_write: bool,
    pub send_close_read: bool,
    pub after_drain: bool,
    pub ttl: Duration,
}
