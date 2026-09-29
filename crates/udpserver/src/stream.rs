//! Port of `internal/udpserver/stream_server.go`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};

/// Queued packet pending transmission or retransmission (`serverStreamTXPacket`).
pub struct ServerStreamTxPacket {
    pub packet_type: u8,
    pub sequence_num: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    pub compression_type: u8,
    pub payload: Vec<u8>,
    #[allow(dead_code)]
    pub created_at: Instant,
    pub ttl: Duration,
}

fn effective_priority(packet_type: u8, base_priority: i32) -> i32 {
    enums::normalize_packet_priority(packet_type, base_priority)
}

/// Upper bound on how long a STREAM_DATA_ACK demoted to
/// `PACKET_PRIORITY_LOW` (see `has_queued_download_data` /
/// `arq::data::store_received_data`) may sit behind this stream's own
/// download backlog before `pop_next_tx_packet` forces it out anyway.
///
/// The client's upload RTO can be as low as ~0.25-0.3s, so this bound must
/// leave generous margin under that: demoting the ACK to let download data
/// through must never delay it long enough to cause a client retransmission.
/// 25ms keeps it inside the ~20-30ms target while still being long enough to
/// batch several demoted ACKs into one PACKED_CONTROL_BLOCKS reply (see
/// `postsession::pack_control_blocks`'s `PACKABLE_SCAN_MAX_PRIORITY`, which
/// already reaches LOW-priority items) instead of trickling out one at a
/// time.
pub(crate) const ACK_COALESCE_BOUND: Duration = Duration::from_millis(25);

pub struct StreamServer {
    pub id: u16,
    pub session_id: u8,
    arq: OnceLock<Arc<arq::Arq>>,
    tx_queue: mlq::MultiLevelQueue<ServerStreamTxPacket>,

    state: Mutex<StreamState>,
    pub connected: AtomicBool,
}

struct StreamState {
    status: String,
    #[allow(dead_code)]
    created_at: Instant,
    last_activity: Instant,
    close_time: Option<Instant>,
    target_host: String,
    target_port: u16,
}

impl StreamServer {
    /// Constructs the stream and its ARQ instance together (two-phase, since
    /// the ARQ needs an `Arc<dyn PacketEnqueuer>` pointing back at this
    /// stream, which doesn't exist until the stream itself is already
    /// allocated — mirrors Go's `s := &Stream_server{...}; s.ARQ =
    /// arq.NewARQ(..., s, ...)` in-place mutation, via `OnceLock` instead).
    pub fn new(
        stream_id: u16,
        session_id: u8,
        arq_config: arq::Config,
        mtu: usize,
        queue_initial_capacity: usize,
        logger: Arc<dyn arq::ArqLogger>,
    ) -> Arc<Self> {
        let queue_cap = queue_initial_capacity.max(1);
        let now = Instant::now();

        let stream = Arc::new(StreamServer {
            id: stream_id,
            session_id,
            arq: OnceLock::new(),
            tx_queue: mlq::MultiLevelQueue::new(queue_cap),
            state: Mutex::new(StreamState {
                status: "PENDING".to_string(),
                created_at: now,
                last_activity: now,
                close_time: None,
                target_host: String::new(),
                target_port: 0,
            }),
            connected: AtomicBool::new(false),
        });

        let enqueuer: Arc<dyn arq::PacketEnqueuer> = stream.clone();
        let arq_instance = arq::Arq::new(stream_id, session_id, enqueuer, mtu, Some(logger), arq_config);
        arq_instance.start();
        let _ = stream.arq.set(arq_instance);

        stream
    }

    pub fn arq(&self) -> Option<&Arc<arq::Arq>> {
        self.arq.get()
    }

    pub fn status(&self) -> String {
        self.state.lock().unwrap().status.clone()
    }

    pub fn set_status(&self, status: &str) {
        self.state.lock().unwrap().status = status.to_string();
    }

    pub fn close_time(&self) -> Option<Instant> {
        self.state.lock().unwrap().close_time
    }

    pub fn target(&self) -> (String, u16) {
        let s = self.state.lock().unwrap();
        (s.target_host.clone(), s.target_port)
    }

    pub fn enqueue_inbound_data(&self, sequence_num: u16, payload: &[u8]) -> bool {
        match self.arq() {
            Some(arq) => arq.receive_data(sequence_num, payload),
            None => false,
        }
    }

    /// Attaches the dialed upstream connection to this stream's ARQ instance.
    /// Returns `false` if the stream is already closed/connected (mirrors Go's
    /// `attachUpstreamConn` guard against double/late attach).
    pub fn attach_upstream_conn<T>(&self, conn: T, host: &str, port: u16, status: &str) -> bool
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        {
            let mut s = self.state.lock().unwrap();
            if s.status == "CLOSED" || s.close_time.is_some() {
                return false;
            }
            if let Some(arq) = self.arq() {
                if arq.is_closed() {
                    return false;
                }
            }
            if self.connected.load(Ordering::SeqCst) {
                return false;
            }

            s.target_host = host.to_string();
            s.target_port = port;
            if !status.is_empty() {
                s.status = status.to_string();
            }
            s.last_activity = Instant::now();
        }
        self.connected.store(true, Ordering::SeqCst);

        if let Some(arq) = self.arq() {
            arq.set_local_conn(conn);
        }
        true
    }

    pub fn clear_tx_queue(&self) {
        self.tx_queue.clear(|_| {});
    }

    pub fn fast_tx_queue_size(&self) -> i32 {
        self.tx_queue.fast_size()
    }

    /// Pops the next queued packet for this stream's turn in
    /// `postsession::dequeue_session_response`.
    ///
    /// Before falling back to strict priority order, checks whether the LOW
    /// level's front item is a STREAM_DATA_ACK that has been waiting at
    /// least `ACK_COALESCE_BOUND` (see that constant) and, if so, forces it
    /// out now regardless of what else is queued. This is the bound half of
    /// the fix in `arq::data::store_received_data`/`has_queued_download_data`:
    /// that fix demotes a freshly-stored upload packet's immediate ACK to
    /// LOW priority when this stream also has NORMAL-priority download data
    /// queued, so a reply prefers sending that data instead of the lone ACK
    /// — strict priority order alone would then let a sustained download
    /// backlog starve the ACK indefinitely (the client's upload RTO can be
    /// as low as ~0.25-0.3s, and a late-enough re-ACK/retransmission risks
    /// the 16-bit sequence-wrap corruption bug `REACK_DELAY` exists to
    /// avoid), so this check guarantees it is released well inside that
    /// margin instead.
    pub fn pop_next_tx_packet(&self, now: Instant) -> Option<(ServerStreamTxPacket, i32)> {
        let aged_ack = self.tx_queue.pop_if(
            enums::PACKET_PRIORITY_LOW,
            |p: &ServerStreamTxPacket| p.packet_type == enums::PACKET_STREAM_DATA_ACK && now.saturating_duration_since(p.created_at) >= ACK_COALESCE_BOUND,
            |_| 0,
        );
        if let Some(item) = aged_ack {
            return Some((item, enums::PACKET_PRIORITY_LOW));
        }
        self.tx_queue.pop()
    }

    pub fn pop_any_tx_packet(&self, max_priority: i32, predicate: impl Fn(&ServerStreamTxPacket) -> bool) -> Option<ServerStreamTxPacket> {
        self.tx_queue.pop_any_if(max_priority, predicate, |_| 0)
    }

    pub fn note_tx_packet_dequeued(&self, packet: &ServerStreamTxPacket) {
        if let Some(arq) = self.arq() {
            arq.note_tx_packet_dequeued(packet.packet_type, packet.sequence_num, packet.fragment_id);
        }
    }

    pub fn abort(&self, reason: &str) {
        self.close_stream(true, Duration::ZERO, reason);
    }

    pub fn close_stream(&self, force: bool, ttl: Duration, reason: &str) {
        match self.arq() {
            Some(arq) => {
                if force {
                    self.set_status("CLOSED");
                    let mut s = self.state.lock().unwrap();
                    if s.close_time.is_none() {
                        s.close_time = Some(Instant::now());
                    }
                    drop(s);
                    arq.close(reason, arq::CloseOptions { send_rst: true, ttl, ..Default::default() });
                } else {
                    arq.close(reason, arq::CloseOptions { send_close_read: true, after_drain: true, ttl, ..Default::default() });
                }
            }
            None => {}
        }
    }
}

impl arq::PacketEnqueuer for StreamServer {
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
    ) -> bool {
        let now = Instant::now();
        {
            let mut s = self.state.lock().unwrap();
            s.last_activity = now;
        }

        let priority = effective_priority(packet_type, priority);

        let data_key = enums::packet_identity_key(self.id, enums::PACKET_STREAM_DATA, sequence_num, fragment_id);
        let resend_key = enums::packet_identity_key(self.id, enums::PACKET_STREAM_RESEND, sequence_num, fragment_id);
        let key = enums::packet_identity_key(self.id, packet_type, sequence_num, fragment_id);

        match packet_type {
            enums::PACKET_STREAM_DATA => {
                if self.tx_queue.contains_key(data_key) || self.tx_queue.contains_key(resend_key) {
                    return false;
                }
            }
            enums::PACKET_STREAM_RESEND => {
                if self.tx_queue.contains_key(resend_key) {
                    return false;
                }
            }
            _ => {}
        }

        let pkt = ServerStreamTxPacket {
            packet_type,
            sequence_num,
            fragment_id,
            total_fragments,
            compression_type,
            payload: payload.to_vec(),
            created_at: now,
            ttl,
        };

        if !self.tx_queue.push(priority, key, pkt) {
            return false;
        }

        if packet_type == enums::PACKET_STREAM_RESEND {
            self.tx_queue.remove_by_key(data_key);
        }

        true
    }

    fn on_arq_closed(&self, _reason: &str) {
        let (host, port);
        {
            let mut s = self.state.lock().unwrap();
            s.status = "CLOSED".to_string();
            if s.close_time.is_none() {
                s.close_time = Some(Instant::now());
            }
            host = s.target_host.clone();
            port = s.target_port;
        }
        let _ = (host, port);
        self.connected.store(false, Ordering::SeqCst);
        self.clear_tx_queue();
    }

    fn remove_queued_data(&self, sequence_num: u16) -> bool {
        let mut removed_any = false;
        for packet_type in [enums::PACKET_STREAM_DATA, enums::PACKET_STREAM_RESEND] {
            let key = enums::packet_identity_key(self.id, packet_type, sequence_num, 0);
            if self.tx_queue.remove_by_key(key).is_some() {
                removed_any = true;
            }
        }
        removed_any
    }

    fn remove_queued_data_nack(&self, sequence_num: u16) -> bool {
        let key = enums::packet_identity_key(self.id, enums::PACKET_STREAM_DATA_NACK, sequence_num, 0);
        self.tx_queue.remove_by_key(key).is_some()
    }

    fn has_queued_download_data(&self) -> bool {
        self.tx_queue.count(enums::PACKET_PRIORITY_NORMAL) > 0
    }
}
