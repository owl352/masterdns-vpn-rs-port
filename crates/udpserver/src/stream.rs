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

    pub fn pop_next_tx_packet(&self) -> Option<(ServerStreamTxPacket, i32)> {
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
}
