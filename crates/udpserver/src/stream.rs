//! Port of `internal/udpserver/stream_server.go`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    control_streak: AtomicUsize,
    data_streak: AtomicUsize,

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
            control_streak: AtomicUsize::new(0),
            data_streak: AtomicUsize::new(0),
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
        let bypassable = |p: &ServerStreamTxPacket| {
            matches!(
                p.packet_type,
                enums::PACKET_STREAM_DATA_ACK | enums::PACKET_STREAM_DATA | enums::PACKET_STREAM_RESEND
            )
        };
        let popped = if self.control_streak.load(Ordering::Relaxed) >= 4 {
            self.tx_queue.pop_prefer_if(&[enums::PACKET_PRIORITY_NORMAL], |p| p.packet_type == enums::PACKET_STREAM_DATA, bypassable)
        } else if self.data_streak.load(Ordering::Relaxed) >= 16 {
            self.tx_queue.pop_prefer_if(
                &[enums::PACKET_PRIORITY_CRITICAL, enums::PACKET_PRIORITY_LOW],
                |p| p.packet_type == enums::PACKET_STREAM_DATA_ACK && p.created_at.elapsed() >= Duration::from_millis(100),
                bypassable,
            )
        } else {
            self.tx_queue.pop()
        };
        if let Some((p, _)) = &popped {
            if p.packet_type == enums::PACKET_STREAM_DATA {
                self.control_streak.store(0, Ordering::Relaxed);
            } else {
                self.control_streak.fetch_add(1, Ordering::Relaxed);
            }
            if matches!(p.packet_type, enums::PACKET_STREAM_DATA | enums::PACKET_STREAM_RESEND) {
                self.data_streak.fetch_add(1, Ordering::Relaxed);
            } else {
                self.data_streak.store(0, Ordering::Relaxed);
            }
        }
        popped
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

#[cfg(test)]
mod scheduling_tests {
    use super::*;
    use arq::PacketEnqueuer;

    fn queue(stream: &StreamServer, kind: u8, sn: u16) {
        assert!(stream.push_tx_packet(enums::default_packet_priority(kind), kind, sn, 0, 0, 0, Duration::ZERO, &[]));
    }

    #[tokio::test]
    async fn ack_and_recovery_backlog_cannot_starve_new_data() {
        for kind in [enums::PACKET_STREAM_DATA_ACK, enums::PACKET_STREAM_RESEND] {
            let stream = StreamServer::new(1, 1, arq::Config::default(), 1000, 64, Arc::new(arq::DummyLogger));
            for sn in 1..20 {
                queue(&stream, kind, sn);
            }
            queue(&stream, enums::PACKET_STREAM_DATA, 50);
            for _ in 0..4 {
                assert_eq!(stream.pop_next_tx_packet().unwrap().0.packet_type, kind);
            }
            assert_eq!(stream.pop_next_tx_packet().unwrap().0.packet_type, enums::PACKET_STREAM_DATA);
            stream.arq().unwrap().close("test", arq::CloseOptions::default());
        }
    }

    #[tokio::test]
    async fn fairness_does_not_bypass_close_or_reset() {
        let stream = StreamServer::new(1, 1, arq::Config::default(), 1000, 64, Arc::new(arq::DummyLogger));
        for sn in 1..5 {
            queue(&stream, enums::PACKET_STREAM_DATA_ACK, sn);
        }
        for _ in 0..4 {
            stream.pop_next_tx_packet().unwrap();
        }
        queue(&stream, enums::PACKET_STREAM_DATA, 50);
        queue(&stream, enums::PACKET_STREAM_RST, 60);
        assert_eq!(stream.pop_next_tx_packet().unwrap().0.packet_type, enums::PACKET_STREAM_RST);
        stream.arq().unwrap().close("test", arq::CloseOptions::default());
    }

    #[tokio::test]
    async fn aged_reack_gets_a_slot_under_continuous_data() {
        let stream = StreamServer::new(1, 1, arq::Config::default(), 1000, 64, Arc::new(arq::DummyLogger));
        for sn in 0..20 {
            queue(&stream, enums::PACKET_STREAM_DATA, sn);
        }
        assert!(stream.tx_queue.push(
            enums::PACKET_PRIORITY_LOW,
            999,
            ServerStreamTxPacket {
                packet_type: enums::PACKET_STREAM_DATA_ACK,
                sequence_num: 90,
                fragment_id: 0,
                total_fragments: 0,
                compression_type: 0,
                payload: Vec::new(),
                created_at: Instant::now() - Duration::from_millis(101),
                ttl: Duration::ZERO,
            }
        ));
        for _ in 0..16 {
            assert_eq!(stream.pop_next_tx_packet().unwrap().0.packet_type, enums::PACKET_STREAM_DATA);
        }
        assert_eq!(stream.pop_next_tx_packet().unwrap().0.packet_type, enums::PACKET_STREAM_DATA_ACK);
        stream.arq().unwrap().close("test", arq::CloseOptions::default());
    }
}
