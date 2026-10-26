//! Port of `internal/udpserver/stream_server.go`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};

/// Queued packet pending transmission or retransmission (`serverStreamTXPacket`).
pub struct ServerStreamTxPacket {
    pub logical_sequence: Option<u32>,
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
    pub(crate) compression_skip: compression::AdaptiveSkip,

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
            compression_skip: compression::AdaptiveSkip::default(),
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
                enums::PACKET_STREAM_FEEDBACK | enums::PACKET_STREAM_DATA_ACK | enums::PACKET_STREAM_DATA | enums::PACKET_STREAM_RESEND
            )
        };
        let popped = if self.control_streak.load(Ordering::Relaxed) >= 4 {
            self.tx_queue.pop_prefer_if(&[enums::PACKET_PRIORITY_NORMAL], |p| p.packet_type == enums::PACKET_STREAM_DATA, bypassable)
        } else if self.data_streak.load(Ordering::Relaxed) >= 16 {
            self.tx_queue.pop_prefer_if(
                &[enums::PACKET_PRIORITY_CRITICAL, enums::PACKET_PRIORITY_LOW],
                |p| matches!(p.packet_type, enums::PACKET_STREAM_DATA_ACK | enums::PACKET_STREAM_FEEDBACK) && p.created_at.elapsed() >= Duration::from_millis(100),
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
        self.push_packet(priority,packet_type,sequence_num,fragment_id,total_fragments,compression_type,ttl,payload,None)
    }
    fn push_tx_logical_packet(&self,priority:i32,packet_type:u8,logical_seq:u32,fragment_id:u8,total_fragments:u8,compression_type:u8,ttl:Duration,payload:&[u8])->bool {
        self.push_packet(priority,packet_type,logical_seq as u16,fragment_id,total_fragments,compression_type,ttl,payload,Some(logical_seq))
    }
    fn remove_queued_logical_data(&self,logical_seq:u32)->bool {
        let mut removed=false;
        for kind in [enums::PACKET_STREAM_DATA,enums::PACKET_STREAM_RESEND] {
            removed |= self.tx_queue.remove_by_key(enums::packet_identity_logical(self.id,kind,logical_seq,0)).is_some();
        }
        removed
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

    fn remove_queued_control(&self, packet_type: u8, sequence_num: u16, fragment_id: u8) -> bool {
        let key = enums::packet_identity_key(self.id, packet_type, sequence_num, fragment_id);
        self.tx_queue.remove_by_key(key).is_some()
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
                logical_sequence: None,
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

    #[tokio::test]
    async fn acked_control_retry_is_removed_from_stream_queue() {
        let stream = StreamServer::new(1, 1, arq::Config { enable_control_reliability: true, ..Default::default() },
            1000, 64, Arc::new(arq::DummyLogger));
        let arq = stream.arq().unwrap();
        let kind = enums::PACKET_STREAM_CONNECTED;
        assert!(arq.send_control_packet_with_ttl(kind, 0, 0, 0, &[], 0, true, None, Duration::ZERO));
        assert_eq!(stream.fast_tx_queue_size(), 1);
        arq.note_tx_packet_dequeued(kind, 0, 0);
        // Model a late ACK of an earlier copy while this retry is still queued.
        assert!(arq.receive_control_ack(enums::control_ack_for(kind).unwrap(), 0, 0));
        assert_eq!(stream.fast_tx_queue_size(), 0);
        arq.close("test", arq::CloseOptions::default());
    }

}

impl StreamServer {
    #[allow(clippy::too_many_arguments)]
    fn push_packet(&self,priority:i32,packet_type:u8,sequence_num:u16,fragment_id:u8,total_fragments:u8,compression_type:u8,ttl:Duration,payload:&[u8],logical_sequence:Option<u32>)->bool {
        if let Some(seq) = logical_sequence {
            if !self.arq().is_some_and(|a| a.has_pending_logical_sequence(seq)) { return false; }
        }
        let now = Instant::now();
        {
            let mut s = self.state.lock().unwrap();
            s.last_activity = now;
        }

        let priority = effective_priority(packet_type, priority);

        let identity = |kind| match logical_sequence { Some(seq) => enums::packet_identity_logical(self.id,kind,seq,fragment_id), None => enums::packet_identity_key(self.id,kind,sequence_num,fragment_id) };
        let data_key = identity(enums::PACKET_STREAM_DATA);
        let resend_key = identity(enums::PACKET_STREAM_RESEND);
        let key = identity(packet_type);

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
            logical_sequence,
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
}

#[cfg(test)]
mod logical_queue_tests {
    use super::*;
    use arq::PacketEnqueuer;
    #[tokio::test]
    async fn stale_cleanup_cannot_remove_same_low16_in_next_epoch() {
        let stream=StreamServer::new(1,1,arq::Config{transport_serial_span:300,transport_feedback_budget:64,..Default::default()},150,64,Arc::new(arq::DummyLogger));
        // Inject identities directly: live ARQ intentionally cannot hold
        // both epochs at once, but an old cleanup callback can overlap one.
        for (seq,data) in [(0,b"old".as_slice()),(65536,b"new".as_slice())] {
            assert!(stream.tx_queue.push(enums::PACKET_PRIORITY_NORMAL,
                enums::packet_identity_logical(stream.id,enums::PACKET_STREAM_DATA,seq,0),
                ServerStreamTxPacket{logical_sequence:Some(seq),packet_type:enums::PACKET_STREAM_DATA,sequence_num:seq as u16,
                    fragment_id:0,total_fragments:0,compression_type:0,payload:data.to_vec(),created_at:Instant::now(),ttl:Duration::ZERO}));
        }
        assert!(stream.remove_queued_logical_data(0));assert_eq!(stream.fast_tx_queue_size(),1);
        let next=stream.pop_next_tx_packet().unwrap().0;assert_eq!(next.logical_sequence,Some(65536));assert_eq!(next.payload,b"new");
        stream.arq().unwrap().close("test",arq::CloseOptions::default());
    }
}
