//! Port of `internal/udpserver/session.go`.
//!
//! Simplification vs. Go: streams are removed from a session's map either at
//! an explicit close-triggering call site (RST, close-read/write handlers,
//! an ACK that resolves a close handshake) or by the periodic
//! `cleanup_terminal_streams` sweep (`session_cleanup_loop`, same as Go's
//! `SweepTerminalStreams`) noticing `Arq::is_closed()` — Go *additionally*
//! wires an immediate `onClosed` callback from `Stream_server` back into the
//! session so a background-timeout close (no triggering inbound packet) is
//! reaped right away instead of waiting for the next sweep tick. That
//! callback isn't ported here; the periodic sweep (default every 30s, see
//! `SESSION_CLEANUP_INTERVAL_SECONDS`) is the sole reaper, at the cost of
//! bounded extra latency before a purely-idle-timed-out stream's slot frees up.

use crate::stream::StreamServer;
use rustc_hash::FxHashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub const MAX_SERVER_SESSION_ID: usize = 255;
pub const SESSION_INIT_DATA_SIZE: usize = 10;
const MIN_SESSION_MTU: u16 = 10;
const MAX_SESSION_MTU: u16 = 4096;

pub const MTU_PROBE_MODE_BASE64: u8 = 1;

pub enum FindOrCreateOutcome {
    /// A `SESSION_INIT` retried before the client saw our `SESSION_ACCEPT`
    /// (idempotent replay of the same signature within the reuse TTL).
    Existing(Arc<SessionRecord>),
    Created(Arc<SessionRecord>),
    /// Malformed payload (wrong length / invalid response-mode byte) — Go
    /// silently ignores these (`nil, false, nil`), not an error.
    InvalidPayload,
    TableFull,
}

struct RecentlyClosedRecord {
    closed_at: Instant,
    suppress_orphan: bool,
}

/// Snapshot of a session's active streams, sorted by stream id.
pub type ActiveStreams = Arc<[(u16, Arc<StreamServer>)]>;

pub struct SessionRecord {
    pub id: u8,
    pub cookie: u8,
    pub response_mode: u8,
    pub upload_compression: u8,
    pub download_compression: u8,
    pub upload_mtu: u16,
    pub download_mtu: u16,
    pub download_mtu_bytes: usize,
    pub verify_code: [u8; 4],
    signature: [u8; SESSION_INIT_DATA_SIZE],
    pub max_packed_blocks: i64,
    pub created_at: Instant,
    reuse_until: Instant,
    last_activity: Mutex<Instant>,

    streams: RwLock<FxHashMap<u16, Arc<StreamServer>>>,
    /// Active (non-control) streams sorted by id, as an immutable snapshot.
    /// Rebuilt on the rare add/remove; every query reads it with one lock
    /// acquire and one `Arc` clone, then scans without touching `streams`.
    /// (Go keeps an equivalent cached snapshot; looking each stream up per
    /// query made all serve threads contend on the `streams` lock and the
    /// streams' refcounts.)
    active_streams: RwLock<ActiveStreams>,
    rr_stream_id: AtomicI32,

    recently_closed: Mutex<FxHashMap<u16, RecentlyClosedRecord>>,
    recently_closed_ttl: Duration,
    recently_closed_cap: usize,

    pub orphan_queue: mlq::MultiLevelQueue<vpnproto::Packet>,
    last_packed_control_block: Mutex<Option<(vpnproto::Packet, u32)>>,

    max_active_streams_per_session: usize,
    stream_queue_cap: usize,
    closed: AtomicBool,
}

impl SessionRecord {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: u8,
        response_mode: u8,
        created_at: Instant,
        reuse_until: Instant,
        signature: [u8; SESSION_INIT_DATA_SIZE],
        stream_queue_cap: usize,
        max_active_streams_per_session: usize,
        recently_closed_ttl: Duration,
        recently_closed_cap: usize,
        orphan_queue_cap: usize,
    ) -> Self {
        SessionRecord {
            id,
            cookie: 0,
            response_mode,
            upload_compression: 0,
            download_compression: 0,
            upload_mtu: 0,
            download_mtu: 0,
            download_mtu_bytes: 0,
            verify_code: [0; 4],
            signature,
            max_packed_blocks: 1,
            created_at,
            reuse_until,
            last_activity: Mutex::new(created_at),
            streams: RwLock::new(FxHashMap::default()),
            active_streams: RwLock::new(Vec::new().into()),
            rr_stream_id: AtomicI32::new(0),
            recently_closed: Mutex::new(FxHashMap::default()),
            recently_closed_ttl,
            recently_closed_cap,
            orphan_queue: mlq::MultiLevelQueue::new(orphan_queue_cap),
            last_packed_control_block: Mutex::new(None),
            max_active_streams_per_session,
            stream_queue_cap,
            closed: AtomicBool::new(false),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn mark_closed(&self) {
        self.closed.store(true, Ordering::Release);
    }

    pub fn set_last_activity(&self, now: Instant) {
        *self.last_activity.lock().unwrap() = now;
    }

    pub fn last_activity(&self) -> Instant {
        *self.last_activity.lock().unwrap()
    }

    pub fn reuse_until(&self) -> Instant {
        self.reuse_until
    }

    pub fn signature(&self) -> [u8; SESSION_INIT_DATA_SIZE] {
        self.signature
    }

    pub fn runtime_view(&self) -> SessionRuntimeView {
        SessionRuntimeView {
            id: self.id,
            cookie: self.cookie,
            response_mode: self.response_mode,
            response_base64: self.response_mode == MTU_PROBE_MODE_BASE64,
            download_compression: self.download_compression,
            download_mtu: self.download_mtu,
            download_mtu_bytes: self.download_mtu_bytes,
            max_packed_blocks: self.max_packed_blocks,
        }
    }

    pub fn apply_mtu_from_session_init(
        &mut self,
        upload_mtu: u16,
        download_mtu: u16,
        max_packets_per_batch: i64,
        max_client_upload_mtu: i64,
        max_client_download_mtu: i64,
    ) {
        let effective_upload_max = clamp_session_init_allowed_mtu(max_client_upload_mtu);
        let effective_download_max = clamp_session_init_allowed_mtu(max_client_download_mtu);

        self.upload_mtu = clamp_mtu_to_limit(upload_mtu, effective_upload_max);
        self.download_mtu = clamp_mtu_to_limit(download_mtu, effective_download_max);
        self.download_mtu_bytes = self.download_mtu as usize;
        self.max_packed_blocks = vpnproto::calculate_max_packed_blocks(self.download_mtu_bytes as i64, 80, max_packets_per_batch);
    }

    pub fn ensure_stream0(&self, logger: Arc<dyn arq::ArqLogger>) {
        if self.is_closed() {
            return;
        }
        self.get_or_create_stream(0, arq::Config { is_virtual: true, ..Default::default() }, 0, logger);
    }

    pub fn get_or_create_stream(&self, stream_id: u16, arq_config: arq::Config, mtu: usize, logger: Arc<dyn arq::ArqLogger>) -> Option<Arc<StreamServer>> {
        if self.is_closed() {
            return None;
        }

        let mut streams = self.streams.write().unwrap();
        if self.is_closed() {
            return None;
        }
        if let Some(s) = streams.get(&stream_id) {
            return Some(s.clone());
        }

        if !self.can_create_additional_stream_locked(&streams, stream_id) {
            return None;
        }

        self.recently_closed.lock().unwrap().remove(&stream_id);

        let stream = StreamServer::new(stream_id, self.id, arq_config, mtu.max(1), self.stream_queue_cap, logger);
        streams.insert(stream_id, stream.clone());

        if stream_id != 0 {
            let mut active = self.active_streams.write().unwrap();
            if let Err(pos) = active.binary_search_by_key(&stream_id, |(id, _)| *id) {
                let mut rebuilt = Vec::with_capacity(active.len() + 1);
                rebuilt.extend_from_slice(&active[..pos]);
                rebuilt.push((stream_id, stream.clone()));
                rebuilt.extend_from_slice(&active[pos..]);
                *active = rebuilt.into();
            }
        }

        Some(stream)
    }

    pub fn can_create_additional_stream(&self, stream_id: u16) -> bool {
        if self.is_closed() {
            return false;
        }
        let streams = self.streams.read().unwrap();
        self.can_create_additional_stream_locked(&streams, stream_id)
    }

    fn can_create_additional_stream_locked(&self, streams: &FxHashMap<u16, Arc<StreamServer>>, stream_id: u16) -> bool {
        if stream_id == 0 {
            return true;
        }
        if streams.contains_key(&stream_id) {
            return true;
        }
        let limit = if self.max_active_streams_per_session == 0 { 2000 } else { self.max_active_streams_per_session };
        let mut active = streams.len();
        if streams.contains_key(&0) {
            active -= 1;
        }
        active < limit
    }

    pub fn get_stream(&self, stream_id: u16) -> Option<Arc<StreamServer>> {
        if self.is_closed() {
            return None;
        }
        self.streams.read().unwrap().get(&stream_id).cloned()
    }

    pub fn active_stream_snapshot(&self) -> ActiveStreams {
        if self.is_closed() {
            return Vec::new().into();
        }
        self.active_streams.read().unwrap().clone()
    }

    pub fn rr_stream_id(&self) -> i32 {
        self.rr_stream_id.load(Ordering::Relaxed)
    }
    pub fn set_rr_stream_id(&self, v: i32) {
        self.rr_stream_id.store(v, Ordering::Relaxed);
    }

    pub fn remove_stream(&self, stream_id: u16, now: Instant, suppress_orphan: bool) {
        if self.is_closed() || stream_id == 0 {
            return;
        }
        self.streams.write().unwrap().remove(&stream_id);
        self.remove_active_stream(stream_id);
        self.note_stream_closed(stream_id, now, suppress_orphan);
    }

    pub fn deactivate_stream(&self, stream_id: u16) {
        if self.is_closed() || stream_id == 0 {
            return;
        }
        self.remove_active_stream(stream_id);
    }

    fn remove_active_stream(&self, stream_id: u16) {
        let mut active = self.active_streams.write().unwrap();
        if active.binary_search_by_key(&stream_id, |(id, _)| *id).is_ok() {
            *active = active.iter().filter(|(id, _)| *id != stream_id).cloned().collect();
        }
    }

    pub fn note_stream_closed(&self, stream_id: u16, now: Instant, suppress_orphan: bool) {
        if self.is_closed() || stream_id == 0 {
            return;
        }
        let mut rc = self.recently_closed.lock().unwrap();
        self.prune_recently_closed_locked(&mut rc, now);
        rc.insert(stream_id, RecentlyClosedRecord { closed_at: now, suppress_orphan });
        if rc.len() > self.recently_closed_cap.max(1) {
            if let Some((&oldest_id, _)) = rc.iter().min_by_key(|(_, r)| r.closed_at) {
                rc.remove(&oldest_id);
            }
        }
    }

    pub fn prune_recently_closed(&self, now: Instant) {
        if self.is_closed() {
            return;
        }
        let mut rc = self.recently_closed.lock().unwrap();
        self.prune_recently_closed_locked(&mut rc, now);
    }

    fn prune_recently_closed_locked(&self, rc: &mut FxHashMap<u16, RecentlyClosedRecord>, now: Instant) {
        rc.retain(|_, r| now.duration_since(r.closed_at) <= self.recently_closed_ttl);
    }

    pub fn is_recently_closed(&self, stream_id: u16, now: Instant) -> bool {
        if self.is_closed() {
            return false;
        }
        let rc = self.recently_closed.lock().unwrap();
        rc.get(&stream_id).map(|r| now.duration_since(r.closed_at) <= self.recently_closed_ttl).unwrap_or(false)
    }

    pub fn should_suppress_orphan_for_closed_stream(&self, stream_id: u16, now: Instant) -> bool {
        if self.is_closed() {
            return false;
        }
        let rc = self.recently_closed.lock().unwrap();
        rc.get(&stream_id).map(|r| now.duration_since(r.closed_at) <= self.recently_closed_ttl && r.suppress_orphan).unwrap_or(false)
    }

    pub fn enqueue_orphan_reset(&self, packet_type: u8, stream_id: u16, sequence_num: u16) {
        if self.is_closed() || stream_id == 0 {
            return;
        }
        let packet = vpnproto::Packet {
            packet_type,
            stream_id,
            has_stream_id: true,
            sequence_num,
            has_sequence_num: sequence_num != 0,
            ..Default::default()
        };
        let key = enums::packet_type_stream_key(stream_id, packet_type);
        self.orphan_queue.push(0, key, packet);
    }

    pub fn dequeue_duplicated_packed_control_block(&self) -> Option<vpnproto::Packet> {
        let mut cached = self.last_packed_control_block.lock().unwrap();
        let (packet, remaining) = cached.as_mut()?;
        let out = packet.clone();
        *remaining -= 1;
        if *remaining == 0 {
            *cached = None;
        }
        Some(out)
    }

    pub fn cache_packed_control_block_duplicate(&self, duplication: u32, packet: Option<vpnproto::Packet>) {
        let mut cached = self.last_packed_control_block.lock().unwrap();
        match (duplication > 1, packet) {
            (true, Some(p)) if p.packet_type == enums::PACKET_PACKED_CONTROL_BLOCKS => {
                *cached = Some((p, duplication - 1));
            }
            _ => *cached = None,
        }
    }

    pub fn close_all_streams(&self, reason: &str) {
        self.mark_closed();
        let streams: Vec<Arc<StreamServer>> = self.streams.read().unwrap().values().cloned().collect();
        for stream in streams {
            if reason != "session closed cleanup" {
                stream.abort(reason);
            } else if let Some(arq) = stream.arq() {
                arq.close(reason, arq::CloseOptions { force: true, ..Default::default() });
            }
        }
        self.streams.write().unwrap().clear();
        *self.active_streams.write().unwrap() = Vec::new().into();
        self.orphan_queue.clear(|_| {});
    }

    pub fn cleanup_terminal_streams(&self, now: Instant, retention: Duration) {
        if self.is_closed() {
            return;
        }
        let snapshot: Vec<(u16, Arc<StreamServer>)> = self.streams.read().unwrap().iter().map(|(&k, v)| (k, v.clone())).collect();

        let mut remove_ids = Vec::new();
        for (stream_id, stream) in &snapshot {
            if *stream_id == 0 {
                continue;
            }
            let arq = match stream.arq() {
                Some(a) => a,
                None => continue,
            };

            match arq.state() {
                arq::StreamState::Draining => stream.set_status("DRAINING"),
                arq::StreamState::HalfClosedLocal | arq::StreamState::HalfClosedRemote | arq::StreamState::Closing => {
                    stream.set_status("CLOSING")
                }
                arq::StreamState::TimeWait => stream.set_status("TIME_WAIT"),
                _ => {}
            }

            let force_closed_expired = stream.close_time().map(|t| now.duration_since(t) >= retention).unwrap_or(false);
            if arq.is_closed() || force_closed_expired {
                stream.set_status("TIME_WAIT");
                if force_closed_expired {
                    remove_ids.push(*stream_id);
                }
            }
        }

        for stream_id in remove_ids {
            if let Some((_, stream)) = snapshot.iter().find(|(id, _)| *id == stream_id) {
                stream.abort("terminal stream retention cleanup");
            }
            self.remove_stream(stream_id, now, false);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SessionRuntimeView {
    pub id: u8,
    pub cookie: u8,
    pub response_mode: u8,
    pub response_base64: bool,
    pub download_compression: u8,
    pub download_mtu: u16,
    pub download_mtu_bytes: usize,
    pub max_packed_blocks: i64,
}

fn clamp_mtu(value: u16) -> u16 {
    value.clamp(MIN_SESSION_MTU, MAX_SESSION_MTU)
}
fn clamp_mtu_to_limit(value: u16, max_allowed: u16) -> u16 {
    clamp_mtu(value).min(max_allowed)
}
fn clamp_session_init_allowed_mtu(value: i64) -> u16 {
    value.clamp(MIN_SESSION_MTU as i64, MAX_SESSION_MTU as i64) as u16
}

pub fn is_valid_session_response_mode(value: u8) -> bool {
    value <= MTU_PROBE_MODE_BASE64
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SessionLookupState {
    Unknown,
    Active,
    Closed,
}

#[derive(Clone, Copy)]
pub struct SessionLookupResult {
    pub cookie: u8,
    pub response_mode: u8,
    pub state: SessionLookupState,
}

pub struct SessionValidationResult {
    pub lookup: SessionLookupResult,
    pub known: bool,
    pub valid: bool,
    pub active: Option<SessionRuntimeView>,
}

struct ClosedSessionRecord {
    cookie: u8,
    response_mode: u8,
    expires_at: Instant,
}

struct SessionStoreInner {
    next_id: u16,
    active_count: u16,
    by_id: Vec<Option<Arc<SessionRecord>>>,
    by_sig: HashMap<[u8; SESSION_INIT_DATA_SIZE], u8>,
    recent_closed: HashMap<u8, ClosedSessionRecord>,
    cookie_bytes: [u8; 32],
    cookie_index: usize,
}

pub struct SessionStore {
    inner: RwLock<SessionStoreInner>,
    orphan_queue_cap: usize,
    stream_queue_cap: usize,
    pub max_active_sessions: AtomicU16,
    pub max_active_streams: AtomicU16,
    session_init_ttl: Duration,
    recently_closed_ttl: Duration,
    recently_closed_cap: usize,
}

impl SessionStore {
    pub fn new(
        orphan_queue_cap: usize,
        stream_queue_cap: usize,
        session_init_ttl: Duration,
        recently_closed_ttl: Duration,
        recently_closed_cap: usize,
    ) -> Self {
        let mut by_id = Vec::with_capacity(MAX_SERVER_SESSION_ID + 1);
        by_id.resize_with(MAX_SERVER_SESSION_ID + 1, || None);

        SessionStore {
            inner: RwLock::new(SessionStoreInner {
                next_id: 1,
                active_count: 0,
                by_id,
                by_sig: HashMap::new(),
                recent_closed: HashMap::new(),
                cookie_bytes: [0; 32],
                cookie_index: 32,
            }),
            orphan_queue_cap: orphan_queue_cap.max(8),
            stream_queue_cap: stream_queue_cap.max(32),
            max_active_sessions: AtomicU16::new(MAX_SERVER_SESSION_ID as u16),
            max_active_streams: AtomicU16::new(1000),
            session_init_ttl: if session_init_ttl.is_zero() { Duration::from_secs(600) } else { session_init_ttl },
            recently_closed_ttl: if recently_closed_ttl.is_zero() { Duration::from_secs(600) } else { recently_closed_ttl },
            recently_closed_cap: recently_closed_cap.max(1),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn find_or_create(
        &self,
        payload: &[u8],
        upload_compression_type: u8,
        download_compression_type: u8,
        max_packets_per_batch: i64,
        max_client_upload_mtu: i64,
        max_client_download_mtu: i64,
    ) -> FindOrCreateOutcome {
        if payload.len() != SESSION_INIT_DATA_SIZE || !is_valid_session_response_mode(payload[0]) {
            return FindOrCreateOutcome::InvalidPayload;
        }

        let mut signature = [0u8; SESSION_INIT_DATA_SIZE];
        signature.copy_from_slice(payload);

        let now = Instant::now();
        let mut inner = self.inner.write().unwrap();

        self.expire_reuse_locked(&mut inner, now);

        if let Some(&session_id) = inner.by_sig.get(&signature) {
            if let Some(existing) = &inner.by_id[session_id as usize] {
                if now <= existing.reuse_until() {
                    existing.set_last_activity(now);
                    return FindOrCreateOutcome::Existing(existing.clone());
                }
            }
            inner.by_sig.remove(&signature);
        }

        let slot = match self.allocate_slot_locked(&mut inner) {
            Some(s) => s,
            None => return FindOrCreateOutcome::TableFull,
        };

        let mut record = SessionRecord::new(
            slot as u8,
            payload[0],
            now,
            now + self.session_init_ttl,
            signature,
            self.stream_queue_cap,
            self.max_active_streams.load(Ordering::Relaxed) as usize,
            self.recently_closed_ttl,
            self.recently_closed_cap,
            self.orphan_queue_cap,
        );

        record.upload_compression = upload_compression_type;
        record.download_compression = download_compression_type;
        record.apply_mtu_from_session_init(
            u16::from_be_bytes([payload[2], payload[3]]),
            u16::from_be_bytes([payload[4], payload[5]]),
            max_packets_per_batch,
            max_client_upload_mtu,
            max_client_download_mtu,
        );
        record.verify_code.copy_from_slice(&payload[6..10]);
        record.cookie = self.random_cookie_locked(&mut inner);

        let record = Arc::new(record);
        inner.by_id[slot] = Some(record.clone());
        inner.active_count += 1;
        inner.by_sig.insert(signature, slot as u8);
        inner.recent_closed.remove(&(slot as u8));
        inner.next_id = next_session_id(slot as u8) as u16;

        FindOrCreateOutcome::Created(record)
    }

    fn expire_reuse_locked(&self, inner: &mut SessionStoreInner, now: Instant) {
        inner.by_sig.retain(|_, &mut session_id| match &inner.by_id[session_id as usize] {
            Some(record) => now <= record.reuse_until(),
            None => false,
        });
    }

    pub fn get(&self, session_id: u8) -> Option<Arc<SessionRecord>> {
        let inner = self.inner.read().unwrap();
        inner.by_id[session_id as usize].as_ref().filter(|r| !r.is_closed()).cloned()
    }

    pub fn lookup(&self, session_id: u8) -> Option<SessionLookupResult> {
        let inner = self.inner.read().unwrap();
        if let Some(record) = &inner.by_id[session_id as usize] {
            return Some(SessionLookupResult { cookie: record.cookie, response_mode: record.response_mode, state: SessionLookupState::Active });
        }
        if let Some(record) = inner.recent_closed.get(&session_id) {
            return Some(SessionLookupResult { cookie: record.cookie, response_mode: record.response_mode, state: SessionLookupState::Closed });
        }
        None
    }

    pub fn validate_and_touch(&self, session_id: u8, cookie: u8, now: Instant) -> SessionValidationResult {
        let inner = self.inner.read().unwrap();
        if let Some(record) = &inner.by_id[session_id as usize] {
            let valid = record.cookie == cookie;
            let result = SessionValidationResult {
                lookup: SessionLookupResult { cookie: record.cookie, response_mode: record.response_mode, state: SessionLookupState::Active },
                known: true,
                valid,
                active: if valid { Some(record.runtime_view()) } else { None },
            };
            if valid {
                record.set_last_activity(now);
            }
            return result;
        }

        if let Some(record) = inner.recent_closed.get(&session_id) {
            return SessionValidationResult {
                lookup: SessionLookupResult { cookie: record.cookie, response_mode: record.response_mode, state: SessionLookupState::Closed },
                known: true,
                valid: false,
                active: None,
            };
        }

        SessionValidationResult {
            lookup: SessionLookupResult { cookie: 0, response_mode: 0, state: SessionLookupState::Unknown },
            known: false,
            valid: false,
            active: None,
        }
    }

    pub fn close(&self, session_id: u8, now: Instant, retention: Duration) -> Option<Arc<SessionRecord>> {
        let mut inner = self.inner.write().unwrap();
        let record = inner.by_id[session_id as usize].take()?;
        record.mark_closed();

        inner.by_sig.remove(&record.signature());
        if inner.active_count > 0 {
            inner.active_count -= 1;
        }
        if !retention.is_zero() {
            inner.recent_closed.insert(
                session_id,
                ClosedSessionRecord { cookie: record.cookie, response_mode: record.response_mode, expires_at: now + retention },
            );
        } else {
            inner.recent_closed.remove(&session_id);
        }
        Some(record)
    }

    pub fn cleanup(&self, now: Instant, idle_timeout: Duration, closed_retention: Duration) -> Vec<(u8, Arc<SessionRecord>)> {
        let mut inner = self.inner.write().unwrap();
        self.expire_reuse_locked(&mut inner, now);

        inner.recent_closed.retain(|_, r| now < r.expires_at);

        if idle_timeout.is_zero() {
            return Vec::new();
        }

        let mut expired = Vec::new();
        for session_id in 1..=MAX_SERVER_SESSION_ID {
            let record = match &inner.by_id[session_id] {
                Some(r) => r.clone(),
                None => continue,
            };

            if now.duration_since(record.last_activity()) < idle_timeout {
                continue;
            }

            inner.by_sig.remove(&record.signature());
            inner.by_id[session_id] = None;
            if inner.active_count > 0 {
                inner.active_count -= 1;
            }
            if !closed_retention.is_zero() {
                inner.recent_closed.insert(
                    session_id as u8,
                    ClosedSessionRecord { cookie: record.cookie, response_mode: record.response_mode, expires_at: now + closed_retention },
                );
            }
            record.mark_closed();
            expired.push((session_id as u8, record));
        }

        expired
    }

    pub fn sweep_terminal_streams(&self, now: Instant, retention: Duration) {
        let records: Vec<Arc<SessionRecord>> = self.inner.read().unwrap().by_id.iter().flatten().cloned().collect();
        for record in records {
            record.cleanup_terminal_streams(now, retention);
        }
    }

    pub fn sweep_recently_closed_streams(&self, now: Instant) {
        let records: Vec<Arc<SessionRecord>> = self.inner.read().unwrap().by_id.iter().flatten().cloned().collect();
        for record in records {
            record.prune_recently_closed(now);
        }
    }

    fn allocate_slot_locked(&self, inner: &mut SessionStoreInner) -> Option<usize> {
        let max_active = (self.max_active_sessions.load(Ordering::Relaxed) as usize).clamp(1, MAX_SERVER_SESSION_ID);
        if inner.active_count as usize >= max_active {
            return None;
        }

        let start = if (1..=MAX_SERVER_SESSION_ID).contains(&(inner.next_id as usize)) { inner.next_id as usize } else { 1 };
        for slot in start..=MAX_SERVER_SESSION_ID {
            if inner.by_id[slot].is_none() {
                return Some(slot);
            }
        }
        for slot in 1..start {
            if inner.by_id[slot].is_none() {
                return Some(slot);
            }
        }
        None
    }

    fn random_cookie_locked(&self, inner: &mut SessionStoreInner) -> u8 {
        if inner.cookie_index >= inner.cookie_bytes.len() {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut inner.cookie_bytes);
            inner.cookie_index = 0;
        }
        let value = inner.cookie_bytes[inner.cookie_index];
        inner.cookie_index += 1;
        value
    }
}

fn next_session_id(current: u8) -> u8 {
    if current as usize >= MAX_SERVER_SESSION_ID {
        1
    } else {
        current + 1
    }
}
