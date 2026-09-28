//! Port of `internal/dnscache/store.go`: a 32-shard, TTL + pending/ready
//! sharded DNS response cache with single-flight-style pending coalescing and
//! binary file persistence.
//!
//! Each shard is an `IndexMap<Vec<u8>, Entry>` rather than Go's
//! `container/list` + map: `IndexMap::move_index` reproduces `MoveToBack`
//! (touch-to-MRU) at the cost of an O(n) shift within that shard (bounded by
//! `maxRecords/32`, not the whole cache) instead of Go's true O(1) — the same
//! trade-off already made in the `mlq` crate, and fine for a resolution cache.

use std::io::{BufWriter, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;

const SHARD_COUNT: usize = 32;
const SHARD_MASK: u32 = (SHARD_COUNT - 1) as u32;
const BINARY_MAGIC: u32 = 0x444E5343; // "DNSC"
const BINARY_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Ready,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub domain: String,
    pub question_type: u16,
    pub question_class: u16,
    pub status: Status,
    pub created_at: SystemTime,
    pub last_used_at: SystemTime,
    pub last_dispatch_at: SystemTime,
    pub response: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct LookupResult {
    pub status: Option<Status>,
    pub response: Option<Vec<u8>>,
    pub dispatch_needed: bool,
}

struct Shard {
    items: IndexMap<Vec<u8>, Entry>,
}

pub struct Store {
    max_records: usize,
    cache_ttl: Duration,
    pending_timeout: Duration,
    shards: Vec<RwLock<Shard>>,
    pending_total: AtomicU64,
    dirty: AtomicU64,
}

pub fn build_key(domain: &str, q_type: u16, q_class: u16) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + domain.len());
    key.extend_from_slice(&q_type.to_be_bytes());
    key.extend_from_slice(&q_class.to_be_bytes());
    key.extend_from_slice(domain.as_bytes());
    key
}

fn shard_index(key: &[u8]) -> usize {
    // FNV-1a 32-bit.
    let mut hash: u32 = 0x811c9dc5;
    for &b in key {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    (hash & SHARD_MASK) as usize
}

/// Rewrites `raw_response`'s DNS transaction ID and the RD/RA flag bits (mask
/// `0x0110`) to match `raw_query`, so a cached answer can serve a differently
/// (but equivalently) ID'd/flagged retry.
pub fn patch_response_for_query(raw_response: &[u8], raw_query: Option<&[u8]>) -> Vec<u8> {
    if raw_response.len() < 2 {
        return raw_response.to_vec();
    }
    let raw_query = match raw_query {
        Some(q) if q.len() >= 2 => q,
        _ => return raw_response.to_vec(),
    };

    let mut patched = raw_response.to_vec();
    patched[0] = raw_query[0];
    patched[1] = raw_query[1];
    if raw_query.len() >= 4 && patched.len() >= 4 {
        let query_flags = u16::from_be_bytes([raw_query[2], raw_query[3]]);
        let response_flags = u16::from_be_bytes([patched[2], patched[3]]);
        let response_flags = (response_flags & !0x0110) | (query_flags & 0x0110);
        patched[2..4].copy_from_slice(&response_flags.to_be_bytes());
    }
    patched
}

impl Store {
    pub fn new(max_records: usize, cache_ttl: Duration, pending_timeout: Duration) -> Self {
        let max_records = max_records.max(1);
        let cache_ttl = if cache_ttl.is_zero() { Duration::from_secs(3600) } else { cache_ttl };
        let pending_timeout = if pending_timeout.is_zero() { Duration::from_secs(30) } else { pending_timeout };

        let per_shard = max_records / SHARD_COUNT + 1;
        let shards = (0..SHARD_COUNT).map(|_| RwLock::new(Shard { items: IndexMap::with_capacity(per_shard) })).collect();

        Store { max_records, cache_ttl, pending_timeout, shards, pending_total: AtomicU64::new(0), dirty: AtomicU64::new(0) }
    }

    pub fn lookup_or_create_pending(&self, key: &[u8], domain: &str, q_type: u16, q_class: u16, now: SystemTime) -> LookupResult {
        if key.is_empty() {
            return LookupResult::default();
        }

        let shard_idx = shard_index(key);
        let mut shard = self.shards[shard_idx].write().unwrap();

        if let Some(idx) = shard.items.get_index_of(key) {
            if !self.is_expired(&shard.items[idx], now) {
                self.touch_entry_at(&mut shard, idx, now);
                let last = shard.items.len() - 1;
                shard.items.move_index(idx, last);
                let entry = &shard.items[last];

                if entry.status == Status::Ready {
                    let response = patch_response_for_query(&entry.response, None);
                    return LookupResult { status: Some(Status::Ready), response: Some(response), dispatch_needed: false };
                }

                if now.duration_since(entry.last_dispatch_at).unwrap_or_default() >= self.pending_timeout {
                    shard.items[last].last_dispatch_at = now;
                    self.dirty.fetch_add(1, Ordering::Relaxed);
                    return LookupResult { status: Some(Status::Pending), response: None, dispatch_needed: true };
                }
                return LookupResult { status: Some(Status::Pending), response: None, dispatch_needed: false };
            }

            self.remove_index_locked(&mut shard, idx);
        }

        let entry = Entry {
            domain: domain.to_string(),
            question_type: q_type,
            question_class: q_class,
            status: Status::Pending,
            created_at: now,
            last_used_at: now,
            last_dispatch_at: now,
            response: Vec::new(),
        };
        shard.items.insert(key.to_vec(), entry);
        self.pending_total.fetch_add(1, Ordering::Relaxed);
        self.dirty.fetch_add(1, Ordering::Relaxed);
        self.evict_if_needed_locked(&mut shard);

        LookupResult { status: Some(Status::Pending), response: None, dispatch_needed: true }
    }

    pub fn get_ready(&self, key: &[u8], raw_query: Option<&[u8]>, now: SystemTime) -> Option<Vec<u8>> {
        if key.is_empty() {
            return None;
        }
        let shard_idx = shard_index(key);
        let mut shard = self.shards[shard_idx].write().unwrap();

        let idx = shard.items.get_index_of(key)?;
        if self.is_expired(&shard.items[idx], now) {
            self.remove_index_locked(&mut shard, idx);
            return None;
        }

        if shard.items[idx].status != Status::Ready || shard.items[idx].response.is_empty() {
            self.touch_entry_at(&mut shard, idx, now);
            let last = shard.items.len() - 1;
            shard.items.move_index(idx, last);
            return None;
        }

        self.touch_entry_at(&mut shard, idx, now);
        let last = shard.items.len() - 1;
        shard.items.move_index(idx, last);
        Some(patch_response_for_query(&shard.items[last].response, raw_query))
    }

    pub fn set_ready(&self, key: &[u8], domain: &str, q_type: u16, q_class: u16, raw_response: &[u8], now: SystemTime) {
        if key.is_empty() || raw_response.len() < 2 {
            return;
        }

        let shard_idx = shard_index(key);
        let mut shard = self.shards[shard_idx].write().unwrap();

        let mut normalized = raw_response.to_vec();
        normalized[0] = 0;
        normalized[1] = 0;

        if let Some(idx) = shard.items.get_index_of(key) {
            if shard.items[idx].status == Status::Pending {
                self.decrement_pending();
            }
            let entry = &mut shard.items[idx];
            entry.domain = domain.to_string();
            entry.question_type = q_type;
            entry.question_class = q_class;
            entry.status = Status::Ready;
            if entry.created_at == UNIX_EPOCH {
                entry.created_at = now;
            }
            entry.last_used_at = now;
            entry.response = normalized;
            self.dirty.fetch_add(1, Ordering::Relaxed);
            let last = shard.items.len() - 1;
            shard.items.move_index(idx, last);
            return;
        }

        let entry = Entry {
            domain: domain.to_string(),
            question_type: q_type,
            question_class: q_class,
            status: Status::Ready,
            created_at: now,
            last_used_at: now,
            last_dispatch_at: UNIX_EPOCH,
            response: normalized,
        };
        shard.items.insert(key.to_vec(), entry);
        self.dirty.fetch_add(1, Ordering::Relaxed);
        self.evict_if_needed_locked(&mut shard);
    }

    pub fn has_pending(&self) -> bool {
        self.pending_total.load(Ordering::Relaxed) > 0
    }

    pub fn clear_pending(&self) {
        for shard_lock in &self.shards {
            let mut shard = shard_lock.write().unwrap();
            let pending_keys: Vec<Vec<u8>> = shard
                .items
                .iter()
                .filter(|(_, e): &(&Vec<u8>, &Entry)| e.status == Status::Pending)
                .map(|(k, _)| k.clone())
                .collect();
            for key in pending_keys {
                if let Some(idx) = shard.items.get_index_of(&key) {
                    self.remove_index_locked(&mut shard, idx);
                }
            }
        }
    }

    fn is_expired(&self, entry: &Entry, now: SystemTime) -> bool {
        if entry.status == Status::Pending {
            return false;
        }
        now.duration_since(entry.last_used_at).unwrap_or_default() >= self.cache_ttl
    }

    fn evict_if_needed_locked(&self, shard: &mut Shard) {
        let limit = (self.max_records / SHARD_COUNT).max(1);
        while shard.items.len() > limit {
            if shard.items.is_empty() {
                return;
            }
            self.remove_index_locked(shard, 0);
        }
    }

    fn remove_index_locked(&self, shard: &mut Shard, idx: usize) {
        if let Some((_, entry)) = shard.items.shift_remove_index(idx) {
            if entry.status == Status::Pending {
                self.decrement_pending();
            }
            self.dirty.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn decrement_pending(&self) {
        let _ = self.pending_total.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| if v > 0 { Some(v - 1) } else { None });
    }

    fn touch_entry_at(&self, shard: &mut Shard, idx: usize, now: SystemTime) {
        let entry = &mut shard.items[idx];
        let stale = entry.last_used_at == UNIX_EPOCH || now.duration_since(entry.last_used_at).unwrap_or_default() >= Duration::from_secs(1);
        entry.last_used_at = now;
        if stale {
            self.dirty.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn load_from_file(&self, path: &Path, now: SystemTime) -> std::io::Result<usize> {
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };

        let magic = read_u32(&mut file)?;
        if magic != BINARY_MAGIC {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid magic number"));
        }
        let version = read_u16(&mut file)?;
        if version != BINARY_VERSION {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported version"));
        }
        let count = read_u32(&mut file)?;

        self.pending_total.store(0, Ordering::Relaxed);
        for shard_lock in &self.shards {
            shard_lock.write().unwrap().items.clear();
        }

        let mut reader = std::io::BufReader::new(file);
        let mut loaded = 0usize;
        for _ in 0..count {
            let (key, entry) = match read_binary_entry(&mut reader) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            };

            if self.is_expired(&entry, now) {
                continue;
            }

            let shard_idx = shard_index(&key);
            self.shards[shard_idx].write().unwrap().items.insert(key, entry);
            loaded += 1;
        }

        for shard_lock in &self.shards {
            self.evict_if_needed_locked(&mut shard_lock.write().unwrap());
        }

        self.dirty.store(0, Ordering::Relaxed);
        Ok(loaded)
    }

    pub fn save_to_file(&self, path: &Path, now: SystemTime) -> std::io::Result<usize> {
        if self.dirty.load(Ordering::Relaxed) == 0 {
            return Ok(0);
        }

        let temp_path = path.with_extension("tmp");
        let file = std::fs::File::create(&temp_path)?;
        let mut writer = BufWriter::new(file);

        let mut entries: Vec<(&Vec<u8>, &Entry)> = Vec::new();
        let guards: Vec<_> = self.shards.iter().map(|s| s.read().unwrap()).collect();
        for shard in &guards {
            for (k, e) in shard.items.iter() {
                if e.status == Status::Ready && !self.is_expired(e, now) {
                    entries.push((k, e));
                }
            }
        }

        let result = (|| -> std::io::Result<usize> {
            write_u32(&mut writer, BINARY_MAGIC)?;
            write_u16(&mut writer, BINARY_VERSION)?;
            write_u32(&mut writer, entries.len() as u32)?;

            for (key, entry) in &entries {
                write_binary_entry(&mut writer, key, entry)?;
            }
            writer.flush()?;
            Ok(entries.len())
        })();

        drop(guards);

        let saved = match result {
            Ok(n) => n,
            Err(e) => {
                let _ = std::fs::remove_file(&temp_path);
                return Err(e);
            }
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&temp_path, path)?;
        self.dirty.store(0, Ordering::Relaxed);
        Ok(saved)
    }
}

fn read_u16<R: Read>(r: &mut R) -> std::io::Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}
fn read_u32<R: Read>(r: &mut R) -> std::io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}
fn read_i64<R: Read>(r: &mut R) -> std::io::Result<i64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(i64::from_be_bytes(buf))
}
fn read_bytes<R: Read>(r: &mut R, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}
fn write_u16<W: Write>(w: &mut W, v: u16) -> std::io::Result<()> {
    w.write_all(&v.to_be_bytes())
}
fn write_u32<W: Write>(w: &mut W, v: u32) -> std::io::Result<()> {
    w.write_all(&v.to_be_bytes())
}
fn write_i64<W: Write>(w: &mut W, v: i64) -> std::io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

fn unix_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}
fn from_unix_secs(secs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs((-secs) as u64)
    }
}

fn read_binary_entry<R: Read>(r: &mut R) -> std::io::Result<(Vec<u8>, Entry)> {
    let key_len = read_u16(r)? as usize;
    let key = read_bytes(r, key_len)?;

    let domain_len = read_u16(r)? as usize;
    let domain_buf = read_bytes(r, domain_len)?;

    let q_type = read_u16(r)?;
    let q_class = read_u16(r)?;

    let res_len = read_u16(r)? as usize;
    let response = read_bytes(r, res_len)?;

    let created_at = read_i64(r)?;
    let last_used_at = read_i64(r)?;

    Ok((
        key,
        Entry {
            domain: String::from_utf8_lossy(&domain_buf).into_owned(),
            question_type: q_type,
            question_class: q_class,
            status: Status::Ready,
            created_at: from_unix_secs(created_at),
            last_used_at: from_unix_secs(last_used_at),
            last_dispatch_at: UNIX_EPOCH,
            response,
        },
    ))
}

fn write_binary_entry<W: Write>(w: &mut W, key: &[u8], entry: &Entry) -> std::io::Result<()> {
    write_u16(w, key.len() as u16)?;
    w.write_all(key)?;

    write_u16(w, entry.domain.len() as u16)?;
    w.write_all(entry.domain.as_bytes())?;

    write_u16(w, entry.question_type)?;
    write_u16(w, entry.question_class)?;

    write_u16(w, entry.response.len() as u16)?;
    w.write_all(&entry.response)?;

    write_i64(w, unix_secs(entry.created_at))?;
    write_i64(w, unix_secs(entry.last_used_at))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_lookup_creates_pending_and_needs_dispatch() {
        let store = Store::new(100, Duration::from_secs(60), Duration::from_secs(5));
        let key = build_key("example.com", 1, 1);
        let now = SystemTime::now();
        let result = store.lookup_or_create_pending(&key, "example.com", 1, 1, now);
        assert_eq!(result.status, Some(Status::Pending));
        assert!(result.dispatch_needed);
        assert!(store.has_pending());
    }

    #[test]
    fn second_lookup_before_pending_timeout_does_not_redispatch() {
        let store = Store::new(100, Duration::from_secs(60), Duration::from_secs(30));
        let key = build_key("example.com", 1, 1);
        let now = SystemTime::now();
        store.lookup_or_create_pending(&key, "example.com", 1, 1, now);
        let second = store.lookup_or_create_pending(&key, "example.com", 1, 1, now);
        assert_eq!(second.status, Some(Status::Pending));
        assert!(!second.dispatch_needed);
    }

    #[test]
    fn set_ready_then_lookup_returns_response() {
        let store = Store::new(100, Duration::from_secs(60), Duration::from_secs(5));
        let key = build_key("example.com", 1, 1);
        let now = SystemTime::now();
        store.lookup_or_create_pending(&key, "example.com", 1, 1, now);
        let response = vec![0xAB, 0xCD, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        store.set_ready(&key, "example.com", 1, 1, &response, now);
        assert!(!store.has_pending());

        let result = store.lookup_or_create_pending(&key, "example.com", 1, 1, now);
        assert_eq!(result.status, Some(Status::Ready));
        assert!(result.response.is_some());
    }

    #[test]
    fn get_ready_patches_transaction_id() {
        let store = Store::new(100, Duration::from_secs(60), Duration::from_secs(5));
        let key = build_key("example.com", 1, 1);
        let now = SystemTime::now();
        let response = vec![0x00, 0x00, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        store.set_ready(&key, "example.com", 1, 1, &response, now);

        let query = vec![0x12, 0x34, 0x01, 0x00];
        let patched = store.get_ready(&key, Some(&query), now).unwrap();
        assert_eq!(&patched[0..2], &[0x12, 0x34]);
    }

    #[test]
    fn expired_ready_entry_is_evicted_on_access() {
        let store = Store::new(100, Duration::from_millis(10), Duration::from_secs(5));
        let key = build_key("example.com", 1, 1);
        let now = SystemTime::now();
        let response = vec![0x00, 0x00, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        store.set_ready(&key, "example.com", 1, 1, &response, now);

        let later = now + Duration::from_millis(50);
        assert!(store.get_ready(&key, None, later).is_none());
    }

    #[test]
    fn clear_pending_removes_only_pending_entries() {
        let store = Store::new(100, Duration::from_secs(60), Duration::from_secs(5));
        let now = SystemTime::now();
        let pending_key = build_key("pending.com", 1, 1);
        let ready_key = build_key("ready.com", 1, 1);
        store.lookup_or_create_pending(&pending_key, "pending.com", 1, 1, now);
        store.set_ready(&ready_key, "ready.com", 1, 1, &[0, 0, 0x81, 0x80], now);

        store.clear_pending();
        assert!(!store.has_pending());
        assert!(store.get_ready(&ready_key, None, now).is_some());
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("dnscache-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.bin");
        let _ = std::fs::remove_file(&path);

        let store = Store::new(100, Duration::from_secs(3600), Duration::from_secs(5));
        let now = SystemTime::now();
        let key = build_key("example.com", 1, 1);
        let response = vec![0x00, 0x00, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        store.set_ready(&key, "example.com", 1, 1, &response, now);

        let saved = store.save_to_file(&path, now).unwrap();
        assert_eq!(saved, 1);

        let store2 = Store::new(100, Duration::from_secs(3600), Duration::from_secs(5));
        let loaded = store2.load_from_file(&path, now).unwrap();
        assert_eq!(loaded, 1);
        assert!(store2.get_ready(&key, None, now).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
