//! Port of `internal/fragmentstore`: a generic keyed reassembly buffer for
//! fragmented packets, with a completed-key dedup cache and lazy time-based purge.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    created_at: Instant,
    total_fragments: u8,
    chunks: Vec<Option<Vec<u8>>>,
    count: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectOutcome {
    /// All fragments received; carries the reassembled payload.
    Complete(Vec<u8>),
    /// Accepted this fragment, but the set isn't complete yet.
    Buffered,
    /// This key already completed within the retention window (duplicate/replay).
    AlreadyCompleted,
    /// `fragment_id >= total_fragments` — malformed input, rejected.
    Rejected,
}

struct Inner<K> {
    items: HashMap<K, Entry>,
    completed: HashMap<K, Instant>,
    last_purge: Option<Instant>,
}

pub struct Store<K> {
    inner: Mutex<Inner<K>>,
}

impl<K: Eq + Hash + Clone> Store<K> {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(16);
        Store {
            inner: Mutex::new(Inner {
                items: HashMap::with_capacity(capacity),
                completed: HashMap::with_capacity(capacity),
                last_purge: None,
            }),
        }
    }

    pub fn collect(
        &self,
        key: K,
        payload: &[u8],
        fragment_id: u8,
        total_fragments: u8,
        now: Instant,
        retention: Duration,
    ) -> CollectOutcome {
        if total_fragments <= 1 {
            if retention.is_zero() {
                return CollectOutcome::Complete(payload.to_vec());
            }

            let mut inner = self.inner.lock().unwrap();
            self.maybe_purge_locked(&mut inner, now, retention);

            if let Some(&expires_at) = inner.completed.get(&key) {
                if now < expires_at {
                    return CollectOutcome::AlreadyCompleted;
                }
            }

            inner.items.remove(&key);
            inner.completed.insert(key, now + retention);
            return CollectOutcome::Complete(payload.to_vec());
        }

        if fragment_id >= total_fragments {
            return CollectOutcome::Rejected;
        }

        let mut inner = self.inner.lock().unwrap();
        self.maybe_purge_locked(&mut inner, now, retention);

        if let Some(&expires_at) = inner.completed.get(&key) {
            if now < expires_at {
                return CollectOutcome::AlreadyCompleted;
            }
        }

        let needs_reset = !inner
            .items
            .get(&key)
            .map(|e| e.total_fragments == total_fragments)
            .unwrap_or(false);
        if needs_reset {
            inner.items.insert(
                key.clone(),
                Entry { created_at: now, total_fragments, chunks: vec![None; total_fragments as usize], count: 0 },
            );
        }

        let current = inner.items.get_mut(&key).unwrap();
        let idx = fragment_id as usize;
        if current.chunks[idx].is_none() {
            current.count += 1;
        }
        current.chunks[idx] = Some(payload.to_vec());

        if current.count < total_fragments {
            return CollectOutcome::Buffered;
        }

        let mut total_size = 0usize;
        for chunk in &current.chunks {
            match chunk {
                Some(c) => total_size += c.len(),
                None => return CollectOutcome::Buffered,
            }
        }

        let mut assembled = Vec::with_capacity(total_size);
        for chunk in &current.chunks {
            assembled.extend_from_slice(chunk.as_ref().unwrap());
        }

        inner.items.remove(&key);
        if !retention.is_zero() {
            inner.completed.insert(key, now + retention);
        } else {
            inner.completed.remove(&key);
        }

        CollectOutcome::Complete(assembled)
    }

    pub fn purge(&self, now: Instant, retention: Duration) {
        let mut inner = self.inner.lock().unwrap();
        self.purge_locked(&mut inner, now, retention);
    }

    pub fn remove(&self, key: &K) {
        let mut inner = self.inner.lock().unwrap();
        inner.items.remove(key);
        inner.completed.remove(key);
    }

    pub fn remove_if(&self, mut matches: impl FnMut(&K) -> bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.items.retain(|k, _| !matches(k));
        inner.completed.retain(|k, _| !matches(k));
    }

    fn maybe_purge_locked(&self, inner: &mut Inner<K>, now: Instant, retention: Duration) {
        let should_purge = match inner.last_purge {
            None => true,
            Some(last) => now.duration_since(last) >= Duration::from_secs(1),
        };
        if should_purge {
            self.purge_locked(inner, now, retention);
            inner.last_purge = Some(now);
        }
    }

    fn purge_locked(&self, inner: &mut Inner<K>, now: Instant, retention: Duration) {
        if retention.is_zero() {
            inner.items.clear();
            inner.completed.clear();
            return;
        }

        let deadline = now.checked_sub(retention).unwrap_or(now);
        inner.items.retain(|_, entry| entry.created_at > deadline);
        inner.completed.retain(|_, &mut expires_at| now < expires_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_fragment_fast_path() {
        let store: Store<u32> = Store::new(8);
        let now = Instant::now();
        let outcome = store.collect(1, b"hello", 0, 1, now, Duration::from_secs(5));
        assert_eq!(outcome, CollectOutcome::Complete(b"hello".to_vec()));
    }

    #[test]
    fn multi_fragment_reassembly_in_order() {
        let store: Store<u32> = Store::new(8);
        let now = Instant::now();
        assert_eq!(store.collect(1, b"AAA", 0, 3, now, Duration::from_secs(5)), CollectOutcome::Buffered);
        assert_eq!(store.collect(1, b"BBB", 1, 3, now, Duration::from_secs(5)), CollectOutcome::Buffered);
        assert_eq!(
            store.collect(1, b"CCC", 2, 3, now, Duration::from_secs(5)),
            CollectOutcome::Complete(b"AAABBBCCC".to_vec())
        );
    }

    #[test]
    fn multi_fragment_reassembly_out_of_order() {
        let store: Store<u32> = Store::new(8);
        let now = Instant::now();
        store.collect(1, b"CCC", 2, 3, now, Duration::from_secs(5));
        store.collect(1, b"AAA", 0, 3, now, Duration::from_secs(5));
        assert_eq!(
            store.collect(1, b"BBB", 1, 3, now, Duration::from_secs(5)),
            CollectOutcome::Complete(b"AAABBBCCC".to_vec())
        );
    }

    #[test]
    fn rejects_out_of_bounds_fragment_id() {
        let store: Store<u32> = Store::new(8);
        let now = Instant::now();
        assert_eq!(store.collect(1, b"x", 5, 3, now, Duration::from_secs(5)), CollectOutcome::Rejected);
    }

    #[test]
    fn duplicate_after_completion_is_flagged() {
        let store: Store<u32> = Store::new(8);
        let now = Instant::now();
        store.collect(1, b"AAA", 0, 2, now, Duration::from_secs(5));
        store.collect(1, b"BBB", 1, 2, now, Duration::from_secs(5));
        // Replaying the same key afterward should be recognized as already completed.
        assert_eq!(store.collect(1, b"AAA", 0, 2, now, Duration::from_secs(5)), CollectOutcome::AlreadyCompleted);
    }

    #[test]
    fn remove_clears_both_maps() {
        let store: Store<u32> = Store::new(8);
        let now = Instant::now();
        store.collect(1, b"AAA", 0, 3, now, Duration::from_secs(5));
        store.remove(&1);
        // After removal, resubmitting the first fragment starts fresh (Buffered, not lost forever).
        assert_eq!(store.collect(1, b"AAA", 0, 3, now, Duration::from_secs(5)), CollectOutcome::Buffered);
    }
}
