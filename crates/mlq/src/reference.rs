//! The previous IndexMap-backed implementation, kept only as the model the
//! randomized equivalence test in `lib.rs` compares against.
#![allow(dead_code)]

use indexmap::IndexMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::RwLock;

const LEVELS: usize = 6;

struct Inner<T> {
    queues: [IndexMap<u64, T, rustc_hash::FxBuildHasher>; LEVELS],
    bitmask: u16,
}

pub struct MultiLevelQueue<T> {
    inner: RwLock<Inner<T>>,
    fast_size: AtomicI32,
}

impl<T> MultiLevelQueue<T> {
    pub fn new(initial_capacity: usize) -> Self {
        let cap_per_level = (initial_capacity / LEVELS).max(1);
        MultiLevelQueue {
            inner: RwLock::new(Inner {
                queues: std::array::from_fn(|_| IndexMap::with_capacity_and_hasher(cap_per_level, rustc_hash::FxBuildHasher)),
                bitmask: 0,
            }),
            fast_size: AtomicI32::new(0),
        }
    }

    pub fn push(&self, priority: i32, key: u64, item: T) -> bool {
        let mut inner = self.inner.write().unwrap();
        let priority = normalize_priority(priority);

        for q in inner.queues.iter() {
            if q.contains_key(&key) {
                return false;
            }
        }

        inner.queues[priority].insert(key, item);
        inner.bitmask |= 1 << priority;
        self.fast_size.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn pop(&self) -> Option<(T, i32)> {
        let mut inner = self.inner.write().unwrap();
        self.pop_locked(&mut inner)
    }

    fn pop_locked(&self, inner: &mut Inner<T>) -> Option<(T, i32)> {
        while inner.bitmask != 0 {
            let priority = inner.bitmask.trailing_zeros() as usize;
            if let Some((_, item)) = inner.queues[priority].shift_remove_index(0) {
                self.fast_size.fetch_sub(1, Ordering::Relaxed);
                if inner.queues[priority].is_empty() {
                    inner.bitmask &= !(1 << priority);
                }
                return Some((item, priority as i32));
            }
            inner.bitmask &= !(1 << priority);
        }
        None
    }

    pub fn peek_cloned(&self) -> Option<(T, i32)>
    where
        T: Clone,
    {
        let inner = self.inner.read().unwrap();
        if inner.bitmask == 0 {
            return None;
        }
        let mut mask = inner.bitmask;
        while mask != 0 {
            let priority = mask.trailing_zeros() as usize;
            if let Some((_, item)) = inner.queues[priority].get_index(0) {
                return Some((item.clone(), priority as i32));
            }
            mask &= !(1 << priority);
        }
        None
    }

    pub fn get(&self, key: u64) -> Option<T>
    where
        T: Clone,
    {
        let inner = self.inner.read().unwrap();
        for q in inner.queues.iter() {
            if let Some(v) = q.get(&key) {
                return Some(v.clone());
            }
        }
        None
    }

    pub fn contains_key(&self, key: u64) -> bool {
        let inner = self.inner.read().unwrap();
        inner.queues.iter().any(|q| q.contains_key(&key))
    }

    pub fn remove_by_key(&self, key: u64) -> Option<T> {
        let mut inner = self.inner.write().unwrap();
        for priority in 0..LEVELS {
            if let Some(item) = inner.queues[priority].shift_remove(&key) {
                self.fast_size.fetch_sub(1, Ordering::Relaxed);
                if inner.queues[priority].is_empty() {
                    inner.bitmask &= !(1 << priority);
                }
                return Some(item);
            }
        }
        None
    }

    pub fn count(&self, priority: i32) -> usize {
        if !(0..LEVELS as i32).contains(&priority) {
            return 0;
        }
        self.inner.read().unwrap().queues[priority as usize].len()
    }

    pub fn size(&self) -> usize {
        self.inner.read().unwrap().queues.iter().map(|q| q.len()).sum()
    }

    pub fn fast_size(&self) -> i32 {
        self.fast_size.load(Ordering::Relaxed)
    }

    pub fn clear(&self, mut callback: impl FnMut(T)) {
        let mut inner = self.inner.write().unwrap();
        for q in inner.queues.iter_mut() {
            for (_, item) in q.drain(..) {
                callback(item);
            }
        }
        inner.bitmask = 0;
        self.fast_size.store(0, Ordering::Relaxed);
    }

    pub fn highest_priority(&self) -> i32 {
        let inner = self.inner.read().unwrap();
        if inner.bitmask == 0 {
            -1
        } else {
            inner.bitmask.trailing_zeros() as i32
        }
    }

    /// Pops the front of exactly `priority`'s level if it exists and
    /// `predicate` accepts it. `key_extractor` is accepted for Go API parity
    /// but unused (the original Go implementation never reads it either).
    pub fn pop_if(&self, priority: i32, predicate: impl Fn(&T) -> bool, _key_extractor: impl Fn(&T) -> u64) -> Option<T> {
        let mut inner = self.inner.write().unwrap();
        if inner.bitmask == 0 || !(0..LEVELS as i32).contains(&priority) {
            return None;
        }
        let priority = priority as usize;
        if inner.bitmask & (1 << priority) == 0 {
            return None;
        }

        let (key, matches) = match inner.queues[priority].get_index(0) {
            Some((k, v)) => (*k, predicate(v)),
            None => {
                inner.bitmask &= !(1 << priority);
                return None;
            }
        };
        if !matches {
            return None;
        }

        let item = inner.queues[priority].shift_remove(&key)?;
        self.fast_size.fetch_sub(1, Ordering::Relaxed);
        if inner.queues[priority].is_empty() {
            inner.bitmask &= !(1 << priority);
        }
        Some(item)
    }

    /// Scans levels `0..=max_priority` front-to-back for the first item
    /// matching `predicate` and pops it.
    pub fn pop_any_if(&self, max_priority: i32, predicate: impl Fn(&T) -> bool, _key_extractor: impl Fn(&T) -> u64) -> Option<T> {
        let mut inner = self.inner.write().unwrap();
        if inner.bitmask == 0 {
            return None;
        }

        let mut mask = inner.bitmask;
        while mask != 0 {
            let priority = mask.trailing_zeros() as usize;
            if priority as i32 > max_priority {
                break;
            }

            let found_key = inner.queues[priority].iter().find(|(_, v)| predicate(v)).map(|(k, _)| *k);

            if let Some(key) = found_key {
                let item = inner.queues[priority].shift_remove(&key)?;
                self.fast_size.fetch_sub(1, Ordering::Relaxed);
                if inner.queues[priority].is_empty() {
                    inner.bitmask &= !(1 << priority);
                }
                return Some(item);
            }

            mask &= !(1 << priority);
        }

        None
    }
}

fn normalize_priority(priority: i32) -> usize {
    if !(0..LEVELS as i32).contains(&priority) {
        3
    } else {
        priority as usize
    }
}
