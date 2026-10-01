//! Port of `internal/mlq`: a thread-safe, 6-level priority queue with O(1)
//! existence checks and keyed removal.
//!
//! Go backs each level with `container/list` plus a `map[key]*list.Element`.
//! Here one hash map holds the live items by key, and each level keeps its
//! FIFO order as a `VecDeque` of `(key, seq)` entries. Removing by key only
//! drops the map entry; the level's stale entry is skipped when it reaches the
//! front and compacted away once stale entries outnumber live ones. `seq`
//! tells a re-pushed key apart from its own stale entry. Push, pop and
//! removal are amortized O(1); the previous IndexMap version shifted the
//! whole level on every pop. Behaviour is unchanged, which the randomized
//! test below checks against that previous implementation.

use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::RwLock;

#[cfg(test)]
mod reference;

const LEVELS: usize = 6;

/// A level is compacted when it holds more than this many stale entries on
/// top of twice its live count.
const COMPACT_SLACK: usize = 32;

struct Entry<T> {
    level: u8,
    seq: u64,
    item: T,
}

struct Inner<T> {
    items: FxHashMap<u64, Entry<T>>,
    order: [VecDeque<(u64, u64)>; LEVELS],
    live: [usize; LEVELS],
    bitmask: u16,
    next_seq: u64,
}

impl<T> Inner<T> {
    fn is_live(&self, key: u64, seq: u64) -> bool {
        self.items.get(&key).is_some_and(|e| e.seq == seq)
    }

    /// Drops stale entries at the front of `level` and returns the first live key.
    fn front_live(&mut self, level: usize) -> Option<u64> {
        while let Some(&(key, seq)) = self.order[level].front() {
            if self.is_live(key, seq) {
                return Some(key);
            }
            self.order[level].pop_front();
        }
        None
    }

    fn take(&mut self, key: u64) -> Option<(T, usize)> {
        let entry = self.items.remove(&key)?;
        let level = entry.level as usize;
        self.live[level] -= 1;
        if self.live[level] == 0 {
            self.bitmask &= !(1 << level);
            self.order[level].clear();
        } else if self.order[level].len() > 2 * self.live[level] + COMPACT_SLACK {
            let items = &self.items;
            self.order[level].retain(|&(k, s)| items.get(&k).is_some_and(|e| e.seq == s));
        }
        Some((entry.item, level))
    }

    /// First live entry of `level` (front to back) whose item matches.
    fn find_live(&self, level: usize, predicate: &impl Fn(&T) -> bool) -> Option<u64> {
        self.order[level].iter().find_map(|&(key, seq)| match self.items.get(&key) {
            Some(e) if e.seq == seq && predicate(&e.item) => Some(key),
            _ => None,
        })
    }
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
                items: FxHashMap::with_capacity_and_hasher(initial_capacity, Default::default()),
                order: std::array::from_fn(|_| VecDeque::with_capacity(cap_per_level)),
                live: [0; LEVELS],
                bitmask: 0,
                next_seq: 0,
            }),
            fast_size: AtomicI32::new(0),
        }
    }

    pub fn push(&self, priority: i32, key: u64, item: T) -> bool {
        let mut inner = self.inner.write().unwrap();
        if inner.items.contains_key(&key) {
            return false;
        }
        let level = normalize_priority(priority);
        let seq = inner.next_seq;
        inner.next_seq += 1;
        inner.items.insert(key, Entry { level: level as u8, seq, item });
        inner.order[level].push_back((key, seq));
        inner.live[level] += 1;
        inner.bitmask |= 1 << level;
        self.fast_size.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn pop(&self) -> Option<(T, i32)> {
        let mut inner = self.inner.write().unwrap();
        while inner.bitmask != 0 {
            let level = inner.bitmask.trailing_zeros() as usize;
            if let Some(key) = inner.front_live(level) {
                let (item, level) = inner.take(key).expect("front entry is live");
                self.fast_size.fetch_sub(1, Ordering::Relaxed);
                return Some((item, level as i32));
            }
            inner.bitmask &= !(1 << level);
        }
        None
    }

    /// Prefer an eligible item only when the highest-priority front can be
    /// bypassed. Selection and removal share one lock: essential control at
    /// the front cannot be displaced by a concurrent fairness decision.
    pub fn pop_prefer_if(&self, priorities: &[i32], preferred: impl Fn(&T) -> bool, may_bypass: impl Fn(&T) -> bool) -> Option<(T, i32)> {
        let mut inner = self.inner.write().unwrap();
        if inner.bitmask == 0 {
            return None;
        }
        let level = inner.bitmask.trailing_zeros() as usize;
        let front = inner.front_live(level)?;
        let key = if may_bypass(&inner.items[&front].item) {
            priorities.iter().filter(|&&p| (0..LEVELS as i32).contains(&p))
                .find_map(|&p| inner.find_live(p as usize, &preferred)).unwrap_or(front)
        } else {
            front
        };
        let (item, level) = inner.take(key)?;
        self.fast_size.fetch_sub(1, Ordering::Relaxed);
        Some((item, level as i32))
    }

    pub fn peek_cloned(&self) -> Option<(T, i32)>
    where
        T: Clone,
    {
        let inner = self.inner.read().unwrap();
        let mut mask = inner.bitmask;
        while mask != 0 {
            let level = mask.trailing_zeros() as usize;
            if let Some(key) = inner.find_live(level, &|_| true) {
                return Some((inner.items[&key].item.clone(), level as i32));
            }
            mask &= !(1 << level);
        }
        None
    }

    pub fn get(&self, key: u64) -> Option<T>
    where
        T: Clone,
    {
        self.inner.read().unwrap().items.get(&key).map(|e| e.item.clone())
    }

    pub fn contains_key(&self, key: u64) -> bool {
        self.inner.read().unwrap().items.contains_key(&key)
    }

    pub fn remove_by_key(&self, key: u64) -> Option<T> {
        let (item, _) = self.inner.write().unwrap().take(key)?;
        self.fast_size.fetch_sub(1, Ordering::Relaxed);
        Some(item)
    }

    pub fn count(&self, priority: i32) -> usize {
        if !(0..LEVELS as i32).contains(&priority) {
            return 0;
        }
        self.inner.read().unwrap().live[priority as usize]
    }

    pub fn size(&self) -> usize {
        self.inner.read().unwrap().items.len()
    }

    pub fn fast_size(&self) -> i32 {
        self.fast_size.load(Ordering::Relaxed)
    }

    /// Removes every item, passing each to `callback` level by level in FIFO order.
    pub fn clear(&self, mut callback: impl FnMut(T)) {
        let mut inner = self.inner.write().unwrap();
        let inner = &mut *inner;
        for level in 0..LEVELS {
            for (key, seq) in inner.order[level].drain(..) {
                if inner.items.get(&key).is_some_and(|e| e.seq == seq) {
                    callback(inner.items.remove(&key).expect("live entry").item);
                }
            }
            inner.live[level] = 0;
        }
        inner.items.clear();
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
        let level = priority as usize;
        if inner.bitmask & (1 << level) == 0 {
            return None;
        }
        let Some(key) = inner.front_live(level) else {
            inner.bitmask &= !(1 << level);
            return None;
        };
        if !predicate(&inner.items[&key].item) {
            return None;
        }
        let (item, _) = inner.take(key)?;
        self.fast_size.fetch_sub(1, Ordering::Relaxed);
        Some(item)
    }

    /// Scans levels `0..=max_priority` front-to-back for the first item
    /// matching `predicate` and pops it.
    pub fn pop_any_if(&self, max_priority: i32, predicate: impl Fn(&T) -> bool, _key_extractor: impl Fn(&T) -> u64) -> Option<T> {
        let mut inner = self.inner.write().unwrap();
        let mut mask = inner.bitmask;
        while mask != 0 {
            let level = mask.trailing_zeros() as usize;
            if level as i32 > max_priority {
                break;
            }
            if let Some(key) = inner.find_live(level, &predicate) {
                let (item, _) = inner.take(key)?;
                self.fast_size.fetch_sub(1, Ordering::Relaxed);
                return Some(item);
            }
            mask &= !(1 << level);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop_priority_order() {
        let q: MultiLevelQueue<&str> = MultiLevelQueue::new(8);
        assert!(q.push(3, 1, "normal"));
        assert!(q.push(0, 2, "critical"));
        assert!(q.push(1, 3, "retry"));

        let (item, priority) = q.pop().unwrap();
        assert_eq!((item, priority), ("critical", 0));
        let (item, priority) = q.pop().unwrap();
        assert_eq!((item, priority), ("retry", 1));
        let (item, priority) = q.pop().unwrap();
        assert_eq!((item, priority), ("normal", 3));
        assert!(q.pop().is_none());
    }

    #[test]
    fn fifo_within_same_priority() {
        let q: MultiLevelQueue<u32> = MultiLevelQueue::new(8);
        q.push(2, 1, 100);
        q.push(2, 2, 200);
        q.push(2, 3, 300);
        assert_eq!(q.pop().unwrap().0, 100);
        assert_eq!(q.pop().unwrap().0, 200);
        assert_eq!(q.pop().unwrap().0, 300);
    }

    #[test]
    fn duplicate_key_rejected() {
        let q: MultiLevelQueue<u32> = MultiLevelQueue::new(8);
        assert!(q.push(2, 1, 100));
        assert!(!q.push(3, 1, 200));
        assert_eq!(q.get(1), Some(100));
    }

    #[test]
    fn remove_by_key_updates_bitmask_and_size() {
        let q: MultiLevelQueue<u32> = MultiLevelQueue::new(8);
        q.push(4, 1, 100);
        assert_eq!(q.fast_size(), 1);
        assert_eq!(q.remove_by_key(1), Some(100));
        assert_eq!(q.fast_size(), 0);
        assert_eq!(q.highest_priority(), -1);
        assert_eq!(q.remove_by_key(1), None);
    }

    #[test]
    fn pop_any_if_scans_levels_in_priority_order() {
        let q: MultiLevelQueue<u32> = MultiLevelQueue::new(8);
        q.push(0, 1, 1);
        q.push(0, 2, 2);
        q.push(1, 3, 3);
        // Only key 3 (priority 1) matches; scan should skip past priority-0
        // items that don't match and find it.
        let got = q.pop_any_if(2, |&v| v == 3, |_| 0);
        assert_eq!(got, Some(3));
        assert_eq!(q.size(), 2);
    }

    #[test]
    fn clear_invokes_callback_for_every_item() {
        let q: MultiLevelQueue<u32> = MultiLevelQueue::new(8);
        q.push(0, 1, 10);
        q.push(1, 2, 20);
        let mut seen = Vec::new();
        q.clear(|v| seen.push(v));
        seen.sort();
        assert_eq!(seen, vec![10, 20]);
        assert_eq!(q.size(), 0);
        assert_eq!(q.fast_size(), 0);
    }

    #[test]
    fn out_of_range_priority_normalizes_to_three() {
        let q: MultiLevelQueue<u32> = MultiLevelQueue::new(8);
        q.push(99, 1, 100);
        assert_eq!(q.count(3), 1);
    }

    /// Runs the same random operation sequence against this implementation
    /// and the previous IndexMap-backed one and requires identical results.
    #[test]
    fn behaves_exactly_like_previous_implementation() {
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut next = |bound: u64| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) % bound
        };
        for round in 0..40 {
            let new_q: MultiLevelQueue<u32> = MultiLevelQueue::new(8);
            let old_q: reference::MultiLevelQueue<u32> = reference::MultiLevelQueue::new(8);
            let key_space = [8, 64, 512][round % 3];
            for step in 0..5000u32 {
                let op = next(100);
                let ctx = format!("round {round} step {step} op {op}");
                match op {
                    0..=39 => {
                        let (p, k) = (next(8) as i32 - 1, next(key_space));
                        assert_eq!(new_q.push(p, k, step), old_q.push(p, k, step), "{ctx} push");
                    }
                    40..=54 => assert_eq!(new_q.pop(), old_q.pop(), "{ctx} pop"),
                    55..=64 => {
                        let k = next(key_space);
                        assert_eq!(new_q.remove_by_key(k), old_q.remove_by_key(k), "{ctx} remove");
                    }
                    65..=72 => {
                        let (max, m) = (next(7) as i32 - 1, next(4) as u32 + 1);
                        let pred = move |v: &u32| v % m == 0;
                        assert_eq!(new_q.pop_any_if(max, pred, |_| 0), old_q.pop_any_if(max, pred, |_| 0), "{ctx} pop_any_if");
                    }
                    73..=78 => {
                        let (p, m) = (next(8) as i32 - 1, next(3) as u32 + 1);
                        let pred = move |v: &u32| v % m == 0;
                        assert_eq!(new_q.pop_if(p, pred, |_| 0), old_q.pop_if(p, pred, |_| 0), "{ctx} pop_if");
                    }
                    79..=86 => {
                        let k = next(key_space);
                        assert_eq!(new_q.get(k), old_q.get(k), "{ctx} get");
                        assert_eq!(new_q.contains_key(k), old_q.contains_key(k), "{ctx} contains");
                    }
                    87..=93 => assert_eq!(new_q.peek_cloned(), old_q.peek_cloned(), "{ctx} peek"),
                    94..=98 => {
                        for p in -1..7 {
                            assert_eq!(new_q.count(p), old_q.count(p), "{ctx} count({p})");
                        }
                        assert_eq!(new_q.highest_priority(), old_q.highest_priority(), "{ctx} highest");
                    }
                    _ => {
                        let (mut a, mut b) = (Vec::new(), Vec::new());
                        new_q.clear(|v| a.push(v));
                        old_q.clear(|v| b.push(v));
                        assert_eq!(a, b, "{ctx} clear order");
                    }
                }
                assert_eq!(new_q.size(), old_q.size(), "{ctx} size");
                assert_eq!(new_q.fast_size(), old_q.fast_size(), "{ctx} fast_size");
            }
        }
    }

    /// Removing items by key without ever popping them must not grow the
    /// level's order list without bound.
    #[test]
    fn stale_entries_are_compacted() {
        let q: MultiLevelQueue<u32> = MultiLevelQueue::new(8);
        q.push(2, u64::MAX, 0); // stays at the front the whole time
        for k in 0..100_000u64 {
            q.push(2, k, 1);
            q.remove_by_key(k);
        }
        {
            let inner = q.inner.read().unwrap();
            assert!(inner.order[2].len() <= 2 * inner.live[2] + COMPACT_SLACK + 1, "order len {}", inner.order[2].len());
        }
        assert_eq!(q.pop(), Some((0, 2)));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn fairness_selection_is_atomic_and_preserves_essential_front() {
        let q = MultiLevelQueue::new(8);
        assert!(q.push(0, 1, "reset"));
        assert!(q.push(0, 2, "ack"));
        assert!(q.push(3, 3, "data"));
        let preferred = |v: &&str| *v == "data";
        let bypassable = |v: &&str| *v == "ack";
        assert_eq!(q.pop_prefer_if(&[3], preferred, bypassable), Some(("reset", 0)));
        assert_eq!(q.pop_prefer_if(&[3], preferred, bypassable), Some(("data", 3)));
        assert_eq!(q.fast_size(), 1);
        assert_eq!(q.pop(), Some(("ack", 0)));
        assert_eq!(q.pop_prefer_if(&[-1, 6], preferred, bypassable), None);
    }

}
