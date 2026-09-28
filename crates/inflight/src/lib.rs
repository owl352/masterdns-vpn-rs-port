//! Port of `internal/inflight`: a single-flight coalescer. The first caller
//! for a key becomes the "leader" and does the work; concurrent callers for
//! the same key await the leader's result instead of duplicating it.
//!
//! Go's "close a channel once to broadcast" primitive becomes
//! `tokio::sync::Notify` here since this is consumed from async server code
//! (unlike the synchronous rest of this workspace's non-`arq`/non-`loops`
//! crates) — `Wait` is a real `async fn`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

enum EntryState<T> {
    Pending,
    /// `None` means "resolved, but the leader had no value to publish"
    /// (mirrors Go's `hasValue == false`), distinct from not-yet-resolved.
    Resolved(Option<T>),
}

pub struct Entry<T> {
    created_at: Instant,
    notify: Notify,
    state: Mutex<EntryState<T>>,
}

pub enum WaitOutcome<T> {
    Resolved(Option<T>),
    TimedOut,
}

struct ManagerInner<T> {
    next_cleanup_at: Option<Instant>,
    items: HashMap<String, Arc<Entry<T>>>,
}

pub struct Manager<T> {
    timeout: Duration,
    cleanup_window: Duration,
    inner: Mutex<ManagerInner<T>>,
}

impl<T: Clone> Manager<T> {
    pub fn new(timeout: Duration, fallback: Duration) -> Self {
        let timeout = if timeout.is_zero() { fallback } else { timeout };
        let cleanup_window = (timeout / 4).max(Duration::from_secs(1));
        Manager {
            timeout,
            cleanup_window,
            inner: Mutex::new(ManagerInner { next_cleanup_at: None, items: HashMap::new() }),
        }
    }

    /// Returns the entry for `key` and whether the caller is the leader
    /// (responsible for eventually calling [`Manager::resolve`]).
    pub fn acquire(&self, key: &str, now: Instant) -> (Arc<Entry<T>>, bool) {
        let mut inner = self.inner.lock().unwrap();

        let should_cleanup = inner.next_cleanup_at.map(|t| now >= t).unwrap_or(true);
        if should_cleanup {
            let timeout = self.timeout;
            inner.items.retain(|_, entry| now.duration_since(entry.created_at) < timeout);
            inner.next_cleanup_at = Some(now + self.cleanup_window);
        }

        if let Some(entry) = inner.items.get(key) {
            if now.duration_since(entry.created_at) < self.timeout {
                return (entry.clone(), false);
            }
        }

        let entry = Arc::new(Entry { created_at: now, notify: Notify::new(), state: Mutex::new(EntryState::Pending) });
        inner.items.insert(key.to_string(), entry.clone());
        (entry, true)
    }

    pub fn begin(&self, key: &str, now: Instant) -> bool {
        self.acquire(key, now).1
    }

    pub fn resolve(&self, key: &str, value: Option<T>) {
        let entry = {
            let mut inner = self.inner.lock().unwrap();
            inner.items.remove(key)
        };

        if let Some(entry) = entry {
            *entry.state.lock().unwrap() = EntryState::Resolved(value);
            entry.notify.notify_waiters();
        }
    }

    pub async fn wait(&self, entry: &Arc<Entry<T>>, timeout: Duration) -> WaitOutcome<T> {
        let timeout = if timeout.is_zero() { self.timeout } else { timeout };
        if timeout.is_zero() {
            return WaitOutcome::TimedOut;
        }

        // Subscribe *before* checking state: `Notify::notify_waiters()` only
        // wakes futures that already exist at the time it's called (no permit
        // buffering, unlike `notify_one()`). Creating `notified()` first and
        // checking afterward means a `resolve()` that races right after our
        // check is still delivered when we `.await` this same future below;
        // checking-then-subscribing would have a lost-wakeup window.
        let notified = entry.notify.notified();

        if let EntryState::Resolved(value) = &*entry.state.lock().unwrap() {
            return WaitOutcome::Resolved(value.clone());
        }

        if tokio::time::timeout(timeout, notified).await.is_err() {
            return WaitOutcome::TimedOut;
        }

        match &*entry.state.lock().unwrap() {
            EntryState::Resolved(value) => WaitOutcome::Resolved(value.clone()),
            EntryState::Pending => WaitOutcome::TimedOut,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn leader_resolves_and_waiter_gets_value() {
        let manager: Manager<String> = Manager::new(Duration::from_secs(5), Duration::from_secs(5));
        let now = Instant::now();

        let (leader_entry, is_leader) = manager.acquire("key", now);
        assert!(is_leader);

        let (waiter_entry, is_leader2) = manager.acquire("key", now);
        assert!(!is_leader2);

        manager.resolve("key", Some("result".to_string()));

        match manager.wait(&waiter_entry, Duration::from_secs(1)).await {
            WaitOutcome::Resolved(Some(v)) => assert_eq!(v, "result"),
            _ => panic!("expected resolved with value"),
        }
        match manager.wait(&leader_entry, Duration::from_secs(1)).await {
            WaitOutcome::Resolved(Some(v)) => assert_eq!(v, "result"),
            _ => panic!("expected resolved with value"),
        }
    }

    #[tokio::test]
    async fn resolve_without_value_is_distinct_from_timeout() {
        let manager: Manager<String> = Manager::new(Duration::from_secs(5), Duration::from_secs(5));
        let now = Instant::now();
        let (entry, _) = manager.acquire("key", now);
        manager.resolve("key", None);

        match manager.wait(&entry, Duration::from_secs(1)).await {
            WaitOutcome::Resolved(None) => {}
            _ => panic!("expected resolved with no value"),
        }
    }

    #[tokio::test]
    async fn wait_times_out_if_never_resolved() {
        let manager: Manager<String> = Manager::new(Duration::from_secs(5), Duration::from_secs(5));
        let now = Instant::now();
        let (entry, _) = manager.acquire("key", now);

        match manager.wait(&entry, Duration::from_millis(50)).await {
            WaitOutcome::TimedOut => {}
            _ => panic!("expected timeout"),
        }
    }

    #[test]
    fn expired_entry_gets_new_leader() {
        let manager: Manager<String> = Manager::new(Duration::from_millis(10), Duration::from_millis(10));
        let t0 = Instant::now();
        let (_, leader1) = manager.acquire("key", t0);
        assert!(leader1);

        let t1 = t0 + Duration::from_millis(50);
        let (_, leader2) = manager.acquire("key", t1);
        assert!(leader2, "a fresh leader should be elected once the prior entry ages out");
    }
}
