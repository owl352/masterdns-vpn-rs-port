//! Port of `internal/udpserver/invalid_cookie_tracker.go`: a sliding-window,
//! bounded-attempt brute-force/spoofed-cookie detector.

use crate::session::{SessionLookupResult, SessionLookupState};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const UNKNOWN_EXPECTED_COOKIE_MARKER: u16 = 256;

#[derive(Hash, PartialEq, Eq)]
struct Key {
    session_id: u8,
    expected_cookie: u16,
    packet_cookie: u8,
    state: u8,
}

#[derive(Default)]
struct Record {
    attempts: Vec<Instant>,
    last_emit_at: Option<Instant>,
}

pub struct InvalidCookieTracker {
    records: Mutex<HashMap<Key, Record>>,
}

impl InvalidCookieTracker {
    pub fn new() -> Self {
        InvalidCookieTracker { records: Mutex::new(HashMap::new()) }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn note(
        &self,
        session_id: u8,
        lookup: SessionLookupResult,
        known: bool,
        packet_cookie: u8,
        now: Instant,
        window: Duration,
        threshold: usize,
    ) -> bool {
        if window.is_zero() || threshold == 0 {
            return false;
        }

        let expected = if known { lookup.cookie as u16 } else { UNKNOWN_EXPECTED_COOKIE_MARKER };
        let cutoff = now.checked_sub(window).unwrap_or(now);
        let key = Key { session_id, expected_cookie: expected, packet_cookie, state: lookup_state_code(lookup.state) };

        let mut records = self.records.lock().unwrap();
        let record = records.entry(key).or_default();
        record.attempts.retain(|&t| t >= cutoff);
        push_bounded(&mut record.attempts, now, threshold);

        if record.attempts.len() < threshold {
            return false;
        }
        if let Some(last) = record.last_emit_at {
            if now.duration_since(last) < window {
                return false;
            }
        }

        record.last_emit_at = Some(now);
        true
    }

    pub fn cleanup(&self, now: Instant, window: Duration) {
        if window.is_zero() {
            return;
        }
        let cutoff = now.checked_sub(window).unwrap_or(now);
        let mut records = self.records.lock().unwrap();
        records.retain(|_, record| {
            record.attempts.retain(|&t| t >= cutoff);
            !record.attempts.is_empty() || record.last_emit_at.map(|t| t >= cutoff).unwrap_or(false)
        });
    }
}

fn lookup_state_code(state: SessionLookupState) -> u8 {
    match state {
        SessionLookupState::Unknown => 0,
        SessionLookupState::Active => 1,
        SessionLookupState::Closed => 2,
    }
}

fn push_bounded(values: &mut Vec<Instant>, now: Instant, limit: usize) {
    if values.len() < limit {
        values.push(now);
        return;
    }
    if !values.is_empty() {
        values.remove(0);
    }
    values.push(now);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(cookie: u8) -> SessionLookupResult {
        SessionLookupResult { cookie, response_mode: 0, state: SessionLookupState::Active }
    }

    #[test]
    fn escalates_after_threshold_within_window() {
        let tracker = InvalidCookieTracker::new();
        let now = Instant::now();
        let window = Duration::from_secs(2);

        for i in 0..2 {
            let escalate = tracker.note(1, lookup(5), true, 9, now + Duration::from_millis(i * 10), window, 3);
            assert!(!escalate);
        }
        let escalate = tracker.note(1, lookup(5), true, 9, now + Duration::from_millis(20), window, 3);
        assert!(escalate);
    }

    #[test]
    fn does_not_re_escalate_within_window() {
        let tracker = InvalidCookieTracker::new();
        let now = Instant::now();
        let window = Duration::from_secs(2);
        for i in 0..3 {
            tracker.note(1, lookup(5), true, 9, now + Duration::from_millis(i * 10), window, 3);
        }
        let second = tracker.note(1, lookup(5), true, 9, now + Duration::from_millis(100), window, 3);
        assert!(!second);
    }

    #[test]
    fn old_attempts_outside_window_are_pruned() {
        let tracker = InvalidCookieTracker::new();
        let now = Instant::now();
        let window = Duration::from_millis(50);
        tracker.note(1, lookup(5), true, 9, now, window, 3);
        tracker.note(1, lookup(5), true, 9, now + Duration::from_millis(10), window, 3);
        // Far later: earlier attempts should have expired out of the window.
        let escalate = tracker.note(1, lookup(5), true, 9, now + Duration::from_millis(200), window, 3);
        assert!(!escalate);
    }
}
