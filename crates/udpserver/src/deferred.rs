//! Rust re-design of `internal/udpserver/deferred_session.go` — the "deferred
//! session runtime" that runs slow work (outbound dials, upstream DNS
//! lookups) off the synchronous request/response path while still
//! guaranteeing strict per-`{session, stream}` lane ordering.
//!
//! Go pins each lane to one worker in a fixed-size goroutine pool (so a lane
//! always executes its tasks in arrival order on that worker, and a
//! FIFO-bounded channel provides backpressure) and threads a lane-scoped
//! `context.CancelFunc` through so `RemoveSession`/`RemoveLane` can abort
//! in-flight work immediately. This port keeps the two guarantees that
//! matter (strict per-lane FIFO ordering; active cancellation of in-flight
//! and queued work) but drops the worker-pool/bounded-channel plumbing,
//! which existed to bound OS-thread-backed goroutines — unnecessary with
//! tokio's much cheaper tasks: each lane gets its own `tokio::sync::Mutex`
//! (whose wait queue is itself FIFO) instead of a pinned worker+channel, and
//! `tokio_util::sync::CancellationToken` (session token → lane child tokens)
//! replaces the per-lane `CancelFunc` map. The one Go guarantee not kept is
//! bounded-worker-queue backpressure; the per-session pending cap (same
//! purpose: one session can't starve others) is kept as the sole admission
//! control.

use rustc_hash::FxHashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

struct LaneState {
    mutex: tokio::sync::Mutex<()>,
    cancel: CancellationToken,
}

struct SessionState {
    cancel: CancellationToken,
    pending: AtomicUsize,
}

pub struct DeferredRuntime {
    root_cancel: CancellationToken,
    sessions: Mutex<FxHashMap<u8, Arc<SessionState>>>,
    lanes: Mutex<FxHashMap<(u8, u16), Arc<LaneState>>>,
    session_pending_cap: usize,
}

impl DeferredRuntime {
    pub fn new(session_pending_cap: usize) -> Self {
        DeferredRuntime {
            root_cancel: CancellationToken::new(),
            sessions: Mutex::new(FxHashMap::default()),
            lanes: Mutex::new(FxHashMap::default()),
            session_pending_cap: session_pending_cap.max(8),
        }
    }

    fn session_state(&self, session_id: u8) -> Arc<SessionState> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions
            .entry(session_id)
            .or_insert_with(|| Arc::new(SessionState { cancel: self.root_cancel.child_token(), pending: AtomicUsize::new(0) }))
            .clone()
    }

    fn lane_state(&self, session_id: u8, stream_id: u16, session: &SessionState) -> Arc<LaneState> {
        let mut lanes = self.lanes.lock().unwrap();
        lanes
            .entry((session_id, stream_id))
            .or_insert_with(|| Arc::new(LaneState { mutex: tokio::sync::Mutex::new(()), cancel: session.cancel.child_token() }))
            .clone()
    }

    /// Enqueues `work` on the `(session_id, stream_id)` lane. `work` receives
    /// a `CancellationToken` it should race against (`tokio::select!`) for
    /// anything that blocks (dials, upstream I/O) so `remove_session`/
    /// `remove_lane` can abort it promptly. Returns `false` if the
    /// per-session pending cap was already reached (dropped, matching Go's
    /// `dispatchDeferredSessionPacketTracked` overload-drop path).
    pub fn enqueue<F, Fut>(&self, session_id: u8, stream_id: u16, work: F) -> bool
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let session = self.session_state(session_id);
        if session.pending.fetch_add(1, Ordering::AcqRel) >= self.session_pending_cap {
            session.pending.fetch_sub(1, Ordering::AcqRel);
            return false;
        }

        let lane = self.lane_state(session_id, stream_id, &session);

        tokio::spawn(async move {
            let _permit = lane.mutex.lock().await;
            if !lane.cancel.is_cancelled() {
                work(lane.cancel.clone()).await;
            }
            session.pending.fetch_sub(1, Ordering::AcqRel);
        });

        true
    }

    /// Cancels and drops all lane state for a session (its queued/in-flight
    /// deferred work is abandoned) — call when a session closes.
    pub fn remove_session(&self, session_id: u8) {
        let session = self.sessions.lock().unwrap().remove(&session_id);
        if let Some(session) = session {
            session.cancel.cancel();
        }
        let mut lanes = self.lanes.lock().unwrap();
        lanes.retain(|&(sid, _), _| sid != session_id);
    }

    /// Cancels and drops lane state for one stream within a session — call
    /// when a single stream closes but the session persists.
    pub fn remove_lane(&self, session_id: u8, stream_id: u16) {
        if let Some(lane) = self.lanes.lock().unwrap().remove(&(session_id, stream_id)) {
            lane.cancel.cancel();
        }
    }
}
