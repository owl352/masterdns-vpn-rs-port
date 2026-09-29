//! End-to-end tests exercising the real background loops (io/write/rx/retransmit)
//! against an in-memory duplex "local connection" and a mock packet enqueuer.

use crate::{ArqLogger, CloseOptions, Config, PacketEnqueuer};
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct MockEnqueuer {
    pushed: Mutex<Vec<(u8, u16, Vec<u8>)>>,
    /// Priority each push was made with, parallel to `pushed` (kept separate
    /// so existing `(packet_type, sn, payload)` tuple patterns above don't
    /// need to change).
    priorities: Mutex<Vec<(i32, u8, u16)>>,
    notify: tokio::sync::Notify,
    /// What `has_queued_download_data` reports, settable per-test to drive
    /// `store_received_data`'s immediate-ACK priority decision.
    has_backlog: std::sync::atomic::AtomicBool,
}

impl PacketEnqueuer for MockEnqueuer {
    fn push_tx_packet(
        &self,
        priority: i32,
        packet_type: u8,
        sequence_num: u16,
        _fragment_id: u8,
        _total_fragments: u8,
        _compression_type: u8,
        _ttl: Duration,
        payload: &[u8],
    ) -> bool {
        self.pushed.lock().unwrap().push((packet_type, sequence_num, payload.to_vec()));
        self.priorities.lock().unwrap().push((priority, packet_type, sequence_num));
        self.notify.notify_one();
        true
    }

    fn has_queued_download_data(&self) -> bool {
        self.has_backlog.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl MockEnqueuer {
    fn set_has_backlog(&self, v: bool) {
        self.has_backlog.store(v, std::sync::atomic::Ordering::SeqCst);
    }

    /// Priority of the most recent push matching `packet_type`/`sn`.
    fn priority_of(&self, packet_type: u8, sn: u16) -> Option<i32> {
        self.priorities.lock().unwrap().iter().rev().find(|&&(_, pt, s)| pt == packet_type && s == sn).map(|&(p, _, _)| p)
    }
}

struct SilentLogger;
impl ArqLogger for SilentLogger {}

async fn wait_for_push(mock: &MockEnqueuer, packet_type: u8) -> (u16, Vec<u8>) {
    for _ in 0..200 {
        {
            let pushed = mock.pushed.lock().unwrap();
            if let Some(&(_, sn, ref payload)) = pushed.iter().find(|(pt, _, _)| *pt == packet_type) {
                return (sn, payload.clone());
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for packet type {packet_type}");
}

#[tokio::test]
async fn local_app_write_becomes_stream_data_push() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(1, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();

    let (mut app_side, arq_side) = tokio::io::duplex(4096);
    arq.set_local_conn(arq_side);

    app_side.write_all(b"hello from app").await.unwrap();

    let (sn, payload) = wait_for_push(&enqueuer, enums::PACKET_STREAM_DATA).await;
    assert_eq!(sn, 0);
    assert_eq!(payload, b"hello from app");
    assert!(arq.has_pending_sequence(0));
}

#[tokio::test]
async fn receive_data_is_delivered_to_local_app_in_order() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(2, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();

    let (mut app_side, arq_side) = tokio::io::duplex(4096);
    arq.set_local_conn(arq_side);

    // Deliver sequence 1 first (out of order), then 0 — write_loop should
    // still emit "helloworld" (in order) once 0 arrives.
    assert!(arq.receive_data(1, b"world"));
    assert!(arq.receive_data(0, b"hello"));

    let mut buf = [0u8; 32];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut collected = Vec::new();
    while collected.len() < 10 && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), app_side.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => collected.extend_from_slice(&buf[..n]),
            _ => continue,
        }
    }

    assert_eq!(collected, b"helloworld");

    // Both sequence numbers should have produced STREAM_DATA_ACK pushes.
    wait_for_push(&enqueuer, enums::PACKET_STREAM_DATA_ACK).await;
}

#[tokio::test]
async fn receive_ack_clears_pending_sequence() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(3, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();

    let (mut app_side, arq_side) = tokio::io::duplex(4096);
    arq.set_local_conn(arq_side);

    app_side.write_all(b"data").await.unwrap();
    wait_for_push(&enqueuer, enums::PACKET_STREAM_DATA).await;
    assert!(arq.has_pending_sequence(0));

    assert!(arq.receive_ack(enums::PACKET_STREAM_DATA_ACK, 0));
    assert!(!arq.has_pending_sequence(0));
    // A second ACK for the same (already-removed) sequence is a no-op.
    assert!(!arq.receive_ack(enums::PACKET_STREAM_DATA_ACK, 0));
}

#[tokio::test]
async fn close_force_finalizes_immediately() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(4, 1, enqueuer, 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();

    assert!(!arq.is_closed());
    arq.close("test forced close", CloseOptions { force: true, ..Default::default() });
    assert!(arq.is_closed());
    assert_eq!(arq.state(), crate::StreamState::Closing);

    tokio::time::timeout(Duration::from_secs(1), arq.done()).await.expect("done() should resolve after close");
}

#[tokio::test]
async fn rst_close_sends_rst_packet_and_closes_after_ack() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(5, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();

    arq.close("test rst", CloseOptions { send_rst: true, ..Default::default() });

    let (sn, _) = wait_for_push(&enqueuer, enums::PACKET_STREAM_RST).await;
    assert!(!arq.is_closed(), "should be waiting for RST_ACK, not yet fully closed");

    assert!(arq.handle_ack_packet(enums::PACKET_STREAM_RST_ACK, sn, 0));
    assert!(arq.is_closed());
}

fn pushed_data_sizes(mock: &MockEnqueuer) -> Vec<usize> {
    mock.pushed.lock().unwrap().iter().filter(|(pt, _, _)| *pt == enums::PACKET_STREAM_DATA).map(|(_, _, p)| p.len()).collect()
}

#[tokio::test]
async fn reads_pause_while_enough_data_is_queued_and_resume_with_full_packets() {
    const MTU: usize = 100;
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(6, 1, enqueuer.clone(), MTU, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();

    let (mut app_side, arq_side) = tokio::io::duplex(8192);
    arq.set_local_conn(arq_side);

    // Small writes spaced out: each is read on its own while there is room.
    for _ in 0..crate::loops::READ_AHEAD_DATA_PACKETS {
        app_side.write_all(&[7u8; 20]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Nothing is being pulled, so these must stay in the connection buffer.
    for _ in 0..30 {
        app_side.write_all(&[9u8; 20]).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(pushed_data_sizes(&enqueuer), vec![20; crate::loops::READ_AHEAD_DATA_PACKETS]);

    // A pull frees one slot; the buffered small writes come out as one full packet.
    arq.note_tx_packet_dequeued(enums::PACKET_STREAM_DATA, 0, 0);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let sizes = pushed_data_sizes(&enqueuer);
    assert_eq!(sizes.len(), crate::loops::READ_AHEAD_DATA_PACKETS + 1);
    assert_eq!(sizes[crate::loops::READ_AHEAD_DATA_PACKETS], MTU);

    // An ACK for a still-queued packet also frees a slot.
    assert!(arq.receive_ack(enums::PACKET_STREAM_DATA_ACK, 1));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(pushed_data_sizes(&enqueuer).len(), crate::loops::READ_AHEAD_DATA_PACKETS + 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_eof_with_unacked_data_does_not_deadlock() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(7, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();

    let (mut app_side, arq_side) = tokio::io::duplex(4096);
    arq.set_local_conn(arq_side);

    app_side.write_all(b"never acked").await.unwrap();
    wait_for_push(&enqueuer, enums::PACKET_STREAM_DATA).await;
    // EOF while sequence 0 is still unacked -> deferred (draining) close, which
    // the retransmit loop then polls. Its first sleep (idle interval) can be
    // over a second, so allow several ticks.
    drop(app_side);
    std::thread::sleep(Duration::from_millis(3000));

    // Probe from a plain OS thread: if the retransmit loop deadlocked it may
    // have taken every runtime worker (and the timer) down with it, so no
    // tokio-based timeout could fire.
    let probe = arq.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(probe.state());
    });
    if rx.recv_timeout(Duration::from_secs(2)).is_err() {
        // Unwinding would hang in runtime shutdown on the stuck worker.
        eprintln!("ARQ state lock is stuck: retransmit loop deadlocked while draining");
        std::process::abort();
    }
    assert_eq!(arq.state(), crate::StreamState::Draining);
}

#[tokio::test]
async fn receive_data_queues_ack_before_returning() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(8, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();
    let (_app_side, arq_side) = tokio::io::duplex(4096);
    arq.set_local_conn(arq_side);

    // No await in between: nothing else gets a chance to run first.
    assert!(arq.receive_data(0, b"payload"));
    let pushed = enqueuer.pushed.lock().unwrap();
    assert!(pushed.iter().any(|(t, sn, _)| *t == enums::PACKET_STREAM_DATA_ACK && *sn == 0), "ACK for seq 0 not queued synchronously: {:?}", pushed.iter().map(|(t, sn, _)| (*t, *sn)).collect::<Vec<_>>());
}

/// CLOSE_READ arrives while a retransmitted duplicate is still being handled:
/// the writer must still half-close the local connection once that duplicate
/// is done, not wait for the terminal drain timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_read_half_closes_after_inflight_duplicate() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(9, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();
    let (mut app_side, arq_side) = tokio::io::duplex(4096);
    arq.set_local_conn(arq_side);

    assert!(arq.receive_data(0, b"x"));
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(2), app_side.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"x");

    // A duplicate of seq 0 is in flight when CLOSE_READ is processed.
    arq.inner.lock().unwrap().pending_inbound += 1;
    arq.mark_close_read_received();
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The duplicate finishes on the "already delivered" early-return path.
    arq.process_received_data(0, b"x");

    let eof = tokio::time::timeout(Duration::from_secs(1), app_side.read(&mut buf)).await;
    assert!(matches!(eof, Ok(Ok(0))), "local connection was not half-closed: {eof:?}");
}

/// A retransmission of data delivered long ago (more than 32768 sequence
/// numbers back, which 16-bit sequence arithmetic reads as "ahead") must be
/// re-ACKed, not dropped: its first ACK was lost and the peer keeps resending
/// it, so dropping it stalled the stream until the drain timeout.
#[tokio::test]
async fn ancient_duplicate_that_looks_ahead_is_reacked() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(10, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.inner.lock().unwrap().rcv_nxt = 60000;

    // 15000 is ~45000 behind 60000, i.e. 20536 "ahead" modulo 65536.
    arq.process_received_data(15000, b"old");
    let acked = |sn: u16| enqueuer.pushed.lock().unwrap().iter().any(|(t, s, _)| *t == enums::PACKET_STREAM_DATA_ACK && *s == sn);
    assert!(acked(15000), "old duplicate was not re-ACKed");
    assert!(arq.inner.lock().unwrap().rcv_buf.is_empty(), "old duplicate must not be buffered");

    // Genuinely ahead (inside the receive window) is still buffered and ACKed.
    arq.process_received_data(60010, b"ahead");
    assert!(acked(60010));
    assert!(arq.inner.lock().unwrap().rcv_buf.contains_key(&60010));
}

/// Past a gap, a peer can legitimately be more than one window ahead
/// (ACKs are per packet). Such data beyond our receive window must be dropped
/// without an ACK so the peer resends it later, never ACKed and discarded.
#[tokio::test]
async fn far_ahead_data_within_peer_reach_is_not_acked() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let cfg = Config { window_size: 4096, ..Config::default() };
    let arq = crate::Arq::new(11, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), cfg);
    {
        // Seq 1000 is missing; we already saw data up to one receive window
        // past it, so the peer may be up to MAX_WINDOW_SIZE beyond that.
        let mut s = arq.inner.lock().unwrap();
        s.rcv_nxt = 1000;
        s.rcv_highest = 1000u16.wrapping_add(arq.receive_window_size as u16);
    }
    let ahead = (arq.receive_window_size + crate::MAX_WINDOW_SIZE / 2) as u16;
    let sn = 1000u16.wrapping_add(ahead);

    arq.process_received_data(sn, b"future");
    let acked = enqueuer.pushed.lock().unwrap().iter().any(|(t, s, _)| *t == enums::PACKET_STREAM_DATA_ACK && *s == sn);
    assert!(!acked, "data {ahead} ahead was ACKed without being stored");
    assert!(arq.inner.lock().unwrap().rcv_buf.is_empty());
}

fn ack_pushes(mock: &MockEnqueuer, sn: u16) -> usize {
    mock.pushed.lock().unwrap().iter().filter(|(t, s, _)| *t == enums::PACKET_STREAM_DATA_ACK && *s == sn).count()
}

/// Delayed re-ACKs (the fix for the sequence-wrap data-corruption bug): a
/// freshly stored packet gets its normal immediate ACK, then exactly one
/// extra ACK after `data::REACK_DELAY` has elapsed -- not before, and not
/// more than once. This is what lets a lost ACK be repaired before the Go
/// client's RTO fires and it retransmits into a future sequence-number wrap.
#[tokio::test]
async fn stored_data_gets_immediate_ack_and_one_delayed_reack() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(12, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();

    arq.process_received_data(0, b"x");
    assert_eq!(ack_pushes(&enqueuer, 0), 1, "immediate ACK missing");

    // Not due yet: still just the immediate ACK.
    tokio::time::sleep(crate::data::REACK_DELAY / 2).await;
    assert_eq!(ack_pushes(&enqueuer, 0), 1, "re-ACK fired before its delay elapsed");

    // Past REACK_DELAY: exactly one extra re-ACK, and no more show up later.
    tokio::time::sleep(crate::data::REACK_DELAY + Duration::from_millis(200)).await;
    assert_eq!(ack_pushes(&enqueuer, 0), 2, "expected exactly one delayed re-ACK");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ack_pushes(&enqueuer, 0), 2, "re-ACK must not repeat");
}

/// Regression test for the duplex-throughput stall (`socks-echo-multi` /
/// `load-streams` went from ~1.2-1.4s to 50-90s): a DNS response can only
/// carry one item pulled from a stream's own priority queue
/// (`udpserver::postsession::dequeue_session_response`), so if the delayed
/// re-ACK copy shared the immediate ACK's CRITICAL priority it would
/// permanently outrank that same stream's own outbound STREAM_DATA
/// (NORMAL priority) for as long as the peer kept sending — i.e. it isn't
/// enough for the *immediate* ACK to stay fast, the *delayed* copy
/// specifically must never be able to preempt outbound data. Pin both halves
/// of that invariant so a future change can't silently restore it:
/// - the immediate ACK keeps the protocol's normal (CRITICAL) priority, and
/// - the delayed re-ACK copy is strictly lower priority than outbound
///   STREAM_DATA, so a stream's own pending send is always picked over it.
#[tokio::test]
async fn delayed_reack_is_lower_priority_than_outbound_data() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(15, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();

    arq.process_received_data(0, b"x");
    tokio::time::sleep(crate::data::REACK_DELAY + Duration::from_millis(200)).await;
    assert_eq!(ack_pushes(&enqueuer, 0), 2, "expected an immediate ACK and one delayed re-ACK");

    let priorities: Vec<i32> = enqueuer
        .priorities
        .lock()
        .unwrap()
        .iter()
        .filter(|&&(_, t, s)| t == enums::PACKET_STREAM_DATA_ACK && s == 0)
        .map(|&(p, _, _)| p)
        .collect();
    assert_eq!(priorities.len(), 2, "expected exactly two ACK pushes for sn 0");
    let immediate_priority = priorities[0];
    let reack_priority = priorities[1];

    assert_eq!(
        immediate_priority,
        enums::default_packet_priority(enums::PACKET_STREAM_DATA_ACK),
        "immediate ACK priority must stay at the protocol default (kept fast on purpose)"
    );
    let data_priority = enums::default_packet_priority(enums::PACKET_STREAM_DATA);
    assert!(
        reack_priority > data_priority,
        "delayed re-ACK priority ({reack_priority}) must be strictly lower priority (a larger number) \
         than outbound STREAM_DATA ({data_priority}), or it starves a duplex stream's download direction \
         for as long as the peer keeps sending"
    );
}

/// Data the server drops without ever ACKing it (out of window / beyond peer
/// reach, see `far_ahead_data_within_peer_reach_is_not_acked`) must never get
/// a re-ACK either: ACKing data we did not keep would make the peer believe
/// it was delivered and it would never resend it, losing data.
#[tokio::test]
async fn unstored_data_never_gets_a_reack() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let cfg = Config { window_size: 4096, ..Config::default() };
    let arq = crate::Arq::new(13, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), cfg);
    arq.start();
    {
        let mut s = arq.inner.lock().unwrap();
        s.rcv_nxt = 1000;
        s.rcv_highest = 1000u16.wrapping_add(arq.receive_window_size as u16);
    }
    let ahead = (arq.receive_window_size + crate::MAX_WINDOW_SIZE / 2) as u16;
    let sn = 1000u16.wrapping_add(ahead);

    arq.process_received_data(sn, b"future");
    assert_eq!(ack_pushes(&enqueuer, sn), 0);

    tokio::time::sleep(crate::data::REACK_DELAY + Duration::from_millis(200)).await;
    assert_eq!(ack_pushes(&enqueuer, sn), 0, "unstored data must never be (re-)ACKed");
    assert!(arq.inner.lock().unwrap().pending_reacks.is_empty());
}

/// The pending re-ACK FIFO must stay bounded even under a flood of duplicate
/// deliveries of the same sequence number (each duplicate schedules another
/// entry), and must be dropped entirely once the stream closes.
#[tokio::test]
async fn pending_reacks_are_bounded_and_cleared_on_close() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let cfg = Config { window_size: 300, ..Config::default() };
    // Don't call start(): process_received_data is synchronous and we want to
    // inspect the FIFO before the retransmit loop has a chance to drain it.
    let arq = crate::Arq::new(14, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), cfg);

    for _ in 0..(crate::data::REACK_QUEUE_CAP + 50) {
        arq.process_received_data(0, b"x");
    }
    let len = arq.inner.lock().unwrap().pending_reacks.len();
    assert!(len > 0);
    assert!(
        len <= crate::data::REACK_QUEUE_CAP,
        "pending_reacks grew past its bound: {len} > {}",
        crate::data::REACK_QUEUE_CAP
    );

    arq.close("test forced close", CloseOptions { force: true, ..Default::default() });
    assert!(arq.inner.lock().unwrap().pending_reacks.is_empty(), "pending_reacks not cleared on close");
}

/// `store_received_data` must queue the immediate ACK for a freshly-stored
/// packet at its normal CRITICAL priority when the enqueuer reports no
/// download data queued, and skip queuing it synchronously - scheduling a
/// short-delay `FAST_ACK_DELAY` fast ACK via `pending_fast_acks` instead -
/// when `has_queued_download_data` is true, so a lone ACK never preempts a
/// stream's own waiting download data, but still rides its own reply
/// promptly when there is nothing to preempt.
///
/// (Two prior designs were tried and rejected: demoting the immediate ACK to
/// LOW priority with a dequeue-time force-release (collided with
/// `REACK_PRIORITY`'s own LOW-priority duplicates and caused a severe
/// duplex-throughput regression), and skipping it entirely in favor of
/// `REACK_DELAY`'s existing 150ms safety net alone (safe, but measurably
/// slower on a near-zero-latency network where the client's own adaptive
/// upload RTO runs under 150ms). See the doc comment on `FAST_ACK_DELAY`
/// above for the full account. This test locks in the corrected "skip the
/// synchronous copy, schedule a short-delay CRITICAL one instead" behavior.)
#[tokio::test]
async fn immediate_ack_becomes_fast_ack_when_download_backlogged() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let cfg = Config { window_size: 300, ..Config::default() };
    // Synchronous, like the FIFO test above: no need for the background loops.
    let arq = crate::Arq::new(15, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), cfg);

    enqueuer.set_has_backlog(false);
    arq.process_received_data(0, b"no backlog");
    assert_eq!(
        enqueuer.priority_of(enums::PACKET_STREAM_DATA_ACK, 0),
        Some(enums::PACKET_PRIORITY_CRITICAL),
        "with no download backlog the immediate ACK must still be sent synchronously, at CRITICAL"
    );
    assert!(!arq.inner.lock().unwrap().pending_fast_acks.iter().any(|&(sn, _)| sn == 0), "no fast ACK should be scheduled when the immediate copy was already sent");

    enqueuer.set_has_backlog(true);
    arq.process_received_data(1, b"backlogged");
    assert_eq!(
        enqueuer.priority_of(enums::PACKET_STREAM_DATA_ACK, 1),
        None,
        "with download backlog the immediate ACK must not be sent synchronously"
    );
    assert!(arq.inner.lock().unwrap().pending_fast_acks.iter().any(|&(sn, _)| sn == 1), "sn=1 must have a fast ACK scheduled");
    // The delayed re-ACK safety net is still scheduled regardless, so sn=1
    // is covered twice over, never left permanently unacknowledged.
    assert!(arq.inner.lock().unwrap().pending_reacks.iter().any(|&(sn, _)| sn == 1), "sn=1 must still also have a delayed re-ACK scheduled");
}

/// The scheduled fast ACK from the test above must actually fire, at the
/// ACK's normal CRITICAL priority, once `FAST_ACK_DELAY` elapses - exercised
/// through the real background loops this time (`arq.start()`) so
/// `retransmit_loop`'s wake-up timing is exactly what a live stream sees.
#[tokio::test]
async fn fast_ack_is_emitted_at_critical_priority_after_its_delay() {
    let enqueuer = std::sync::Arc::new(MockEnqueuer::default());
    let arq = crate::Arq::new(16, 1, enqueuer.clone(), 1500, Some(std::sync::Arc::new(SilentLogger)), Config::default());
    arq.start();

    enqueuer.set_has_backlog(true);
    arq.process_received_data(0, b"backlogged");
    // Not sent synchronously.
    assert!(enqueuer.priority_of(enums::PACKET_STREAM_DATA_ACK, 0).is_none());

    // `retransmit_loop`'s wake-up floor is 20ms and `FAST_ACK_DELAY` is
    // 25ms, so this should land well within a couple hundred ms even under
    // test-harness scheduling noise.
    let (sn, _) = wait_for_push(&enqueuer, enums::PACKET_STREAM_DATA_ACK).await;
    assert_eq!(sn, 0);
    assert_eq!(enqueuer.priority_of(enums::PACKET_STREAM_DATA_ACK, 0), Some(enums::PACKET_PRIORITY_CRITICAL), "the fast ACK must fire at CRITICAL, not LOW");
}
