//! The background loops ported from `internal/arq/arq.go` (`ioLoop`,
//! `writeLoop`, `retransmitLoop`), plus `Start`/`SetLocalConn`/`SetIOReady`.
//! Go's `rxLoop` has no counterpart: `Arq::receive_data` processes inbound
//! data inline.
//!
//! Unlike the rest of this crate (kept synchronous to mirror Go's non-blocking
//! design), these are real `async fn`s spawned as tokio tasks — they are the
//! only places that actually wait on I/O, timers, or channels.

use crate::arq::{Arq, BoxedRead, BoxedWrite};
use crate::types::CloseOptions;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const IO_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const IO_TRANSIENT_READ_BUDGET: Duration = Duration::from_secs(3);
const IO_TRANSIENT_WRITE_BUDGET: u32 = 3;
const READ_WRITE_DEADLINE: Duration = Duration::from_millis(500);

enum IoErrorClass {
    Fatal,
    Timeout,
    Eof,
    Closed,
    Transient,
}

fn classify_io_error(err: &std::io::Error) -> IoErrorClass {
    use std::io::ErrorKind::*;
    match err.kind() {
        TimedOut => IoErrorClass::Timeout,
        WouldBlock | Interrupted => IoErrorClass::Transient,
        ConnectionReset | ConnectionAborted | BrokenPipe | NotConnected => IoErrorClass::Closed,
        UnexpectedEof => IoErrorClass::Eof,
        _ => IoErrorClass::Fatal,
    }
}

impl Arq {
    /// Launches the core background loops for I/O multiplexing and retransmission.
    pub fn start(self: &Arc<Self>) {
        tokio::spawn(retransmit_loop(self.clone()));

        let io_ready = self.inner.lock().unwrap().io_ready;
        if io_ready {
            self.start_stream_workers();
        }
    }

    fn start_stream_workers(self: &Arc<Self>) {
        {
            let mut s = self.inner.lock().unwrap();
            if s.stream_workers_started {
                return;
            }
            if !self.has_local_conn.load(Ordering::SeqCst) {
                return;
            }
            s.stream_workers_started = true;
        }

        tokio::spawn(io_loop(self.clone()));
        tokio::spawn(write_loop(self.clone()));
        self.signal_flush_ready();
    }

    /// Attaches the local application connection (e.g. a SOCKS stream or TCP
    /// forward). Splits it into independent read/write halves so the io and
    /// write loops never contend on the same lock. Only the first call takes
    /// effect, matching Go's `SetLocalConn`.
    pub fn set_local_conn<T>(self: &Arc<Self>, conn: T)
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        {
            let mut r = self.local_conn_read.lock().unwrap();
            let mut w = self.local_conn_write.lock().unwrap();
            if r.is_some() || w.is_some() || self.has_local_conn.load(Ordering::SeqCst) {
                return;
            }
            let (read_half, write_half) = tokio::io::split(conn);
            *r = Some(Box::new(read_half) as BoxedRead);
            *w = Some(Box::new(write_half) as BoxedWrite);
        }
        self.has_local_conn.store(true, Ordering::SeqCst);

        let should_start = {
            let s = self.inner.lock().unwrap();
            !self.cancel_token.is_cancelled() && s.io_ready
        };

        if should_start {
            self.start_stream_workers();
            self.signal_flush_ready();
        }
    }

    pub fn set_io_ready(self: &Arc<Self>, ready: bool) {
        let changed = {
            let mut s = self.inner.lock().unwrap();
            let changed = s.io_ready != ready;
            s.io_ready = ready;
            changed
        };
        if !changed {
            return;
        }
        if ready {
            self.start_stream_workers();
            self.signal_flush_ready();
        }
    }
}

async fn wait_window_not_full(arq: &Arc<Arq>) {
    loop {
        let (snd_buf_len, closed) = {
            let s = arq.inner.lock().unwrap();
            (s.snd_buf.len(), s.closed)
        };
        if snd_buf_len < arq.limit || closed {
            return;
        }

        tokio::select! {
            _ = arq.window_not_full.notified() => {}
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
            _ = arq.cancel_token.cancelled() => return,
        }
    }
}

/// Queued-but-not-yet-pulled DATA packets per stream above which `io_loop`
/// stops reading from the local connection. Downstream capacity is set by how
/// often the peer pulls (one packet per DNS query), not by how fast we read,
/// so reading further ahead only turns every small `read()` into its own
/// packet — and each packet costs a whole DNS response. Leaving the bytes in
/// the kernel socket buffer instead means the next read, done when a pull
/// frees a slot, comes back MTU-sized. A few packets stay queued so that a
/// burst of concurrent pulls (duplicated queries) all find data.
pub(crate) const READ_AHEAD_DATA_PACKETS: usize = 4;

/// Upper bound between rechecks while paced, and how long to wait without any
/// dequeue signal before recounting `queued_data` from `snd_buf` in case it
/// drifted.
const PULL_DEMAND_RECHECK: Duration = Duration::from_millis(50);
const PULL_DEMAND_RECOUNT_AFTER: Duration = Duration::from_millis(500);

/// Waits until fewer than `READ_AHEAD_DATA_PACKETS` DATA packets are queued.
/// Returns false if the stream closed or stopped reading meanwhile.
async fn wait_for_pull_demand(arq: &Arc<Arq>) -> bool {
    let mut waiting_since: Option<std::time::Instant> = None;
    loop {
        {
            let mut s = arq.inner.lock().unwrap();
            if s.closed || s.stop_local_read {
                return false;
            }
            if s.queued_data < READ_AHEAD_DATA_PACKETS {
                return true;
            }
            let since = *waiting_since.get_or_insert_with(std::time::Instant::now);
            if since.elapsed() >= PULL_DEMAND_RECOUNT_AFTER {
                s.queued_data = s.snd_buf.values().filter(|info| !info.dispatched).count();
                waiting_since = None;
                if s.queued_data < READ_AHEAD_DATA_PACKETS {
                    return true;
                }
            }
        }

        tokio::select! {
            _ = arq.data_dequeued.notified() => waiting_since = None,
            _ = tokio::time::sleep(PULL_DEMAND_RECHECK) => {}
            _ = arq.cancel_token.cancelled() => return false,
        }
    }
}

/// After a successful read of `filled` bytes, keeps appending whatever the
/// connection can hand over without blocking, so a packet isn't cut short
/// just because the data arrived in several TCP segments. Errors and EOF are
/// left for the next regular read to report.
async fn fill_from_ready(reader: &mut BoxedRead, buf: &mut [u8], mut filled: usize) -> usize {
    use std::pin::Pin;
    use std::task::Poll;
    use tokio::io::AsyncRead;

    while filled < buf.len() {
        let got = std::future::poll_fn(|cx| {
            let mut read_buf = tokio::io::ReadBuf::new(&mut buf[filled..]);
            match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(read_buf.filled().len()),
                Poll::Ready(Err(_)) | Poll::Pending => Poll::Ready(0),
            }
        })
        .await;
        if got == 0 {
            break;
        }
        filled += got;
    }
    filled
}

/// Reads from the local application connection and enqueues reliable outbound
/// DATA packets.
async fn io_loop(arq: Arc<Arq>) {
    let mut transient_since: Option<std::time::Instant> = None;

    loop {
        if arq.is_closed() {
            return;
        }
        wait_window_not_full(&arq).await;

        let (stop_local_read, closed, io_ready) = {
            let s = arq.inner.lock().unwrap();
            (s.stop_local_read, s.closed, s.io_ready)
        };
        if stop_local_read || closed {
            return;
        }
        if !io_ready {
            tokio::select! {
                _ = arq.cancel_token.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_millis(100)) => continue,
            }
        }

        if !wait_for_pull_demand(&arq).await {
            return;
        }

        let taken = arq.local_conn_read.lock().unwrap().take();
        let mut reader = match taken {
            Some(r) => r,
            None => {
                arq.close("Local connection missing", CloseOptions { send_rst: true, ..Default::default() });
                return;
            }
        };

        let mut buf = vec![0u8; arq.mtu.max(1)];

        let result = match tokio::time::timeout(READ_WRITE_DEADLINE, reader.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => Ok(Ok(fill_from_ready(&mut reader, &mut buf, n).await)),
            other => other,
        };

        {
            let mut guard = arq.local_conn_read.lock().unwrap();
            if guard.is_none() && !arq.is_closed() {
                *guard = Some(reader);
            }
        }

        match result {
            Err(_elapsed) => {
                transient_since = None;
                continue;
            }
            Ok(Ok(0)) => {
                arq.note_client_eof(std::time::Instant::now());
                arq.close("Local App Closed Connection (EOF)", CloseOptions { send_close_read: true, after_drain: true, ..Default::default() });
                return;
            }
            Ok(Ok(n)) => {
                transient_since = None;
                let raw = buf[..n].to_vec();
                let now = std::time::Instant::now();
                let sn = {
                    let mut s = arq.inner.lock().unwrap();
                    s.last_activity = now;
                    let sn = s.snd_nxt;
                    s.snd_nxt = s.snd_nxt.wrapping_add(1);
                    let current_rto = arq.current_data_base_rto(&s);
                    s.queued_data += 1;
                    s.snd_buf.insert(
                        sn,
                        crate::types::DataItem {
                            data: raw.clone(),
                            created_at: now,
                            last_sent_at: None,
                            dispatched: false,
                            last_nack_sent_at: None,
                            retries: 0,
                            current_rto,
                            sample_eligible: true,
                            compression_type: arq.compression_type,
                            ttl: Duration::ZERO,
                        },
                    );
                    sn
                };

                let ok = arq.enqueuer.push_tx_packet(
                    enums::default_packet_priority(enums::PACKET_STREAM_DATA),
                    enums::PACKET_STREAM_DATA,
                    sn,
                    0,
                    0,
                    arq.compression_type,
                    Duration::ZERO,
                    &raw,
                );
                if !ok {
                    let mut s = arq.inner.lock().unwrap();
                    let s = &mut *s;
                    if let Some(info) = s.snd_buf.get_mut(&sn) {
                        if !info.dispatched {
                            s.queued_data = s.queued_data.saturating_sub(1);
                        }
                        info.dispatched = true;
                        info.last_sent_at = now.checked_sub(info.current_rto);
                    }
                }
            }
            Ok(Err(e)) => match classify_io_error(&e) {
                IoErrorClass::Timeout => {
                    transient_since = None;
                    continue;
                }
                IoErrorClass::Transient => {
                    let now = std::time::Instant::now();
                    let since = transient_since.get_or_insert(now);
                    if now.duration_since(*since) > IO_TRANSIENT_READ_BUDGET {
                        arq.close(
                            &format!("Repeated transient read errors: {e}"),
                            CloseOptions { send_rst: true, after_drain: false, ..Default::default() },
                        );
                        return;
                    }
                    tokio::time::sleep(IO_RETRY_BACKOFF).await;
                }
                IoErrorClass::Eof => {
                    arq.note_client_eof(std::time::Instant::now());
                    arq.close("Local App Closed Connection (EOF)", CloseOptions { send_close_read: true, after_drain: true, ..Default::default() });
                    return;
                }
                IoErrorClass::Closed => {
                    if arq.is_graceful_close_in_progress() {
                        return;
                    }
                    arq.close("Local connection closed", CloseOptions { send_rst: true, ..Default::default() });
                    return;
                }
                IoErrorClass::Fatal => {
                    arq.close(&format!("Read Error: {e}"), CloseOptions { send_rst: true, ..Default::default() });
                    return;
                }
            },
        }
    }
}

/// Drains contiguous, in-order buffered data to the local application connection.
async fn write_loop(arq: Arc<Arq>) {
    loop {
        let has_ready = {
            let s = arq.inner.lock().unwrap();
            s.rcv_buf.contains_key(&s.rcv_nxt)
        };

        if !has_ready {
            tokio::select! {
                _ = arq.cancel_token.cancelled() => return,
                _ = arq.flush_signal.notified() => {}
            }
        }

        loop {
            if arq.is_closed() {
                return;
            }

            let (io_ready, closed) = {
                let s = arq.inner.lock().unwrap();
                (s.io_ready, s.closed)
            };
            if !io_ready || closed {
                break;
            }

            if !arq.has_local_conn.load(Ordering::SeqCst) {
                arq.close(
                    "Local connection missing for writer",
                    CloseOptions { send_rst: true, after_drain: true, ..Default::default() },
                );
                return;
            }

            let mut to_write: Vec<Vec<u8>> = Vec::new();
            {
                let mut s = arq.inner.lock().unwrap();
                loop {
                    let key = s.rcv_nxt;
                    match s.rcv_buf.remove(&key) {
                        Some(data) => {
                            to_write.push(data);
                            s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
                        }
                        None => break,
                    }
                }
                s.local_write_pending = !to_write.is_empty();
            }

            if to_write.is_empty() {
                let (cr, rst_received, pending_inbound) = {
                    let s = arq.inner.lock().unwrap();
                    (s.close_read_received, s.rst_received, s.pending_inbound)
                };
                if cr && pending_inbound == 0 {
                    arq.half_close_local_writer().await;
                }
                if rst_received && arq.try_finalize_peer_reset_drain() {
                    return;
                }
                arq.try_finalize_remote_eof();
                break;
            }

            let merged: Vec<u8> = to_write.concat();
            let taken = arq.local_conn_write.lock().unwrap().take();
            let mut writer = match taken {
                Some(w) => w,
                None => {
                    arq.close(
                        "Local connection missing for writer",
                        CloseOptions { send_rst: true, after_drain: true, ..Default::default() },
                    );
                    return;
                }
            };

            let mut remaining: &[u8] = &merged;
            let mut transient_retries: u32 = 0;
            let mut exit_after_write = false;

            while !remaining.is_empty() {
                match tokio::time::timeout(READ_WRITE_DEADLINE, writer.write(remaining)).await {
                    Err(_elapsed) => {
                        if !bump_transient_write_retry(&arq, &mut transient_retries) {
                            exit_after_write = true;
                            break;
                        }
                    }
                    Ok(Ok(0)) => {
                        if !bump_transient_write_retry(&arq, &mut transient_retries) {
                            exit_after_write = true;
                            break;
                        }
                    }
                    Ok(Ok(n)) => remaining = &remaining[n..],
                    Ok(Err(e)) => match classify_io_error(&e) {
                        IoErrorClass::Timeout | IoErrorClass::Transient => {
                            if !bump_transient_write_retry(&arq, &mut transient_retries) {
                                exit_after_write = true;
                                break;
                            }
                        }
                        IoErrorClass::Eof | IoErrorClass::Closed => {
                            arq.mark_local_writer_broken(&format!("local app writer closed: {e}"));
                            close_after_write_failure(&arq, "writer closed");
                            exit_after_write = true;
                            break;
                        }
                        IoErrorClass::Fatal => {
                            arq.mark_local_writer_broken(&format!("local app write error: {e}"));
                            close_after_write_failure(&arq, &format!("Local App Write Error: {e}"));
                            exit_after_write = true;
                            break;
                        }
                    },
                }
            }

            {
                let mut guard = arq.local_conn_write.lock().unwrap();
                if guard.is_none() && !arq.is_closed() {
                    *guard = Some(writer);
                }
            }
            {
                let mut s = arq.inner.lock().unwrap();
                s.local_write_pending = false;
            }

            if exit_after_write {
                return;
            }

            if arq.try_finalize_peer_reset_drain() {
                return;
            }
            arq.try_finalize_remote_eof();
        }
    }
}

/// Returns `false` once the transient-write retry budget is exhausted (and has
/// already closed the stream in that case).
fn bump_transient_write_retry(arq: &Arc<Arq>, retries: &mut u32) -> bool {
    *retries += 1;
    if *retries >= IO_TRANSIENT_WRITE_BUDGET {
        arq.mark_local_writer_broken("local app write timeout/transient budget exceeded");
        close_after_write_failure(arq, "local app write timeout/transient budget exceeded");
        return false;
    }
    true
}

fn close_after_write_failure(arq: &Arc<Arq>, reason: &str) {
    let graceful = arq.is_graceful_close_in_progress();
    let reason = if graceful {
        format!("Local App Write Error during graceful close: {reason}")
    } else {
        format!("Local App Write Error: {reason}")
    };
    arq.close(&reason, CloseOptions { send_close_write: true, ..Default::default() });
}

async fn retransmit_loop(arq: Arc<Arq>) {
    loop {
        let (base_interval, has_pending) = {
            let s = arq.inner.lock().unwrap();
            let mut rto_factor = arq.rto;
            if arq.enable_control_reliability && arq.control_rto < rto_factor {
                rto_factor = arq.control_rto;
            }
            let base_interval = (rto_factor / 3).max(Duration::from_millis(50));
            let has_pending = !s.snd_buf.is_empty()
                || (arq.enable_control_reliability && !s.control_snd_buf.is_empty())
                || !s.pending_reacks.is_empty();
            (base_interval, has_pending)
        };

        let mut interval = if has_pending { base_interval } else { (base_interval * 4).max(Duration::from_millis(100)) };

        // A scheduled re-ACK has its own fixed delay (`data::REACK_DELAY`),
        // independent of the RTO-derived interval above: cap the sleep to
        // when it falls due so an upload-only stream (which never touches
        // the `has_pending` branch through `snd_buf`/`control_snd_buf`)
        // still emits it close to on time instead of up to a whole
        // `base_interval` late.
        //
        // Floored at 20ms, not driven all the way down to the front entry's
        // exact due time: under sustained receive traffic a new entry lands
        // in `pending_reacks` faster than old ones fall due, so the front's
        // due time is almost always "very soon" and an unfloored clamp turns
        // this into a near-busy-loop (observed up to ~1kHz per busy stream)
        // for as long as the stream keeps receiving — real contention on
        // `arq.inner` across every stream's `io_loop`/`write_loop` at
        // higher concurrency (see the duplex-throughput regression this and
        // `data::REACK_PRIORITY` together fix). 20ms is still a fraction of
        // `REACK_DELAY` (150ms), so it does not meaningfully change how late
        // a re-ACK can land relative to the client's RTO margin.
        if let Some(due) = arq.next_reack_due() {
            let remaining = due.saturating_duration_since(std::time::Instant::now()).max(Duration::from_millis(20));
            interval = interval.min(remaining);
        }

        tokio::select! {
            _ = arq.cancel_token.cancelled() => return,
            _ = tokio::time::sleep(interval) => {}
            // Wakes early when a fresh re-ACK is scheduled while this loop is
            // mid-sleep on the long "nothing pending" interval, so the very
            // first re-ACK of an otherwise idle stream isn't delayed by a
            // sleep that was already committed to before it existed.
            _ = arq.reack_scheduled.notified() => {}
        }

        arq.check_retransmits();
    }
}
