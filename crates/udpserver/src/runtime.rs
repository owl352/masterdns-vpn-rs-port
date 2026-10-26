//! Port of the bootstrap/serving half of `internal/udpserver/server.go`
//! + `server_runtime.go` + `reuseport_unix.go`/`reuseport_fallback.go`.
//!
//! Differences vs. Go: requests are handled inline by the task that received
//! them instead of Go's reader -> channel -> worker pipeline (see
//! `serve_loop`), and replies go out on the socket the request arrived on.
//! `UDP_READERS` still sets the socket count and `DNS_REQUEST_WORKERS` the
//! total serving tasks; `MAX_CONCURRENT_REQUESTS` no longer sizes a request
//! queue (the kernel socket buffer is the queue). Also not ported: the
//! optional raw-UDP `FALLBACK` passthrough feature (see crate root docs).

use crate::Server;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Runs the server until `shutdown` is cancelled. Mirrors Go's `Server.Run`.
pub async fn run(server: Arc<Server>, shutdown: CancellationToken) -> std::io::Result<()> {
    let reader_count = server.cfg.effective_udp_readers().max(1) as usize;
    let sockets = open_udp_listeners(&server.cfg, reader_count)?;

    let buffer_size = server.cfg.max_packet_size.max(512) as usize;
    let worker_count = server.cfg.effective_dns_request_workers().max(1) as usize;
    let tasks_per_socket = worker_count.div_ceil(sockets.len()).max(MIN_TASKS_PER_SOCKET);

    server.log.infof(&format!(
        "UDP Listener Ready, Addr: {}, Readers: {}, Workers: {}, Sockets: {}, Tasks Per Socket: {}",
        server.cfg.address(),
        reader_count,
        worker_count,
        sockets.len(),
        tasks_per_socket,
    ));

    let mut serve_handles = Vec::with_capacity(sockets.len() * tasks_per_socket);
    for socket in &sockets {
        for _ in 0..tasks_per_socket {
            let socket = socket.clone();
            let shutdown = shutdown.clone();
            let server = server.clone();
            serve_handles.push(tokio::spawn(async move { serve_loop(server, socket, buffer_size, shutdown).await }));
        }
    }

    let cleanup_handle = {
        let server = server.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move { session_cleanup_loop(server, shutdown).await })
    };

    for handle in serve_handles {
        let _ = handle.await;
    }
    shutdown.cancel();
    let _ = cleanup_handle.await;

    Ok(())
}

/// Floor on concurrent serve tasks per socket. On Linux `SO_REUSEPORT` hashes
/// each resolver's 4-tuple to one socket, so a busy resolver lands on a single
/// socket; a second task there keeps one slow request from stalling the rest.
/// Going higher only adds `sendto` contention on the socket: 4 per socket cost
/// ~75% more server CPU than 2 on the loopback upload benchmark, for no gain.
const MIN_TASKS_PER_SOCKET: usize = 2;

/// Receives, handles and answers datagrams on one socket, all in the same task.
///
/// Earlier this was split into a reader task feeding worker tasks through a
/// channel (Go's layout). In tokio that hand-off wakes a task on another
/// worker thread for every query, which added latency to each round trip and
/// had many threads racing in `sendto` on the same socket: on a loopback
/// upload benchmark it cost ~2.5x the CPU of the Go server and ~20% less
/// throughput. Handling inline removes the hop; `handle_packet` is synchronous
/// and fast, and anything slow (dials, upstream DNS) is already spawned off
/// as deferred work. Several tasks share each socket, and the kernel socket
/// buffer (`SOCKET_BUFFER_SIZE`) is the queue under load.
///
/// On Linux each task moves datagrams in batches (`recvmmsg`/`sendmmsg`, see
/// `batch_io`); elsewhere it handles one datagram per `recv_from`/`send_to`.
async fn serve_loop(server: Arc<Server>, socket: Arc<UdpSocket>, buffer_size: usize, shutdown: CancellationToken) {
    #[cfg(target_os = "linux")]
    serve_loop_batched(server, socket, buffer_size, shutdown).await;
    #[cfg(not(target_os = "linux"))]
    serve_loop_single(server, socket, buffer_size, shutdown).await;
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
async fn serve_loop_single(server: Arc<Server>, socket: Arc<UdpSocket>, buffer_size: usize, shutdown: CancellationToken) {
    let mut buf = vec![0u8; buffer_size];
    loop {
        let (n, addr) = tokio::select! {
            _ = shutdown.cancelled() => return,
            result = socket.recv_from(&mut buf) => match result {
                Ok(received) => received,
                Err(_) => return,
            },
        };
        if let Some((response, ticket)) = server.handle_packet_with_ticket(&buf[..n], std::time::Instant::now()) {
            if socket.send_to(&response, addr).await.is_ok() {
                if let Some(ticket) = ticket { ticket.sent(); }
            }
        }
    }
}

/// One `recvmmsg` per wakeup, each query handled with the same timestamp,
/// then one `sendmmsg` for all replies. Errors mirror the single path: the
/// task ends on a receive error, and a reply that cannot be sent is dropped.
#[cfg(target_os = "linux")]
async fn serve_loop_batched(server: Arc<Server>, socket: Arc<UdpSocket>, buffer_size: usize, shutdown: CancellationToken) {
    use crate::batch_io::{send_batch, RecvBatch, BATCH};
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    let fd = socket.as_raw_fd();
    let mut batch = RecvBatch::new(buffer_size);
    let mut replies: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(BATCH);
    let mut tickets: Vec<Option<crate::transport::ResponseTicket>> = Vec::with_capacity(BATCH);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            ready = socket.readable() => if ready.is_err() { return },
        }
        let received = match socket.try_io(Interest::READABLE, || batch.recv(fd)) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => continue,
            Err(_) => return,
        };

        let now = std::time::Instant::now();
        for i in 0..received {
            if let Some((packet, addr)) = batch.get(i) {
                if let Some((response, ticket)) = server.handle_packet_with_ticket(packet, now) {
                    replies.push((response, addr));
                    tickets.push(ticket);
                }
            }
        }

        let mut sent = 0;
        while sent < replies.len() {
            match socket.try_io(Interest::WRITABLE, || send_batch(fd, &replies[sent..])) {
                Ok(n) => {
                    for ticket in &mut tickets[sent..sent+n] {
                        if let Some(ticket) = ticket.take() { ticket.sent(); }
                    }
                    sent += n;
                },
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if socket.writable().await.is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                // The first remaining reply failed (e.g. unreachable): drop it
                // like the single path ignores a failed send_to.
                Err(_) => sent += 1,
            }
        }
        replies.clear();
        tickets.clear();
    }
}

async fn session_cleanup_loop(server: Arc<Server>, shutdown: CancellationToken) {
    let interval = non_zero_or(server.cfg.session_cleanup_interval(), Duration::from_secs(30));
    let mut ticker = tokio::time::interval(interval);
    let recently_closed_sweep_interval = Duration::from_secs(300);
    let mut last_recently_closed_sweep: Option<std::time::Instant> = None;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => {
                let now = std::time::Instant::now();
                let expired = server.sessions.cleanup(now, server.cfg.session_timeout(), server.cfg.closed_session_retention());
                server.sessions.sweep_terminal_streams(now, server.cfg.terminal_stream_retention());

                let should_sweep_recently_closed = last_recently_closed_sweep.map(|t| now.duration_since(t) >= recently_closed_sweep_interval).unwrap_or(true);
                if should_sweep_recently_closed {
                    server.sessions.sweep_recently_closed_streams(now);
                    last_recently_closed_sweep = Some(now);
                }

                server.invalid_cookie_tracker_cleanup(now);
                server.purge_dns_query_fragments(now);
                server.purge_socks5_syn_fragments(now);

                if !expired.is_empty() {
                    let count = expired.len();
                    for (session_id, record) in expired {
                        server.cleanup_closed_session(session_id, &record);
                    }
                    server.log.infof(&format!("Expired Sessions Cleaned, Count: {count}"));
                }
            }
        }
    }
}

fn non_zero_or(d: Duration, fallback: Duration) -> Duration {
    if d.is_zero() {
        fallback
    } else {
        d
    }
}

fn open_udp_listeners(cfg: &config::ServerConfig, reader_count: usize) -> std::io::Result<Vec<Arc<UdpSocket>>> {
    let host = if cfg.udp_host.is_empty() { "0.0.0.0" } else { &cfg.udp_host };
    let addr: SocketAddr = format!("{host}:{}", cfg.udp_port)
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid UDP_HOST/UDP_PORT: {e}")))?;

    if reader_count > 1 {
        let mut built = Vec::with_capacity(reader_count);
        let mut all_ok = true;
        for _ in 0..reader_count {
            match listen_udp_reuseport(addr, cfg.socket_buffer_size) {
                Ok(s) => built.push(s),
                Err(_) => {
                    all_ok = false;
                    break;
                }
            }
        }
        if all_ok {
            return Ok(built);
        }
    }

    let std_socket = std::net::UdpSocket::bind(addr)?;
    std_socket.set_nonblocking(true)?;
    Ok(vec![Arc::new(UdpSocket::from_std(std_socket)?)])
}

#[cfg(unix)]
fn listen_udp_reuseport(addr: SocketAddr, buffer_size: u32) -> std::io::Result<Arc<UdpSocket>> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    if buffer_size > 0 {
        let _ = socket.set_recv_buffer_size(buffer_size as usize);
        let _ = socket.set_send_buffer_size(buffer_size as usize);
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(Arc::new(UdpSocket::from_std(std_socket)?))
}

#[cfg(not(unix))]
fn listen_udp_reuseport(_addr: SocketAddr, _buffer_size: u32) -> std::io::Result<Arc<UdpSocket>> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "SO_REUSEPORT is not supported on this platform"))
}
