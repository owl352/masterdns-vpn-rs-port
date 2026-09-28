//! Batched UDP receive/send for Linux: one `recvmmsg` reads up to [`BATCH`]
//! queries and one `sendmmsg` sends all their replies, instead of one
//! `recvfrom` and one `sendto` per query. Each reply keeps its own
//! destination, so a batch can answer many resolvers at once.
//!
//! Only the syscalls live here; `runtime::serve_loop` drives them through
//! tokio's readiness (`try_io`), so they never block.

use socket2::SockAddr;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::SocketAddr;
use std::os::fd::RawFd;

/// Datagrams per `recvmmsg`/`sendmmsg` call.
pub(crate) const BATCH: usize = 32;

/// Reusable receive buffers and headers for one serve task. The header
/// pointers are re-armed before every call, so the vectors can live anywhere.
pub(crate) struct RecvBatch {
    bufs: Vec<Vec<u8>>,
    addrs: Vec<libc::sockaddr_storage>,
    iovs: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>,
}

// SAFETY: the raw pointers in `iovs`/`hdrs` only ever point into this
// struct's own `bufs`/`addrs`, are re-armed before each `recv`, and are never
// shared; moving the whole struct to another thread is therefore sound.
unsafe impl Send for RecvBatch {}

impl RecvBatch {
    /// `buffer_size` is the per-datagram capacity (the old single-buffer
    /// path used the same size). Pages are only touched as data arrives, so
    /// resident memory stays small even for 64 KiB slots.
    pub(crate) fn new(buffer_size: usize) -> Self {
        RecvBatch {
            bufs: (0..BATCH).map(|_| vec![0u8; buffer_size]).collect(),
            addrs: vec![unsafe { zeroed() }; BATCH],
            iovs: vec![libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; BATCH],
            hdrs: vec![unsafe { zeroed() }; BATCH],
        }
    }

    /// Non-blocking `recvmmsg`. Returns how many datagrams arrived, or
    /// `WouldBlock` when none are pending.
    pub(crate) fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        for i in 0..BATCH {
            self.iovs[i] = libc::iovec { iov_base: self.bufs[i].as_mut_ptr().cast(), iov_len: self.bufs[i].len() };
            let hdr = &mut self.hdrs[i];
            *hdr = unsafe { zeroed() };
            hdr.msg_hdr.msg_name = (&mut self.addrs[i] as *mut libc::sockaddr_storage).cast();
            hdr.msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            hdr.msg_hdr.msg_iov = &mut self.iovs[i];
            hdr.msg_hdr.msg_iovlen = 1;
        }
        // SAFETY: every header points at buffers owned by `self` that stay
        // alive and unaliased for the duration of the call.
        let n = unsafe { libc::recvmmsg(fd, self.hdrs.as_mut_ptr(), BATCH as libc::c_uint, libc::MSG_DONTWAIT, std::ptr::null_mut()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Datagram `i` of the last [`Self::recv`] and its sender.
    pub(crate) fn get(&self, i: usize) -> Option<(&[u8], SocketAddr)> {
        let hdr = &self.hdrs[i];
        let len = (hdr.msg_len as usize).min(self.bufs[i].len());
        // SAFETY: the kernel filled `addrs[i]` and set `msg_namelen` for it.
        let addr = unsafe { SockAddr::new(self.addrs[i], hdr.msg_hdr.msg_namelen) }.as_socket()?;
        Some((&self.bufs[i][..len], addr))
    }
}

/// Non-blocking `sendmmsg` of `replies`, each to its own address. Returns how
/// many were sent from the front (at least one), or the error of the first
/// datagram (`WouldBlock` when the socket buffer is full).
pub(crate) fn send_batch(fd: RawFd, replies: &[(Vec<u8>, SocketAddr)]) -> io::Result<usize> {
    let count = replies.len().min(BATCH);
    if count == 0 {
        return Ok(0);
    }
    let addrs: Vec<SockAddr> = replies[..count].iter().map(|(_, a)| SockAddr::from(*a)).collect();
    let mut iovs: Vec<libc::iovec> = replies[..count].iter().map(|(data, _)| libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() }).collect();
    let mut hdrs: Vec<libc::mmsghdr> = (0..count)
        .map(|i| {
            let mut hdr: libc::mmsghdr = unsafe { zeroed() };
            hdr.msg_hdr.msg_name = addrs[i].as_ptr() as *mut libc::c_void;
            hdr.msg_hdr.msg_namelen = addrs[i].len();
            hdr.msg_hdr.msg_iov = &mut iovs[i];
            hdr.msg_hdr.msg_iovlen = 1;
            hdr
        })
        .collect();
    // SAFETY: headers point into `addrs`, `iovs` and `replies`, all alive for
    // the call; the kernel only reads the payloads.
    let n = unsafe { libc::sendmmsg(fd, hdrs.as_mut_ptr(), count as libc::c_uint, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn receives_a_batch_and_answers_several_senders_in_one_call() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let server_addr = server.local_addr().unwrap();
        let clients: Vec<std::net::UdpSocket> = (0..3).map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap()).collect();

        let mut rx = RecvBatch::new(65535);
        assert_eq!(rx.recv(server.as_raw_fd()).unwrap_err().kind(), io::ErrorKind::WouldBlock);

        for round in 0..20u8 {
            for (c, client) in clients.iter().enumerate() {
                client.send_to(&[round, c as u8, 0xAB], server_addr).unwrap();
            }
        }

        let mut got = Vec::new();
        while got.len() < 60 {
            let n = rx.recv(server.as_raw_fd()).unwrap();
            assert!(n >= 1 && n <= BATCH);
            for i in 0..n {
                let (data, from) = rx.get(i).unwrap();
                got.push((data.to_vec(), from));
            }
        }
        assert_eq!(got.len(), 60);
        for (c, client) in clients.iter().enumerate() {
            let mine: Vec<u8> = got.iter().filter(|(_, from)| *from == client.local_addr().unwrap()).map(|(d, _)| d[0]).collect();
            assert_eq!(mine, (0..20).collect::<Vec<u8>>(), "client {c}: order or content wrong");
        }

        // Answer everything; replies go back to three different addresses.
        let replies: Vec<(Vec<u8>, SocketAddr)> = got.iter().map(|(d, from)| (vec![d[0], d[1], 0xCD], *from)).collect();
        let mut sent = 0;
        while sent < replies.len() {
            sent += send_batch(server.as_raw_fd(), &replies[sent..]).unwrap();
        }
        for (c, client) in clients.iter().enumerate() {
            client.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            for round in 0..20u8 {
                let mut buf = [0u8; 16];
                let (n, from) = client.recv_from(&mut buf).unwrap();
                assert_eq!(from, server_addr);
                assert_eq!(&buf[..n], &[round, c as u8, 0xCD]);
            }
        }
    }
}
