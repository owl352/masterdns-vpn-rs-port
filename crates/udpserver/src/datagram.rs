//! Unreliable UDP relay for sessions that selected the datagram transport
//! feature (voice/video calls, games). Each client flow gets one UDP socket;
//! replies ride the next polls at high priority and expire quickly, because
//! late audio is useless.

use crate::Server;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

const MAX_FLOWS_PER_SESSION: usize = 64;
const FLOW_IDLE: Duration = Duration::from_secs(60);
pub(crate) const DATAGRAM_TTL: Duration = Duration::from_millis(800);
pub(crate) const DATAGRAM_ASSEMBLY: Duration = Duration::from_secs(2);
const MAX_QUEUED_PACKETS: usize = 1024;
const MAX_FRAGMENTS: usize = 16;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub(crate) struct DatagramFragmentKey {
    pub session_id: u8,
    pub sequence_num: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Addr(SocketAddr),
    Domain(String, u16),
}

/// Parses `flow(2) | SOCKS5 address (ATYP, address, port) | data`.
pub(crate) fn parse_datagram(b: &[u8]) -> Option<(u16, Target, &[u8])> {
    let flow = u16::from_be_bytes([*b.first()?, *b.get(1)?]);
    let rest = &b[2..];
    let (target, used) = match *rest.first()? {
        ATYP_IPV4 => {
            let a: [u8; 4] = rest.get(1..5)?.try_into().ok()?;
            let port = u16::from_be_bytes(rest.get(5..7)?.try_into().ok()?);
            (Target::Addr(SocketAddr::new(IpAddr::from(a), port)), 7)
        }
        ATYP_IPV6 => {
            let a: [u8; 16] = rest.get(1..17)?.try_into().ok()?;
            let port = u16::from_be_bytes(rest.get(17..19)?.try_into().ok()?);
            (Target::Addr(SocketAddr::new(IpAddr::from(a), port)), 19)
        }
        ATYP_DOMAIN => {
            let n = *rest.get(1)? as usize;
            let name = std::str::from_utf8(rest.get(2..2 + n)?).ok()?.to_string();
            let port = u16::from_be_bytes(rest.get(2 + n..4 + n)?.try_into().ok()?);
            (Target::Domain(name, port), 4 + n)
        }
        _ => return None,
    };
    Some((flow, target, &rest[used..]))
}

/// Encodes a reply from `from` in the same layout as [`parse_datagram`].
pub(crate) fn encode_datagram(flow: u16, from: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(data.len() + 21);
    b.extend_from_slice(&flow.to_be_bytes());
    match from.ip().to_canonical() {
        IpAddr::V4(a) => {
            b.push(ATYP_IPV4);
            b.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            b.push(ATYP_IPV6);
            b.extend_from_slice(&a.octets());
        }
    }
    b.extend_from_slice(&from.port().to_be_bytes());
    b.extend_from_slice(data);
    b
}

/// Keeps clients from reaching the server's own host or private networks.
pub(crate) fn relay_allowed(addr: SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip().to_canonical() {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(a) => {
            let s = a.segments()[0];
            !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80)
        }
    }
}

pub(crate) struct UdpFlow {
    socket: UdpSocket,
    // Synchronous non-blocking sends: the tokio socket reports WouldBlock
    // until its first readiness event.
    sender: std::net::UdpSocket,
    dual_stack: bool,
    allow_private: bool,
    cancel: CancellationToken,
    started: Instant,
    last_active_ms: AtomicU64,
    resolved: Mutex<HashMap<String, SocketAddr>>,
}

impl UdpFlow {
    fn touch(&self) {
        self.last_active_ms.store(self.started.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    fn idle_for(&self) -> Duration {
        self.started.elapsed().saturating_sub(Duration::from_millis(self.last_active_ms.load(Ordering::Relaxed)))
    }
    fn send(&self, to: SocketAddr, data: &[u8]) {
        if !self.allow_private && !relay_allowed(to) {
            return;
        }
        let to = match to {
            SocketAddr::V4(v4) if self.dual_stack => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
            SocketAddr::V6(_) if !self.dual_stack => return,
            other => other,
        };
        self.touch();
        let _ = self.sender.send_to(data, to);
    }
}

#[derive(Default)]
pub(crate) struct Flows {
    map: Mutex<HashMap<(u8, u16), Arc<UdpFlow>>>,
}

fn bind_flow_socket() -> Option<(std::net::UdpSocket, bool)> {
    if let Ok(s) = std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)) {
        return Some((s, true));
    }
    std::net::UdpSocket::bind(("0.0.0.0", 0)).ok().map(|s| (s, false))
}

impl Server {
    pub(crate) fn handle_udp_datagram_request(&self, p: &vpnproto::Packet, now: Instant) -> bool {
        let Some(record) = self.sessions.get(p.session_id) else { return false };
        if !record.datagrams_active() {
            return false;
        }
        let key = DatagramFragmentKey { session_id: p.session_id, sequence_num: p.sequence_num };
        let assembled = match self.datagram_fragments.collect(key, &p.payload, p.fragment_id, p.total_fragments.max(1), now, DATAGRAM_ASSEMBLY) {
            fragmentstore::CollectOutcome::Complete(bytes) => bytes,
            _ => return true,
        };
        let Some((flow_id, target, data)) = parse_datagram(&assembled) else { return true };
        let Some(flow) = self.udp_flow(p.session_id, flow_id) else { return true };
        match target {
            Target::Addr(to) => flow.send(to, data),
            Target::Domain(name, port) => {
                let cached = flow.resolved.lock().unwrap().get(&name).copied();
                if let Some(to) = cached {
                    flow.send(to, data);
                } else if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    let data = data.to_vec();
                    handle.spawn(async move {
                        let Ok(mut addrs) = tokio::net::lookup_host((name.clone(), port)).await else { return };
                        if let Some(to) = addrs.find(|a| (flow.allow_private || relay_allowed(*a)) && (flow.dual_stack || a.is_ipv4())) {
                            flow.resolved.lock().unwrap().insert(name, to);
                            flow.send(to, &data);
                        }
                    });
                }
            }
        }
        true
    }

    fn udp_flow(&self, session_id: u8, flow_id: u16) -> Option<Arc<UdpFlow>> {
        let mut map = self.udp_flows.map.lock().unwrap();
        if let Some(flow) = map.get(&(session_id, flow_id)) {
            return Some(flow.clone());
        }
        if map.keys().filter(|(s, _)| *s == session_id).count() >= MAX_FLOWS_PER_SESSION {
            return None;
        }
        let handle = tokio::runtime::Handle::try_current().ok()?;
        let (std_socket, dual_stack) = bind_flow_socket()?;
        std_socket.set_nonblocking(true).ok()?;
        let sender = std_socket.try_clone().ok()?;
        let socket = {
            let _guard = handle.enter();
            UdpSocket::from_std(std_socket).ok()?
        };
        let flow = Arc::new(UdpFlow {
            socket,
            sender,
            dual_stack,
            allow_private: self.cfg.udp_relay_allow_private,
            cancel: CancellationToken::new(),
            started: Instant::now(),
            last_active_ms: AtomicU64::new(0),
            resolved: Mutex::new(HashMap::new()),
        });
        map.insert((session_id, flow_id), flow.clone());
        drop(map);

        let server = self.self_arc();
        let task_flow = flow.clone();
        handle.spawn(async move {
            let flow = task_flow;
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    _ = flow.cancel.cancelled() => break,
                    received = tokio::time::timeout(FLOW_IDLE, flow.socket.recv_from(&mut buf)) => match received {
                        Ok(Ok((n, from))) => {
                            flow.touch();
                            if !server.queue_udp_datagram(session_id, flow_id, from, &buf[..n]) && server.sessions.get(session_id).is_none() {
                                break;
                            }
                        }
                        Ok(Err(_)) => {}
                        Err(_) => if flow.idle_for() >= FLOW_IDLE { break },
                    },
                }
            }
            let mut map = server.udp_flows.map.lock().unwrap();
            if map.get(&(session_id, flow_id)).is_some_and(|f| Arc::ptr_eq(f, &flow)) {
                map.remove(&(session_id, flow_id));
            }
        });
        Some(flow)
    }

    fn queue_udp_datagram(&self, session_id: u8, flow_id: u16, from: SocketAddr, data: &[u8]) -> bool {
        let Some(record) = self.sessions.get(session_id) else { return false };
        let payload = encode_datagram(flow_id, from, data);
        let chunk_size = record.download_mtu_bytes.saturating_sub(64).max(64);
        let chunks: Vec<&[u8]> = payload.chunks(chunk_size).collect();
        if chunks.len() > MAX_FRAGMENTS {
            return false;
        }
        let sequence_num = self.datagram_seq.fetch_add(1, Ordering::Relaxed) as u16;
        let now = Instant::now();
        let mut queue = record.datagrams.lock().unwrap();
        while queue.front().is_some_and(|(at, _)| now.duration_since(*at) > DATAGRAM_TTL) {
            queue.pop_front();
        }
        if queue.len() + chunks.len() > MAX_QUEUED_PACKETS {
            return false;
        }
        for (i, chunk) in chunks.iter().enumerate() {
            queue.push_back((
                now,
                vpnproto::Packet {
                    packet_type: enums::PACKET_UDP_DATAGRAM,
                    sequence_num,
                    has_sequence_num: true,
                    fragment_id: i as u8,
                    total_fragments: chunks.len() as u8,
                    payload: chunk.to_vec(),
                    ..Default::default()
                },
            ));
        }
        true
    }

    pub(crate) fn close_udp_flows(&self, session_id: u8) {
        self.udp_flows.map.lock().unwrap().retain(|(s, _), flow| {
            if *s == session_id {
                flow.cancel.cancel();
            }
            *s != session_id
        });
        self.datagram_fragments.remove_if(|key: &DatagramFragmentKey| key.session_id == session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_framing_round_trips_and_rejects_truncation() {
        let from: SocketAddr = "203.0.113.7:50001".parse().unwrap();
        let b = encode_datagram(9, from, b"voice");
        assert_eq!(parse_datagram(&b), Some((9, Target::Addr(from), &b"voice"[..])));
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let b = encode_datagram(1, v6, b"");
        assert_eq!(parse_datagram(&b), Some((1, Target::Addr(v6), &b""[..])));
        let mut d = vec![0, 2, ATYP_DOMAIN, 7];
        d.extend_from_slice(b"example");
        d.extend_from_slice(&[0x1f, 0x90, 1, 2]);
        assert_eq!(parse_datagram(&d), Some((2, Target::Domain("example".into(), 8080), &[1u8, 2][..])));
        for n in 0..9 {
            assert!(parse_datagram(&encode_datagram(9, from, b"")[..n]).is_none());
        }
        let mapped = SocketAddr::new(IpAddr::V6("::ffff:203.0.113.7".parse().unwrap()), 50001);
        assert_eq!(encode_datagram(9, mapped, b"x"), encode_datagram(9, from, b"x"));
    }

    #[test]
    fn relay_refuses_local_and_private_destinations() {
        for bad in ["127.0.0.1:5", "10.1.2.3:5", "192.168.1.1:5", "172.16.0.1:5", "169.254.1.1:5", "100.64.0.1:5", "0.0.0.0:5", "8.8.8.8:0", "[::1]:5", "[fd00::1]:5", "[fe80::1]:5", "[::ffff:127.0.0.1]:5", "224.0.0.1:5"] {
            assert!(!relay_allowed(bad.parse().unwrap()), "{bad}");
        }
        for good in ["8.8.8.8:50000", "[2001:4860::8888]:3478"] {
            assert!(relay_allowed(good.parse().unwrap()), "{good}");
        }
    }
}
