//! Ports of `internal/enums/packet_ack.go`.

use crate::packet::*;
use std::collections::HashMap;
use std::sync::OnceLock;

/// (packet_type, ack_type) pairs — mirrors Go's `ControlAckPairs` map.
const CONTROL_ACK_PAIRS: &[(u8, u8)] = &[
    (PACKET_DNS_QUERY_REQ, PACKET_DNS_QUERY_REQ_ACK),
    (PACKET_DNS_QUERY_RES, PACKET_DNS_QUERY_RES_ACK),
    (PACKET_STREAM_SYN, PACKET_STREAM_SYN_ACK),
    (PACKET_STREAM_CONNECTED, PACKET_STREAM_CONNECTED_ACK),
    (PACKET_STREAM_CONNECT_FAIL, PACKET_STREAM_CONNECT_FAIL_ACK),
    (PACKET_STREAM_CLOSE_WRITE, PACKET_STREAM_CLOSE_WRITE_ACK),
    (PACKET_STREAM_CLOSE_READ, PACKET_STREAM_CLOSE_READ_ACK),
    (PACKET_STREAM_RST, PACKET_STREAM_RST_ACK),
    (PACKET_SOCKS5_SYN, PACKET_SOCKS5_SYN_ACK),
    (PACKET_SOCKS5_CONNECT_FAIL, PACKET_SOCKS5_CONNECT_FAIL_ACK),
    (PACKET_SOCKS5_RULESET_DENIED, PACKET_SOCKS5_RULESET_DENIED_ACK),
    (
        PACKET_SOCKS5_NETWORK_UNREACHABLE,
        PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
    ),
    (PACKET_SOCKS5_HOST_UNREACHABLE, PACKET_SOCKS5_HOST_UNREACHABLE_ACK),
    (
        PACKET_SOCKS5_CONNECTION_REFUSED,
        PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
    ),
    (PACKET_SOCKS5_TTL_EXPIRED, PACKET_SOCKS5_TTL_EXPIRED_ACK),
    (
        PACKET_SOCKS5_COMMAND_UNSUPPORTED,
        PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
    ),
    (
        PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
        PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
    ),
    (PACKET_SOCKS5_AUTH_FAILED, PACKET_SOCKS5_AUTH_FAILED_ACK),
    (
        PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
        PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
    ),
    (PACKET_SOCKS5_CONNECTED, PACKET_SOCKS5_CONNECTED_ACK),
];

/// (packet_type, ack_type) pairs that also signal stream close — mirrors `PacketsCloseStream`.
const PACKETS_CLOSE_STREAM: &[(u8, u8)] = &[
    (PACKET_STREAM_RST, PACKET_STREAM_RST_ACK),
    (PACKET_STREAM_CLOSE_WRITE, PACKET_STREAM_CLOSE_WRITE_ACK),
    (PACKET_STREAM_CLOSE_READ, PACKET_STREAM_CLOSE_READ_ACK),
    (PACKET_SOCKS5_RULESET_DENIED, PACKET_SOCKS5_RULESET_DENIED_ACK),
    (
        PACKET_SOCKS5_NETWORK_UNREACHABLE,
        PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
    ),
    (PACKET_SOCKS5_HOST_UNREACHABLE, PACKET_SOCKS5_HOST_UNREACHABLE_ACK),
    (
        PACKET_SOCKS5_CONNECTION_REFUSED,
        PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
    ),
    (PACKET_SOCKS5_TTL_EXPIRED, PACKET_SOCKS5_TTL_EXPIRED_ACK),
    (
        PACKET_SOCKS5_COMMAND_UNSUPPORTED,
        PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
    ),
    (
        PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
        PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
    ),
    (PACKET_SOCKS5_AUTH_FAILED, PACKET_SOCKS5_AUTH_FAILED_ACK),
    (
        PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
        PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
    ),
    (PACKET_STREAM_CONNECT_FAIL, PACKET_STREAM_CONNECT_FAIL_ACK),
    (PACKET_SOCKS5_CONNECT_FAIL, PACKET_SOCKS5_CONNECT_FAIL_ACK),
];

fn reverse_control_ack_pairs() -> &'static HashMap<u8, u8> {
    static MAP: OnceLock<HashMap<u8, u8>> = OnceLock::new();
    MAP.get_or_init(|| {
        CONTROL_ACK_PAIRS
            .iter()
            .map(|&(ptype, ack)| (ack, ptype))
            .collect()
    })
}

fn packets_close_stream_map() -> &'static HashMap<u8, u8> {
    static MAP: OnceLock<HashMap<u8, u8>> = OnceLock::new();
    MAP.get_or_init(|| PACKETS_CLOSE_STREAM.iter().copied().collect())
}

pub fn get_packet_close_stream(packet_type: u8) -> Option<u8> {
    packets_close_stream_map().get(&packet_type).copied()
}

pub fn control_ack_for(packet_type: u8) -> Option<u8> {
    CONTROL_ACK_PAIRS
        .iter()
        .find(|&&(ptype, _)| ptype == packet_type)
        .map(|&(_, ack)| ack)
}

pub fn reverse_control_ack_for(ack_type: u8) -> Option<u8> {
    reverse_control_ack_pairs().get(&ack_type).copied()
}
