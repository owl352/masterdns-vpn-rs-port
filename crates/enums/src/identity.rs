//! Ports of `internal/enums/packet_identity.go`.

use crate::packet::*;

/// Builds the queue/deduplication key for stream-owned packets.
/// DATA and RESEND intentionally remain distinct so retransmits can live in
/// their own priority lane while enqueue policy decides coexistence.
pub fn packet_identity_key(stream_id: u16, packet_type: u8, sequence_num: u16, fragment_id: u8) -> u64 {
    match packet_type {
        PACKET_STREAM_DATA
        | PACKET_STREAM_RESEND
        | PACKET_STREAM_DATA_ACK
        | PACKET_STREAM_DATA_NACK
        | PACKET_STREAM_SYN
        | PACKET_STREAM_SYN_ACK
        | PACKET_SOCKS5_SYN
        | PACKET_SOCKS5_SYN_ACK
        | PACKET_DNS_QUERY_REQ
        | PACKET_DNS_QUERY_REQ_ACK
        | PACKET_DNS_QUERY_RES
        | PACKET_DNS_QUERY_RES_ACK => packet_identity_seq_frag(stream_id, packet_type, sequence_num, fragment_id),

        PACKET_STREAM_CLOSE_WRITE
        | PACKET_STREAM_CLOSE_WRITE_ACK
        | PACKET_STREAM_CLOSE_READ
        | PACKET_STREAM_CLOSE_READ_ACK
        | PACKET_STREAM_RST
        | PACKET_STREAM_RST_ACK
        | PACKET_STREAM_CONNECTED
        | PACKET_STREAM_CONNECTED_ACK
        | PACKET_STREAM_CONNECT_FAIL
        | PACKET_STREAM_CONNECT_FAIL_ACK
        | PACKET_SOCKS5_CONNECT_FAIL
        | PACKET_SOCKS5_CONNECT_FAIL_ACK
        | PACKET_SOCKS5_RULESET_DENIED
        | PACKET_SOCKS5_RULESET_DENIED_ACK
        | PACKET_SOCKS5_NETWORK_UNREACHABLE
        | PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK
        | PACKET_SOCKS5_HOST_UNREACHABLE
        | PACKET_SOCKS5_HOST_UNREACHABLE_ACK
        | PACKET_SOCKS5_CONNECTION_REFUSED
        | PACKET_SOCKS5_CONNECTION_REFUSED_ACK
        | PACKET_SOCKS5_TTL_EXPIRED
        | PACKET_SOCKS5_TTL_EXPIRED_ACK
        | PACKET_SOCKS5_COMMAND_UNSUPPORTED
        | PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK
        | PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED
        | PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK
        | PACKET_SOCKS5_AUTH_FAILED
        | PACKET_SOCKS5_AUTH_FAILED_ACK
        | PACKET_SOCKS5_UPSTREAM_UNAVAILABLE
        | PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK
        | PACKET_SOCKS5_CONNECTED
        | PACKET_SOCKS5_CONNECTED_ACK
        | PACKET_PACKED_CONTROL_BLOCKS
        | PACKET_ERROR_DROP
        | PACKET_PING
        | PACKET_PONG => packet_identity_seq(stream_id, packet_type, sequence_num),

        PACKET_SESSION_CLOSE | PACKET_SESSION_BUSY => packet_type_stream_key(stream_id, packet_type),

        _ => packet_identity_seq_frag(stream_id, packet_type, sequence_num, fragment_id),
    }
}

/// Coarser identity for cases where the packet type is unique per stream and
/// sequence/fragment should be ignored, such as orphan fallback resets.
pub fn packet_type_stream_key(stream_id: u16, packet_type: u8) -> u64 {
    (stream_id as u64) << 40 | (packet_type as u64) << 32
}

fn packet_identity_seq(stream_id: u16, packet_type: u8, sequence_num: u16) -> u64 {
    (stream_id as u64) << 40 | (packet_type as u64) << 32 | (sequence_num as u64) << 8
}

fn packet_identity_seq_frag(stream_id: u16, packet_type: u8, sequence_num: u16, fragment_id: u8) -> u64 {
    (stream_id as u64) << 40 | (packet_type as u64) << 32 | (sequence_num as u64) << 8 | (fragment_id as u64)
}
