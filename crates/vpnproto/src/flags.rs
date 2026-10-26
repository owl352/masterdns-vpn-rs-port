//! Per-packet-type header extension flags, ported from the `packetFlags` table
//! built in `internal/vpnproto/{builder,parser}.go`.

use std::sync::OnceLock;

pub(crate) const INTEGRITY_LENGTH: usize = 2;
pub(crate) const MIN_HEADER_LENGTH: usize = 4;

pub(crate) const FLAG_VALID: u8 = 1 << 0;
pub(crate) const FLAG_STREAM: u8 = 1 << 1;
pub(crate) const FLAG_SEQUENCE: u8 = 1 << 2;
pub(crate) const FLAG_FRAGMENT: u8 = 1 << 3;
pub(crate) const FLAG_COMPRESSION: u8 = 1 << 4;

pub(crate) fn packet_flags() -> &'static [u8; 256] {
    static FLAGS: OnceLock<[u8; 256]> = OnceLock::new();
    FLAGS.get_or_init(build_packet_flags)
}

pub fn has_stream_extension(packet_type: u8) -> bool {
    packet_flags()[packet_type as usize] & FLAG_STREAM != 0
}

pub fn has_sequence_extension(packet_type: u8) -> bool {
    packet_flags()[packet_type as usize] & FLAG_SEQUENCE != 0
}

pub fn has_fragment_extension(packet_type: u8) -> bool {
    packet_flags()[packet_type as usize] & FLAG_FRAGMENT != 0
}

pub fn has_compression_extension(packet_type: u8) -> bool {
    packet_flags()[packet_type as usize] & FLAG_COMPRESSION != 0
}

fn build_packet_flags() -> [u8; 256] {
    use enums::*;

    let mut flags = [0u8; 256];

    let valid_only: &[u8] = &[
        PACKET_MTU_UP_RES,
        PACKET_MTU_DOWN_REQ,
        PACKET_SESSION_INIT,
        PACKET_TRANSPORT_CAPS,
        PACKET_TRANSPORT_CAPS_ACK,
        PACKET_SESSION_ACCEPT,
        PACKET_SESSION_BUSY,
        PACKET_SESSION_CLOSE,
        PACKET_PING,
        PACKET_PONG,
        PACKET_ERROR_DROP,
        PACKET_MTU_UP_REQ,
        PACKET_MTU_DOWN_RES,
    ];
    for &pt in valid_only {
        flags[pt as usize] |= FLAG_VALID;
    }

    flags[PACKET_STREAM_ENVELOPE as usize] = FLAG_VALID | FLAG_STREAM | FLAG_SEQUENCE | FLAG_FRAGMENT | FLAG_COMPRESSION;
    flags[PACKET_STREAM_FEEDBACK as usize] = FLAG_VALID | FLAG_COMPRESSION;
    flags[PACKET_UDP_DATAGRAM as usize] = FLAG_VALID | FLAG_STREAM | FLAG_SEQUENCE | FLAG_FRAGMENT;

    let stream_and_seq: &[u8] = &[
        PACKET_STREAM_SYN,
        PACKET_STREAM_SYN_ACK,
        PACKET_STREAM_DATA,
        PACKET_STREAM_DATA_ACK,
        PACKET_STREAM_DATA_NACK,
        PACKET_STREAM_RESEND,
        PACKET_STREAM_CLOSE_WRITE,
        PACKET_STREAM_CLOSE_WRITE_ACK,
        PACKET_STREAM_CLOSE_READ,
        PACKET_STREAM_CLOSE_READ_ACK,
        PACKET_STREAM_RST,
        PACKET_STREAM_RST_ACK,
        PACKET_MTU_UP_REQ,
        PACKET_MTU_DOWN_RES,
        PACKET_SOCKS5_SYN,
        PACKET_SOCKS5_SYN_ACK,
        PACKET_STREAM_CONNECTED,
        PACKET_STREAM_CONNECTED_ACK,
        PACKET_STREAM_CONNECT_FAIL,
        PACKET_STREAM_CONNECT_FAIL_ACK,
        PACKET_SOCKS5_CONNECT_FAIL,
        PACKET_SOCKS5_CONNECT_FAIL_ACK,
        PACKET_SOCKS5_RULESET_DENIED,
        PACKET_SOCKS5_RULESET_DENIED_ACK,
        PACKET_SOCKS5_NETWORK_UNREACHABLE,
        PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
        PACKET_SOCKS5_HOST_UNREACHABLE,
        PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
        PACKET_SOCKS5_CONNECTION_REFUSED,
        PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
        PACKET_SOCKS5_TTL_EXPIRED,
        PACKET_SOCKS5_TTL_EXPIRED_ACK,
        PACKET_SOCKS5_COMMAND_UNSUPPORTED,
        PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
        PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
        PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
        PACKET_SOCKS5_AUTH_FAILED,
        PACKET_SOCKS5_AUTH_FAILED_ACK,
        PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
        PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
        PACKET_SOCKS5_CONNECTED,
        PACKET_SOCKS5_CONNECTED_ACK,
        PACKET_DNS_QUERY_REQ,
        PACKET_DNS_QUERY_RES,
        PACKET_DNS_QUERY_REQ_ACK,
        PACKET_DNS_QUERY_RES_ACK,
    ];
    for &pt in stream_and_seq {
        flags[pt as usize] |= FLAG_VALID | FLAG_STREAM | FLAG_SEQUENCE;
    }

    let frag: &[u8] = &[
        PACKET_STREAM_DATA,
        PACKET_STREAM_RESEND,
        PACKET_SOCKS5_SYN,
        PACKET_DNS_QUERY_REQ,
        PACKET_DNS_QUERY_RES,
        PACKET_DNS_QUERY_REQ_ACK,
        PACKET_DNS_QUERY_RES_ACK,
        PACKET_MTU_UP_REQ,
        PACKET_MTU_DOWN_RES,
    ];
    for &pt in frag {
        flags[pt as usize] |= FLAG_FRAGMENT;
    }

    let comp: &[u8] = &[
        PACKET_STREAM_DATA,
        PACKET_STREAM_RESEND,
        PACKET_PACKED_CONTROL_BLOCKS,
        PACKET_DNS_QUERY_REQ,
        PACKET_DNS_QUERY_RES,
        PACKET_MTU_UP_REQ,
        PACKET_MTU_DOWN_RES,
    ];
    for &pt in comp {
        flags[pt as usize] |= FLAG_VALID | FLAG_COMPRESSION;
    }

    flags
}
