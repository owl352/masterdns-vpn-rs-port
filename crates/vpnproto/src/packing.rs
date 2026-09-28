//! Port of `internal/vpnproto/packing.go`.

use enums::*;

/// Fixed size of each block inside a `PACKET_PACKED_CONTROL_BLOCKS` (Type 14) payload.
/// Structure: `Type(1) + StreamID(2) + SeqNum(2) + FragID(1) + Total(1)` = 7 bytes.
pub const PACKED_CONTROL_BLOCK_SIZE: usize = 7;

/// Returns true if a packet type is eligible for packing. Only control
/// packets without payload should be packed.
pub fn is_packable_control_packet(packet_type: u8, payload_len: usize) -> bool {
    if payload_len != 0 {
        return false;
    }

    matches!(
        packet_type,
        PACKET_STREAM_DATA_ACK
            | PACKET_STREAM_DATA_NACK
            | PACKET_STREAM_SYN_ACK
            | PACKET_STREAM_CLOSE_WRITE_ACK
            | PACKET_STREAM_CLOSE_READ_ACK
            | PACKET_STREAM_RST_ACK
            | PACKET_SOCKS5_SYN_ACK
            | PACKET_STREAM_CONNECTED
            | PACKET_STREAM_CONNECTED_ACK
            | PACKET_STREAM_CONNECT_FAIL
            | PACKET_STREAM_CONNECT_FAIL_ACK
            | PACKET_SOCKS5_CONNECT_FAIL
            | PACKET_SOCKS5_RULESET_DENIED
            | PACKET_SOCKS5_NETWORK_UNREACHABLE
            | PACKET_SOCKS5_HOST_UNREACHABLE
            | PACKET_SOCKS5_CONNECTION_REFUSED
            | PACKET_SOCKS5_TTL_EXPIRED
            | PACKET_SOCKS5_COMMAND_UNSUPPORTED
            | PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED
            | PACKET_SOCKS5_AUTH_FAILED
            | PACKET_SOCKS5_UPSTREAM_UNAVAILABLE
            | PACKET_SOCKS5_CONNECTED
            | PACKET_SOCKS5_CONNECTED_ACK
            | PACKET_SOCKS5_CONNECT_FAIL_ACK
            | PACKET_SOCKS5_RULESET_DENIED_ACK
            | PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK
            | PACKET_SOCKS5_HOST_UNREACHABLE_ACK
            | PACKET_SOCKS5_CONNECTION_REFUSED_ACK
            | PACKET_SOCKS5_TTL_EXPIRED_ACK
            | PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK
            | PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK
            | PACKET_SOCKS5_AUTH_FAILED_ACK
            | PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK
            | PACKET_DNS_QUERY_REQ_ACK
            | PACKET_DNS_QUERY_RES_ACK
    )
}

/// Serializes a control packet's metadata into a 7-byte block and appends it to `dst`.
pub fn append_packed_control_block(
    dst: &mut Vec<u8>,
    ptype: u8,
    stream_id: u16,
    sn: u16,
    frag_id: u8,
    total: u8,
) {
    dst.push(ptype);
    dst.push((stream_id >> 8) as u8);
    dst.push(stream_id as u8);
    dst.push((sn >> 8) as u8);
    dst.push(sn as u8);
    dst.push(frag_id);
    dst.push(total);
}

/// Iterates over a Type 14 payload and invokes `yield_fn` for each block.
/// `yield_fn` returns `false` to stop iteration early.
pub fn for_each_packed_control_block(
    payload: &[u8],
    mut yield_fn: impl FnMut(u8, u16, u16, u8, u8) -> bool,
) {
    let mut offset = 0usize;
    while offset + PACKED_CONTROL_BLOCK_SIZE <= payload.len() {
        let ptype = payload[offset];
        let stream_id = (payload[offset + 1] as u16) << 8 | payload[offset + 2] as u16;
        let sn = (payload[offset + 3] as u16) << 8 | payload[offset + 4] as u16;
        let frag_id = payload[offset + 5];
        let total = payload[offset + 6];

        if !yield_fn(ptype, stream_id, sn, frag_id, total) {
            break;
        }
        offset += PACKED_CONTROL_BLOCK_SIZE;
    }
}

/// Returns a compact summary suitable for logs, e.g.
/// `"Blocks(4): PACKET_STREAM_DATA_ACK x2, PACKET_STREAM_DATA_NACK x1, PACKET_STREAM_CLOSE_WRITE_ACK x1"`.
pub fn describe_packed_control_blocks(payload: &[u8], max_kinds: usize) -> String {
    if payload.is_empty() {
        return "Blocks(0)".to_string();
    }
    let max_kinds = if max_kinds == 0 { 4 } else { max_kinds };

    let mut order: Vec<u8> = Vec::with_capacity(max_kinds);
    let mut counts: std::collections::HashMap<u8, usize> = std::collections::HashMap::new();
    let mut total_blocks = 0usize;

    for_each_packed_control_block(payload, |ptype, _, _, _, _| {
        total_blocks += 1;
        if !counts.contains_key(&ptype) {
            order.push(ptype);
        }
        *counts.entry(ptype).or_insert(0) += 1;
        true
    });

    if total_blocks == 0 {
        return "Blocks(0)".to_string();
    }

    let mut out = String::new();
    out.push_str("Blocks(");
    out.push_str(&total_blocks.to_string());
    out.push_str("): ");

    let limit = order.len().min(max_kinds);
    for (i, &ptype) in order[..limit].iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&enums::packet_type_name(ptype));
        out.push_str(" x");
        out.push_str(&counts[&ptype].to_string());
    }

    if order.len() > limit {
        out.push_str(", +");
        out.push_str(&(order.len() - limit).to_string());
        out.push_str(" more types");
    }

    out
}
