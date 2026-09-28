//! Port of `internal/vpnproto/parser.go`.

use crate::flags::*;
use crate::VpnProtoError;
use security::Codec;

/// Header layout copied from the Python parser, with one change:
/// `total_data_length` has been removed from the fragment extension.
///
/// Base header:
///   `[0] Session ID     (1 byte)`
///   `[1] Packet Type    (1 byte)`
///
/// Optional extensions by packet type:
///   Stream extension:     `[2..3] Stream ID (2 bytes)`
///   Sequence extension:   `[+2]   Sequence Number (2 bytes)`
///   Fragment extension:   `[+1]   Fragment ID (1 byte)`, `[+1] Total Fragments (1 byte)`
///   Compression extension: `[+1]  Compression Type (1 byte)`
///
/// Integrity footer: `[+1] Session Cookie (1 byte)`, `[+1] Header Check (1 byte)`.
/// Payload starts immediately after the header check byte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Packet {
    pub session_id: u8,
    pub packet_type: u8,
    pub session_cookie: u8,

    pub has_stream_id: bool,
    pub stream_id: u16,

    pub has_sequence_num: bool,
    pub sequence_num: u16,

    pub has_fragment_info: bool,
    pub fragment_id: u8,
    pub total_fragments: u8,

    pub has_compression_type: bool,
    pub compression_type: u8,

    pub header_length: usize,
    pub payload: Vec<u8>,
}

pub fn parse_from_labels(labels: &str, codec: Option<&Codec>) -> Result<Packet, VpnProtoError> {
    let codec = codec.ok_or(VpnProtoError::CodecUnavailable)?;
    if labels.is_empty() {
        return Err(VpnProtoError::InvalidEncodedData);
    }

    let raw = codec
        .decode_string_and_decrypt(labels)
        .map_err(|_| VpnProtoError::InvalidEncodedData)?;

    parse(&raw)
}

pub fn parse(data: &[u8]) -> Result<Packet, VpnProtoError> {
    parse_at_offset(data, 0)
}

pub fn parse_at_offset(data: &[u8], offset: usize) -> Result<Packet, VpnProtoError> {
    if offset >= data.len() {
        return Err(VpnProtoError::PacketTooShort);
    }
    parse_from(data, offset)
}

fn parse_from(data: &[u8], start: usize) -> Result<Packet, VpnProtoError> {
    let data = &data[start..];
    if data.len() < MIN_HEADER_LENGTH {
        return Err(VpnProtoError::PacketTooShort);
    }

    let packet_type = data[1];
    let flags = packet_flags()[packet_type as usize];
    if flags & FLAG_VALID == 0 {
        return Err(VpnProtoError::InvalidPacketType);
    }

    let mut min_len = 2 + INTEGRITY_LENGTH;
    if flags & FLAG_STREAM != 0 {
        min_len += 2;
    }
    if flags & FLAG_SEQUENCE != 0 {
        min_len += 2;
    }
    if flags & FLAG_FRAGMENT != 0 {
        min_len += 2;
    }
    if flags & FLAG_COMPRESSION != 0 {
        min_len += 1;
    }

    if data.len() < min_len {
        return Err(VpnProtoError::PacketTooShort);
    }

    let mut packet = Packet {
        session_id: data[0],
        packet_type,
        ..Default::default()
    };

    let mut offset = 2usize;
    if flags & FLAG_STREAM != 0 {
        packet.has_stream_id = true;
        packet.stream_id = (data[offset] as u16) << 8 | data[offset + 1] as u16;
        offset += 2;
    }

    if flags & FLAG_SEQUENCE != 0 {
        packet.has_sequence_num = true;
        packet.sequence_num = (data[offset] as u16) << 8 | data[offset + 1] as u16;
        offset += 2;
    }

    if flags & FLAG_FRAGMENT != 0 {
        packet.has_fragment_info = true;
        packet.fragment_id = data[offset];
        packet.total_fragments = data[offset + 1];
        offset += 2;
    }

    if flags & FLAG_COMPRESSION != 0 {
        packet.has_compression_type = true;
        packet.compression_type = data[offset];
        offset += 1;
    }

    packet.session_cookie = data[offset];
    let check_byte = data[offset + 1];
    let expected = compute_header_check_byte(&data[..offset + 1]);
    if check_byte != expected {
        return Err(VpnProtoError::InvalidHeaderCheck);
    }

    packet.header_length = offset + INTEGRITY_LENGTH;
    packet.payload = data[packet.header_length..].to_vec();
    Ok(packet)
}

pub(crate) fn compute_header_check_byte(header: &[u8]) -> u8 {
    let mut acc = (header.len() as u8).wrapping_mul(17).wrapping_add(0x5D);
    for (idx, &value) in header.iter().enumerate() {
        acc = acc.wrapping_add(value).wrapping_add(idx as u8);
        acc ^= value.wrapping_shl((idx & 0x03) as u32);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_raw, BuildOptions};

    #[test]
    fn build_then_parse_round_trip() {
        let opts = BuildOptions {
            session_id: 7,
            packet_type: enums::PACKET_STREAM_DATA,
            session_cookie: 42,
            stream_id: 100,
            sequence_num: 200,
            fragment_id: 1,
            total_fragments: 3,
            compression_type: 0,
            payload: b"hello".to_vec(),
        };
        let raw = build_raw(&opts).unwrap();
        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed.session_id, 7);
        assert_eq!(parsed.packet_type, enums::PACKET_STREAM_DATA);
        assert_eq!(parsed.session_cookie, 42);
        assert_eq!(parsed.stream_id, 100);
        assert_eq!(parsed.sequence_num, 200);
        assert_eq!(parsed.fragment_id, 1);
        assert_eq!(parsed.total_fragments, 3);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn corrupted_header_check_is_rejected() {
        let opts = BuildOptions {
            session_id: 1,
            packet_type: enums::PACKET_PING,
            session_cookie: 1,
            ..Default::default()
        };
        let mut raw = build_raw(&opts).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        assert_eq!(parse(&raw).unwrap_err(), VpnProtoError::InvalidHeaderCheck);
    }
}
