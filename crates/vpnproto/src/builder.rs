//! Port of `internal/vpnproto/builder.go`.

use crate::flags::*;
use crate::parser::compute_header_check_byte;
use crate::VpnProtoError;
use security::Codec;

#[derive(Debug, Clone, Default)]
pub struct BuildOptions {
    pub session_id: u8,
    pub packet_type: u8,
    pub session_cookie: u8,
    pub stream_id: u16,
    pub sequence_num: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    pub compression_type: u8,
    pub payload: Vec<u8>,
}

pub fn build_raw(opts: &BuildOptions) -> Result<Vec<u8>, VpnProtoError> {
    let flags = packet_flags()[opts.packet_type as usize];
    if flags & FLAG_VALID == 0 {
        return Err(VpnProtoError::InvalidPacketType);
    }

    let mut header_len = 2 + INTEGRITY_LENGTH;
    if flags & FLAG_STREAM != 0 {
        header_len += 2;
    }
    if flags & FLAG_SEQUENCE != 0 {
        header_len += 2;
    }
    if flags & FLAG_FRAGMENT != 0 {
        header_len += 2;
    }
    if flags & FLAG_COMPRESSION != 0 {
        header_len += 1;
    }

    let mut raw = vec![0u8; header_len + opts.payload.len()];
    raw[0] = opts.session_id;
    raw[1] = opts.packet_type;
    let mut offset = 2usize;

    if flags & FLAG_STREAM != 0 {
        raw[offset] = (opts.stream_id >> 8) as u8;
        raw[offset + 1] = opts.stream_id as u8;
        offset += 2;
    }
    if flags & FLAG_SEQUENCE != 0 {
        raw[offset] = (opts.sequence_num >> 8) as u8;
        raw[offset + 1] = opts.sequence_num as u8;
        offset += 2;
    }
    if flags & FLAG_FRAGMENT != 0 {
        raw[offset] = opts.fragment_id;
        raw[offset + 1] = opts.total_fragments;
        offset += 2;
    }
    if flags & FLAG_COMPRESSION != 0 {
        raw[offset] = opts.compression_type;
        offset += 1;
    }

    raw[offset] = opts.session_cookie;
    offset += 1;
    raw[offset] = compute_header_check_byte(&raw[..offset]);
    offset += 1;
    raw[offset..].copy_from_slice(&opts.payload);
    Ok(raw)
}

pub fn build_encoded(opts: &BuildOptions, codec: Option<&Codec>) -> Result<String, VpnProtoError> {
    let raw = build_raw(opts)?;
    let codec = codec.ok_or(VpnProtoError::CodecUnavailable)?;
    codec.encrypt_and_encode(&raw).map_err(|_| VpnProtoError::CodecUnavailable)
}

pub fn header_raw_size(packet_type: u8) -> usize {
    let flags = packet_flags()[packet_type as usize];
    if flags & FLAG_VALID == 0 {
        return 0;
    }

    let mut size = 2 + INTEGRITY_LENGTH;
    if flags & FLAG_STREAM != 0 {
        size += 2;
    }
    if flags & FLAG_SEQUENCE != 0 {
        size += 2;
    }
    if flags & FLAG_FRAGMENT != 0 {
        size += 2;
    }
    if flags & FLAG_COMPRESSION != 0 {
        size += 1;
    }
    size
}

pub fn max_header_raw_size() -> usize {
    (0..=255).map(header_raw_size).max().unwrap_or(0)
}

pub fn max_header_packet_type() -> u8 {
    let mut best_type = 0u8;
    let mut max_size = 0usize;
    for packet_type in 0..=255u8 {
        let size = header_raw_size(packet_type);
        if size > max_size {
            max_size = size;
            best_type = packet_type;
        }
        if packet_type == 255 {
            break;
        }
    }
    best_type
}
