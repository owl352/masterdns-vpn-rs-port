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

fn header_flags_and_len(packet_type: u8) -> Result<(u8, usize), VpnProtoError> {
    let flags = packet_flags()[packet_type as usize];
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
    Ok((flags, header_len))
}

/// Writes everything before the payload into `buf[..header_len]` (`buf` must
/// be at least that long) and returns `header_len`. Shared by [`build_raw`]
/// and [`build_raw_header`], which otherwise duplicated this field layout.
#[allow(clippy::too_many_arguments)]
fn write_header_fields(
    buf: &mut [u8],
    flags: u8,
    session_id: u8,
    packet_type: u8,
    session_cookie: u8,
    stream_id: u16,
    sequence_num: u16,
    fragment_id: u8,
    total_fragments: u8,
    compression_type: u8,
) -> usize {
    buf[0] = session_id;
    buf[1] = packet_type;
    let mut offset = 2usize;

    if flags & FLAG_STREAM != 0 {
        buf[offset] = (stream_id >> 8) as u8;
        buf[offset + 1] = stream_id as u8;
        offset += 2;
    }
    if flags & FLAG_SEQUENCE != 0 {
        buf[offset] = (sequence_num >> 8) as u8;
        buf[offset + 1] = sequence_num as u8;
        offset += 2;
    }
    if flags & FLAG_FRAGMENT != 0 {
        buf[offset] = fragment_id;
        buf[offset + 1] = total_fragments;
        offset += 2;
    }
    if flags & FLAG_COMPRESSION != 0 {
        buf[offset] = compression_type;
        offset += 1;
    }

    buf[offset] = session_cookie;
    offset += 1;
    buf[offset] = compute_header_check_byte(&buf[..offset]);
    offset += 1;
    offset
}

pub fn build_raw(opts: &BuildOptions) -> Result<Vec<u8>, VpnProtoError> {
    let (flags, header_len) = header_flags_and_len(opts.packet_type)?;

    let mut raw = vec![0u8; header_len + opts.payload.len()];
    write_header_fields(
        &mut raw[..header_len],
        flags,
        opts.session_id,
        opts.packet_type,
        opts.session_cookie,
        opts.stream_id,
        opts.sequence_num,
        opts.fragment_id,
        opts.total_fragments,
        opts.compression_type,
    );
    raw[header_len..].copy_from_slice(&opts.payload);
    Ok(raw)
}

/// Upper bound on [`header_raw_size`] across all packet types (base 2 +
/// 2-byte integrity footer + stream(2) + sequence(2) + fragment(2) +
/// compression(1) = 11), rounded up for headroom.
pub const MAX_HEADER_RAW_SIZE: usize = 16;

/// A raw frame header (everything before the payload), built without
/// allocating: callers that already hold the payload as a borrowed slice can
/// write header and payload separately into their own destination buffer
/// instead of paying for [`build_raw`]'s owned `Vec` (see
/// `dnsparser::build_vpn_response_packet`).
#[derive(Debug, Clone, Copy)]
pub struct RawHeader {
    buf: [u8; MAX_HEADER_RAW_SIZE],
    len: u8,
}

impl RawHeader {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

/// Fields needed to build just the header, i.e. [`BuildOptions`] without the
/// payload (which the caller of [`build_raw_header`] keeps borrowed).
#[derive(Debug, Clone, Copy, Default)]
pub struct BuildHeaderOptions {
    pub session_id: u8,
    pub packet_type: u8,
    pub session_cookie: u8,
    pub stream_id: u16,
    pub sequence_num: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    pub compression_type: u8,
}

pub fn build_raw_header(opts: &BuildHeaderOptions) -> Result<RawHeader, VpnProtoError> {
    let (flags, header_len) = header_flags_and_len(opts.packet_type)?;
    debug_assert!(header_len <= MAX_HEADER_RAW_SIZE);
    let mut buf = [0u8; MAX_HEADER_RAW_SIZE];
    let written = write_header_fields(
        &mut buf[..header_len],
        flags,
        opts.session_id,
        opts.packet_type,
        opts.session_cookie,
        opts.stream_id,
        opts.sequence_num,
        opts.fragment_id,
        opts.total_fragments,
        opts.compression_type,
    );
    debug_assert_eq!(written, header_len);
    Ok(RawHeader { buf, len: header_len as u8 })
}

pub fn build_encoded(opts: &BuildOptions, codec: Option<&Codec>) -> Result<String, VpnProtoError> {
    let raw = build_raw(opts)?;
    let codec = codec.ok_or(VpnProtoError::CodecUnavailable)?;
    codec.encrypt_and_encode(&raw).map_err(|_| VpnProtoError::CodecUnavailable)
}

pub fn header_raw_size(packet_type: u8) -> usize {
    header_flags_and_len(packet_type).map(|(_, len)| len).unwrap_or(0)
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

#[cfg(test)]
mod header_split_tests {
    use super::*;

    #[test]
    fn max_header_raw_size_bound_holds() {
        assert!(max_header_raw_size() <= MAX_HEADER_RAW_SIZE);
    }

    #[test]
    fn build_raw_header_matches_build_raw_prefix() {
        for packet_type in 0..=255u8 {
            if header_raw_size(packet_type) == 0 {
                continue;
            }
            let opts = BuildOptions {
                session_id: 7,
                packet_type,
                session_cookie: 42,
                stream_id: 0x1234,
                sequence_num: 0x5678,
                fragment_id: 3,
                total_fragments: 9,
                compression_type: 2,
                payload: b"the quick brown fox".to_vec(),
            };
            let raw = build_raw(&opts).unwrap();

            let header_opts = BuildHeaderOptions {
                session_id: opts.session_id,
                packet_type: opts.packet_type,
                session_cookie: opts.session_cookie,
                stream_id: opts.stream_id,
                sequence_num: opts.sequence_num,
                fragment_id: opts.fragment_id,
                total_fragments: opts.total_fragments,
                compression_type: opts.compression_type,
            };
            let header = build_raw_header(&header_opts).unwrap();

            let header_len = header_raw_size(packet_type);
            assert_eq!(header.as_slice(), &raw[..header_len], "packet_type {packet_type}");
            assert_eq!(&raw[header_len..], &opts.payload[..], "packet_type {packet_type}");
        }
    }

    #[test]
    fn build_raw_header_rejects_invalid_packet_type() {
        assert!(build_raw_header(&BuildHeaderOptions { packet_type: 0, ..Default::default() }).is_err());
    }
}
