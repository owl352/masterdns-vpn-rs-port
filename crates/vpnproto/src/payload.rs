//! Port of `internal/vpnproto/payload.go`.

use crate::flags::has_compression_extension;
use crate::parser::{parse, parse_from_labels, parse_from_labels_into};
use crate::{build_raw, BuildOptions, Packet, VpnProtoError};
use security::Codec;
use std::borrow::Cow;

pub fn prepare_payload(packet_type: u8, payload: &[u8], requested_compression: u8, min_size: usize) -> (Vec<u8>, u8) {
    let requested_compression = compression::normalize_available_type(requested_compression);
    if requested_compression == compression::TYPE_OFF {
        return (payload.to_vec(), compression::TYPE_OFF);
    }

    if !has_compression_extension(packet_type) {
        return (payload.to_vec(), compression::TYPE_OFF);
    }
    if payload.is_empty() {
        return (payload.to_vec(), compression::TYPE_OFF);
    }
    compression::compress_payload(payload, requested_compression, min_size)
}

/// Same decision as [`prepare_payload`], but borrows `payload` instead of
/// cloning it in every branch that ends up not compressing (the common case
/// on the request path: most packet types don't carry the compression
/// extension, and short payloads stay under `min_size`). Only allocates when
/// compression actually runs and helps.
pub fn prepare_payload_cow<'a>(packet_type: u8, payload: &'a [u8], requested_compression: u8, min_size: usize) -> (Cow<'a, [u8]>, u8) {
    let requested_compression = compression::normalize_available_type(requested_compression);
    if requested_compression == compression::TYPE_OFF {
        return (Cow::Borrowed(payload), compression::TYPE_OFF);
    }
    if !has_compression_extension(packet_type) {
        return (Cow::Borrowed(payload), compression::TYPE_OFF);
    }
    if payload.is_empty() {
        return (Cow::Borrowed(payload), compression::TYPE_OFF);
    }
    // Mirrors compress_payload's own min_size short-circuit, so we can skip
    // its unconditional `data.to_vec()` in that branch too.
    let effective_min_size = if min_size == 0 { compression::DEFAULT_MIN_SIZE } else { min_size };
    if payload.len() <= effective_min_size {
        return (Cow::Borrowed(payload), compression::TYPE_OFF);
    }
    let (compressed, ctype) = compression::compress_payload(payload, requested_compression, min_size);
    if ctype == compression::TYPE_OFF {
        // Compression didn't help; compress_payload's `compressed` here is
        // just a redundant clone of `payload` - drop it and borrow instead.
        (Cow::Borrowed(payload), compression::TYPE_OFF)
    } else {
        (Cow::Owned(compressed), ctype)
    }
}

pub fn inflate_payload(mut packet: Packet) -> Result<Packet, VpnProtoError> {
    if !packet.has_compression_type || packet.compression_type == compression::TYPE_OFF {
        return Ok(packet);
    }

    let payload = compression::try_decompress_payload(&packet.payload, packet.compression_type)
        .ok_or(VpnProtoError::InvalidCompressedPayload)?;
    packet.payload = payload;
    Ok(packet)
}

pub fn parse_inflated_from_labels(labels: &str, codec: Option<&Codec>) -> Result<Packet, VpnProtoError> {
    let packet = parse_from_labels(labels, codec)?;
    inflate_payload(packet)
}

/// Same result as [`parse_inflated_from_labels`], but via
/// [`parse_from_labels_into`] - see that function's docs.
pub fn parse_inflated_from_labels_into(labels: &str, codec: Option<&Codec>, scratch: &mut Vec<u8>) -> Result<Packet, VpnProtoError> {
    let packet = parse_from_labels_into(labels, codec, scratch)?;
    inflate_payload(packet)
}

pub fn parse_inflated(data: &[u8]) -> Result<Packet, VpnProtoError> {
    let packet = parse(data)?;
    inflate_payload(packet)
}

pub fn build_raw_auto(mut opts: BuildOptions, min_size: usize) -> Result<Vec<u8>, VpnProtoError> {
    let (payload, compression_type) = prepare_payload(opts.packet_type, &opts.payload, opts.compression_type, min_size);
    opts.payload = payload;
    opts.compression_type = compression_type;
    build_raw(&opts)
}

pub fn build_encoded_auto(opts: BuildOptions, codec: Option<&Codec>, min_size: usize) -> Result<String, VpnProtoError> {
    let raw = build_raw_auto(opts, min_size)?;
    let codec = codec.ok_or(VpnProtoError::CodecUnavailable)?;
    codec.encrypt_and_encode(&raw).map_err(|_| VpnProtoError::CodecUnavailable)
}

#[cfg(test)]
mod cow_tests {
    use super::*;

    #[test]
    fn prepare_payload_cow_matches_prepare_payload() {
        let payloads: Vec<Vec<u8>> = vec![
            vec![],
            b"short".to_vec(),
            vec![b'x'; compression::DEFAULT_MIN_SIZE],
            vec![b'x'; compression::DEFAULT_MIN_SIZE + 1],
            vec![b'x'; 5000], // long run, compresses well
            (0..5000u32).map(|i| (i % 251) as u8).collect(), // less compressible
        ];
        for packet_type in [enums::PACKET_STREAM_DATA, enums::PACKET_PONG, enums::PACKET_DNS_QUERY_REQ] {
            for requested in [compression::TYPE_OFF, compression::TYPE_ZSTD, compression::TYPE_LZ4, compression::TYPE_ZLIB] {
                for payload in &payloads {
                    let (owned, owned_type) = prepare_payload(packet_type, payload, requested, 0);
                    let (cow, cow_type) = prepare_payload_cow(packet_type, payload, requested, 0);
                    assert_eq!(owned_type, cow_type, "packet_type={packet_type} requested={requested} len={}", payload.len());
                    assert_eq!(owned, cow.into_owned(), "packet_type={packet_type} requested={requested} len={}", payload.len());
                }
            }
        }
    }

    #[test]
    fn prepare_payload_cow_borrows_when_uncompressed() {
        let payload = b"short payload";
        let (cow, ctype) = prepare_payload_cow(enums::PACKET_STREAM_DATA, payload, compression::TYPE_ZSTD, 0);
        assert_eq!(ctype, compression::TYPE_OFF);
        assert!(matches!(cow, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn parse_inflated_from_labels_into_matches_allocating_version() {
        use crate::{build_encoded_auto, BuildOptions};
        use security::Codec;

        for method in [security::METHOD_NONE, security::METHOD_XOR, security::METHOD_CHACHA20, security::METHOD_AES128GCM] {
            let codec = Codec::new(method, "shared secret").unwrap();
            let mut scratch = Vec::new();
            for payload_len in [0usize, 1, 50, 500, 5000] {
                let opts = BuildOptions {
                    session_id: 3,
                    packet_type: enums::PACKET_STREAM_DATA,
                    session_cookie: 9,
                    stream_id: 4,
                    sequence_num: 77,
                    compression_type: compression::TYPE_ZSTD,
                    payload: vec![0x5Au8; payload_len],
                    ..Default::default()
                };
                let labels = build_encoded_auto(opts, Some(&codec), compression::DEFAULT_MIN_SIZE).unwrap();

                let expected = parse_inflated_from_labels(&labels, Some(&codec)).unwrap();

                scratch.extend_from_slice(&[0xCCu8; 20]);
                let via_scratch = parse_inflated_from_labels_into(&labels, Some(&codec), &mut scratch).unwrap();

                assert_eq!(via_scratch, expected, "method={method} payload_len={payload_len}");
            }
        }
    }
}
