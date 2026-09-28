//! Port of `internal/vpnproto/payload.go`.

use crate::flags::has_compression_extension;
use crate::parser::{parse, parse_from_labels};
use crate::{build_raw, BuildOptions, Packet, VpnProtoError};
use security::Codec;

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
