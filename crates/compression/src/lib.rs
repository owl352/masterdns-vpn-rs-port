//! Port of `internal/compression/types.go`.

use std::io::{Read, Write};

pub const TYPE_OFF: u8 = 0;
pub const TYPE_ZSTD: u8 = 1;
pub const TYPE_LZ4: u8 = 2;
pub const TYPE_ZLIB: u8 = 3;

pub const DEFAULT_MIN_SIZE: usize = 100;

/// Caps decompressed output to prevent decompression bombs.
const MAX_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;

const AVAILABLE_TYPE_MASK: u8 = (1 << TYPE_OFF) | (1 << TYPE_ZSTD) | (1 << TYPE_LZ4) | (1 << TYPE_ZLIB);

const NORMALIZED_PACKED_PAIR_NIBBLE: [u8; 16] = [
    TYPE_OFF, TYPE_ZSTD, TYPE_LZ4, TYPE_ZLIB, TYPE_OFF, TYPE_OFF, TYPE_OFF, TYPE_OFF, TYPE_OFF, TYPE_OFF,
    TYPE_OFF, TYPE_OFF, TYPE_OFF, TYPE_OFF, TYPE_OFF, TYPE_OFF,
];

#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    #[error("decompressed payload exceeds safety limit")]
    DecompressedTooLarge,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("lz4 payload truncated")]
    Lz4Truncated,
    #[error("lz4 error: {0}")]
    Lz4(#[from] lz4_flex::block::DecompressError),
}

pub fn normalize_type(value: u8) -> u8 {
    if value <= TYPE_ZLIB {
        value
    } else {
        TYPE_OFF
    }
}

pub fn is_type_available(value: u8) -> bool {
    let value = normalize_type(value);
    AVAILABLE_TYPE_MASK & (1 << value) != 0
}

pub fn normalize_available_type(value: u8) -> u8 {
    if value > TYPE_ZLIB || AVAILABLE_TYPE_MASK & (1 << value) == 0 {
        TYPE_OFF
    } else {
        value
    }
}

pub fn pack_pair(upload_type: u8, download_type: u8) -> u8 {
    let upload_type = if upload_type > TYPE_ZLIB { TYPE_OFF } else { upload_type };
    let download_type = if download_type > TYPE_ZLIB { TYPE_OFF } else { download_type };
    (upload_type << 4) | download_type
}

pub fn split_pair(value: u8) -> (u8, u8) {
    (
        NORMALIZED_PACKED_PAIR_NIBBLE[((value >> 4) & 0x0F) as usize],
        NORMALIZED_PACKED_PAIR_NIBBLE[(value & 0x0F) as usize],
    )
}

pub fn type_name(value: u8) -> &'static str {
    match normalize_type(value) {
        TYPE_ZSTD => "ZSTD",
        TYPE_LZ4 => "LZ4",
        TYPE_ZLIB => "ZLIB",
        _ => "OFF",
    }
}

pub fn compress_payload(data: &[u8], comp_type: u8, min_size: usize) -> (Vec<u8>, u8) {
    if data.is_empty() {
        return (data.to_vec(), TYPE_OFF);
    }

    let comp_type = normalize_available_type(comp_type);
    if comp_type == TYPE_OFF {
        return (data.to_vec(), TYPE_OFF);
    }

    let min_size = if min_size == 0 { DEFAULT_MIN_SIZE } else { min_size };
    if data.len() <= min_size {
        return (data.to_vec(), TYPE_OFF);
    }

    let compressed = match comp_type {
        TYPE_ZLIB => compress_zlib(data).ok(),
        TYPE_ZSTD => compress_zstd(data).ok(),
        TYPE_LZ4 => Some(compress_lz4(data)),
        _ => None,
    };

    match compressed {
        Some(comp_data) if comp_data.len() < data.len() => (comp_data, comp_type),
        _ => (data.to_vec(), TYPE_OFF),
    }
}

pub fn try_decompress_payload(data: &[u8], comp_type: u8) -> Option<Vec<u8>> {
    if data.is_empty() {
        return Some(data.to_vec());
    }

    let comp_type = normalize_available_type(comp_type);
    if comp_type == TYPE_OFF {
        return Some(data.to_vec());
    }

    match comp_type {
        TYPE_ZLIB => decompress_zlib(data).ok(),
        TYPE_ZSTD => decompress_zstd(data).ok(),
        TYPE_LZ4 => decompress_lz4(data).ok(),
        _ => None,
    }
}

fn compress_zlib(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(1));
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let decoder = flate2::read::DeflateDecoder::new(data);
    let mut limited = decoder.take((MAX_DECOMPRESSED_SIZE + 1) as u64);
    let mut out = Vec::new();
    limited.read_to_end(&mut out)?;
    if out.len() > MAX_DECOMPRESSED_SIZE {
        return Err(CompressionError::DecompressedTooLarge);
    }
    Ok(out)
}

fn compress_zstd(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    Ok(zstd::stream::encode_all(data, 1)?)
}

fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let decoder = zstd::stream::Decoder::new(data)?;
    let mut limited = decoder.take((MAX_DECOMPRESSED_SIZE + 1) as u64);
    let mut out = Vec::new();
    limited.read_to_end(&mut out)?;
    if out.len() > MAX_DECOMPRESSED_SIZE {
        return Err(CompressionError::DecompressedTooLarge);
    }
    Ok(out)
}

/// 4-byte little-endian original-size prefix + raw LZ4 block (matches the
/// Go/Python `lz4.block` `store_size=True` convention).
fn compress_lz4(data: &[u8]) -> Vec<u8> {
    let compressed = lz4_flex::block::compress(data);
    let mut out = Vec::with_capacity(4 + compressed.len());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&compressed);
    out
}

fn decompress_lz4(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    if data.len() < 4 {
        return Err(CompressionError::Lz4Truncated);
    }
    let orig_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if orig_size > MAX_DECOMPRESSED_SIZE {
        return Err(CompressionError::DecompressedTooLarge);
    }
    let out = lz4_flex::block::decompress(&data[4..], orig_size)?;
    if out.len() != orig_size {
        return Err(CompressionError::Lz4Truncated);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn pack_and_split_pair() {
        let packed = pack_pair(TYPE_ZSTD, TYPE_LZ4);
        assert_eq!(split_pair(packed), (TYPE_ZSTD, TYPE_LZ4));
    }

    #[test]
    fn below_min_size_stays_uncompressed() {
        let data = payload(10);
        let (out, t) = compress_payload(&data, TYPE_ZSTD, 100);
        assert_eq!(t, TYPE_OFF);
        assert_eq!(out, data);
    }

    #[test]
    fn zstd_round_trip() {
        let data = payload(4096);
        let (compressed, t) = compress_payload(&data, TYPE_ZSTD, 100);
        assert_eq!(t, TYPE_ZSTD);
        let decompressed = try_decompress_payload(&compressed, t).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn lz4_round_trip() {
        let data = payload(4096);
        let (compressed, t) = compress_payload(&data, TYPE_LZ4, 100);
        assert_eq!(t, TYPE_LZ4);
        let decompressed = try_decompress_payload(&compressed, t).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn zlib_round_trip() {
        let data = payload(4096);
        let (compressed, t) = compress_payload(&data, TYPE_ZLIB, 100);
        assert_eq!(t, TYPE_ZLIB);
        let decompressed = try_decompress_payload(&compressed, t).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn lz4_bomb_guard() {
        let mut fake = vec![0u8; 8];
        let huge = (MAX_DECOMPRESSED_SIZE as u32) + 1;
        fake[0..4].copy_from_slice(&huge.to_le_bytes());
        assert!(decompress_lz4(&fake).is_err());
    }
}
