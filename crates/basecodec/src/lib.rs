//! Ports of `internal/basecodec` (lowerbase32.go, lowerbase36.go, rawbase64.go,
//! codec.go) from the Go MasterDnsVPN source.

mod lowerbase32;
mod lowerbase36;
mod rawbase64;

pub use lowerbase32::*;
pub use lowerbase36::*;
pub use rawbase64::*;

/// `codec.go`: the active DNS-label-safe encoding scheme, currently aliased to
/// LowerBase36 (matches the Go default).
pub fn encoded_len(n: usize) -> usize {
    encoded_len_lower_base36(n)
}

pub fn encode_to(dst: &mut [u8], data: &[u8]) -> usize {
    encode_lower_base36_to(dst, data)
}

pub fn encode_to_bytes(data: &[u8]) -> Vec<u8> {
    encode_lower_base36_bytes(data)
}

pub fn encode(data: &[u8]) -> String {
    encode_lower_base36(data)
}

pub fn decode(data: &[u8]) -> Result<Vec<u8>, Base36Error> {
    decode_lower_base36(data)
}

pub fn decode_string(data: &str) -> Result<Vec<u8>, Base36Error> {
    decode_lower_base36_string(data)
}

/// Same as [`decode`], but writes into a caller-owned buffer instead of
/// allocating a fresh one - see [`decode_lower_base36_into`].
pub fn decode_into(dst: &mut Vec<u8>, data: &[u8]) -> Result<(), Base36Error> {
    decode_lower_base36_into(dst, data)
}

/// Same as [`decode_string`], but writes into a caller-owned buffer instead
/// of allocating a fresh one - see [`decode_lower_base36_string_into`].
pub fn decode_string_into(dst: &mut Vec<u8>, data: &str) -> Result<(), Base36Error> {
    decode_lower_base36_string_into(dst, data)
}
