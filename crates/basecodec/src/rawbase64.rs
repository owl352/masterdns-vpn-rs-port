//! Port of `internal/basecodec/rawbase64.go`: standard base64 alphabet, no padding
//! (matches Go's `base64.RawStdEncoding`).

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;

pub fn encode_raw_base64(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    STANDARD_NO_PAD.encode(data).into_bytes()
}

pub fn encoded_raw_base64_len(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (n * 4 + 2) / 3
}

pub fn encode_raw_base64_to(dst: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    dst.extend_from_slice(STANDARD_NO_PAD.encode(data).as_bytes());
}

pub fn encode_raw_base64_into(dst: &mut [u8], data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let encoded = STANDARD_NO_PAD.encode(data);
    dst[..encoded.len()].copy_from_slice(encoded.as_bytes());
}

pub fn decode_raw_base64(data: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    STANDARD_NO_PAD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let cases: &[&[u8]] = &[b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"];
        for &case in cases {
            let encoded = encode_raw_base64(case);
            let decoded = decode_raw_base64(&encoded).unwrap();
            assert_eq!(decoded, case);
            assert_eq!(encoded.len(), encoded_raw_base64_len(case.len()));
        }
    }
}
