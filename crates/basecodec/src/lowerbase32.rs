//! Port of `internal/basecodec/lowerbase32.go`: RFC4648 base32 with the
//! `abcdefghijklmnopqrstuvwxyz234567` alphabet and no padding.

use std::fmt;

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[derive(Debug)]
pub struct Base32Error;

impl fmt::Display for Base32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid lower base32 data")
    }
}

impl std::error::Error for Base32Error {}

fn decode_char(c: u8) -> Result<u8, Base32Error> {
    match c {
        b'a'..=b'z' => Ok(c - b'a'),
        b'2'..=b'7' => Ok(c - b'2' + 26),
        _ => Err(Base32Error),
    }
}

pub fn encoded_len_lower_base32(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (n * 8 + 4) / 5
}

pub fn encode_lower_base32_to(dst: &mut [u8], data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }

    let mut out_len = 0usize;
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            dst[out_len] = ALPHABET[idx];
            out_len += 1;
        }
    }
    if bits > 0 {
        let idx = (((buf & ((1u32 << bits) - 1)) << (5 - bits)) & 0x1F) as usize;
        dst[out_len] = ALPHABET[idx];
        out_len += 1;
    }
    out_len
}

pub fn encode_lower_base32_bytes(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = vec![0u8; encoded_len_lower_base32(data.len())];
    let n = encode_lower_base32_to(&mut out, data);
    out.truncate(n);
    out
}

pub fn encode_lower_base32(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    String::from_utf8(encode_lower_base32_bytes(data)).expect("alphabet is ASCII")
}

pub fn decode_lower_base32(data: &[u8]) -> Result<Vec<u8>, Base32Error> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut normalized = Vec::with_capacity(data.len());
    for &c in data {
        if c.is_ascii_uppercase() {
            normalized.push(c + (b'a' - b'A'));
        } else {
            normalized.push(c);
        }
    }

    let mut out = Vec::with_capacity(normalized.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &c in &normalized {
        let val = decode_char(c)?;
        buf = (buf << 5) | val as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }

    Ok(out)
}

pub fn decode_lower_base32_string(data: &str) -> Result<Vec<u8>, Base32Error> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    decode_lower_base32(data.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let cases: &[&[u8]] = &[b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"];
        for &case in cases {
            let encoded = encode_lower_base32(case);
            let decoded = decode_lower_base32_string(&encoded).unwrap();
            assert_eq!(decoded, case, "round trip failed for {case:?}");
        }
    }

    #[test]
    fn known_vectors() {
        // RFC 4648 test vectors, lowercased, no padding.
        assert_eq!(encode_lower_base32(b"f"), "my");
        assert_eq!(encode_lower_base32(b"fo"), "mzxq");
        assert_eq!(encode_lower_base32(b"foo"), "mzxw6");
        assert_eq!(encode_lower_base32(b"foob"), "mzxw6yq");
        assert_eq!(encode_lower_base32(b"fooba"), "mzxw6ytb");
        assert_eq!(encode_lower_base32(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn uppercase_input_decodes() {
        assert_eq!(decode_lower_base32_string("MZXW6YTBOI").unwrap(), b"foobar");
    }
}
