//! Direct port of `internal/basecodec/lowerbase36.go`: a custom base36
//! encoding operating on 7-byte blocks -> 11 characters.

use std::fmt;

const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

const ENCODED_CHARS_BY_BYTES: [usize; 8] = [0, 2, 4, 5, 7, 8, 10, 11];
const DECODED_BYTES_BY_CHARS: [usize; 12] = [0, 0, 1, 0, 2, 3, 0, 4, 5, 0, 6, 7];

#[derive(Debug)]
pub struct Base36Error;

impl fmt::Display for Base36Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid lower base36 data")
    }
}

impl std::error::Error for Base36Error {}

fn decode_map() -> &'static [u8; 256] {
    static MAP: std::sync::OnceLock<[u8; 256]> = std::sync::OnceLock::new();
    MAP.get_or_init(|| {
        let mut table = [0xFFu8; 256];
        for (i, &ch) in ALPHABET.iter().enumerate() {
            table[ch as usize] = i as u8;
            if ch.is_ascii_lowercase() {
                table[(ch - (b'a' - b'A')) as usize] = i as u8;
            }
        }
        table
    })
}

pub fn encoded_len_lower_base36(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let blocks = n / 7;
    let rem = n % 7;
    blocks * 11 + ENCODED_CHARS_BY_BYTES[rem]
}

fn write_base36_block(dst: &mut [u8], mut val: u64, count: usize) {
    for i in (0..count).rev() {
        dst[i] = ALPHABET[(val % 36) as usize];
        val /= 36;
    }
}

pub fn encode_lower_base36_to(dst: &mut [u8], data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }

    let mut offset = 0usize;
    let mut src = data;

    while src.len() >= 7 {
        let val = (src[0] as u64) << 48
            | (src[1] as u64) << 40
            | (src[2] as u64) << 32
            | (src[3] as u64) << 24
            | (src[4] as u64) << 16
            | (src[5] as u64) << 8
            | (src[6] as u64);

        write_base36_block(&mut dst[offset..offset + 11], val, 11);
        offset += 11;
        src = &src[7..];
    }

    if !src.is_empty() {
        let mut val: u64 = 0;
        for &b in src {
            val = (val << 8) | b as u64;
        }

        let char_count = ENCODED_CHARS_BY_BYTES[src.len()];
        write_base36_block(&mut dst[offset..offset + char_count], val, char_count);
        offset += char_count;
    }

    offset
}

pub fn encode_lower_base36_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; encoded_len_lower_base36(data.len())];
    let n = encode_lower_base36_to(&mut out, data);
    out.truncate(n);
    out
}

pub fn encode_lower_base36(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    String::from_utf8(encode_lower_base36_bytes(data)).expect("alphabet is ASCII")
}

fn decoded_len_lower_base36(encoded_len: usize) -> Result<usize, Base36Error> {
    if encoded_len == 0 {
        return Ok(0);
    }
    let blocks = encoded_len / 11;
    let rem = encoded_len % 11;
    if rem >= DECODED_BYTES_BY_CHARS.len() {
        return Err(Base36Error);
    }
    let decoded_rem = DECODED_BYTES_BY_CHARS[rem];
    if rem != 0 && decoded_rem == 0 {
        return Err(Base36Error);
    }
    Ok(blocks * 7 + decoded_rem)
}

fn next_decode_block(remaining: usize) -> (usize, usize) {
    if remaining >= 11 {
        (7, 11)
    } else {
        (DECODED_BYTES_BY_CHARS[remaining], remaining)
    }
}

fn read_base36_block(data: &[u8]) -> Result<u64, Base36Error> {
    let map = decode_map();
    let mut val: u64 = 0;
    for &ch in data {
        let digit = map[ch as usize];
        if digit == 0xFF {
            return Err(Base36Error);
        }
        val = val * 36 + digit as u64;
    }
    Ok(val)
}

pub fn decode_lower_base36(data: &[u8]) -> Result<Vec<u8>, Base36Error> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let total_bytes = decoded_len_lower_base36(data.len())?;
    let mut out = vec![0u8; total_bytes];
    let mut offset = 0usize;
    let mut src = data;

    while !src.is_empty() {
        let (block_size, char_count) = next_decode_block(src.len());
        let mut val = read_base36_block(&src[..char_count])?;

        for i in (0..block_size).rev() {
            out[offset + i] = (val & 0xFF) as u8;
            val >>= 8;
        }
        offset += block_size;
        src = &src[char_count..];
    }

    Ok(out)
}

pub fn decode_lower_base36_string(data: &str) -> Result<Vec<u8>, Base36Error> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    decode_lower_base36(data.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_various_lengths() {
        for len in 0..30usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 5) as u8).collect();
            let encoded = encode_lower_base36(&data);
            let decoded = decode_lower_base36_string(&encoded).unwrap();
            assert_eq!(decoded, data, "round trip failed for len={len}");
        }
    }

    #[test]
    fn seven_byte_block_is_eleven_chars() {
        let data = [0xFFu8; 7];
        let encoded = encode_lower_base36(&data);
        assert_eq!(encoded.len(), 11);
        assert_eq!(decode_lower_base36_string(&encoded).unwrap(), data);
    }

    #[test]
    fn uppercase_decodes() {
        let data = b"hello world";
        let encoded = encode_lower_base36(data).to_uppercase();
        assert_eq!(decode_lower_base36_string(&encoded).unwrap(), data);
    }
}
