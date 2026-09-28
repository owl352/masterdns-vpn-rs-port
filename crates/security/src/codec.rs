//! Port of `internal/security/codec.go`.

use crate::SecurityError;
use aes_gcm::aead::{generic_array::GenericArray, Aead, AeadInPlace};
use aes::Aes192;
use aes_gcm::{AesGcm, Aes128Gcm, Aes256Gcm, KeyInit};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use rand::RngCore;
use sha2::{Digest, Sha256};

type Aes192Gcm = AesGcm<Aes192, aes_gcm::aead::consts::U12>;

pub const METHOD_NONE: u8 = 0;
pub const METHOD_XOR: u8 = 1;
pub const METHOD_CHACHA20: u8 = 2;
pub const METHOD_AES128GCM: u8 = 3;
pub const METHOD_AES192GCM: u8 = 4;
pub const METHOD_AES256GCM: u8 = 5;

const CHACHA_NONCE_SIZE: usize = 16;
const AES_NONCE_SIZE: usize = 12;

enum Aead4 {
    Aes128(Aes128Gcm),
    Aes192(Aes192Gcm),
    Aes256(Aes256Gcm),
}

pub struct Codec {
    method: u8,
    key: Vec<u8>,
    aead: Option<Aead4>,
}

impl Codec {
    pub fn new(method: u8, raw_key: &str) -> Result<Codec, SecurityError> {
        if method > 5 {
            return Err(SecurityError::InvalidMethod);
        }

        let key = derive_key(method, raw_key);
        let aead = match method {
            METHOD_AES128GCM => Some(Aead4::Aes128(Aes128Gcm::new(GenericArray::from_slice(&key)))),
            METHOD_AES192GCM => Some(Aead4::Aes192(Aes192Gcm::new(GenericArray::from_slice(&key)))),
            METHOD_AES256GCM => Some(Aead4::Aes256(Aes256Gcm::new(GenericArray::from_slice(&key)))),
            _ => None,
        };

        Ok(Codec { method, key, aead })
    }

    pub fn method(&self) -> u8 {
        self.method
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, SecurityError> {
        match self.method {
            METHOD_NONE => Ok(data.to_vec()),
            METHOD_XOR => Ok(xor_crypto(&self.key, data)),
            METHOD_CHACHA20 => chacha_encrypt(&self.key, data),
            METHOD_AES128GCM | METHOD_AES192GCM | METHOD_AES256GCM => {
                aes_encrypt(self.aead.as_ref().expect("aead configured"), data)
            }
            _ => Err(SecurityError::InvalidMethod),
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, SecurityError> {
        match self.method {
            METHOD_NONE => Ok(data.to_vec()),
            METHOD_XOR => Ok(xor_crypto(&self.key, data)),
            METHOD_CHACHA20 => chacha_decrypt(&self.key, data),
            METHOD_AES128GCM | METHOD_AES192GCM | METHOD_AES256GCM => {
                aes_decrypt(self.aead.as_ref().expect("aead configured"), data)
            }
            _ => Err(SecurityError::InvalidMethod),
        }
    }

    pub fn encrypt_and_encode(&self, data: &[u8]) -> Result<String, SecurityError> {
        if self.method == METHOD_NONE {
            return Ok(basecodec::encode(data));
        }
        let encrypted = self.encrypt(data)?;
        Ok(basecodec::encode(&encrypted))
    }

    pub fn encrypt_and_encode_bytes(&self, data: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if self.method == METHOD_NONE {
            return Ok(basecodec::encode_to_bytes(data));
        }
        let encrypted = self.encrypt(data)?;
        Ok(basecodec::encode_to_bytes(&encrypted))
    }

    pub fn decode_and_decrypt(&self, data: &[u8]) -> Result<Vec<u8>, SecurityError> {
        let decoded = basecodec::decode(data).map_err(|_| SecurityError::InvalidCiphertext)?;
        if self.method == METHOD_NONE {
            return Ok(decoded);
        }
        self.decrypt(&decoded)
    }

    pub fn decode_string_and_decrypt(&self, data: &str) -> Result<Vec<u8>, SecurityError> {
        let decoded = basecodec::decode_string(data).map_err(|_| SecurityError::InvalidCiphertext)?;
        if self.method == METHOD_NONE {
            return Ok(decoded);
        }
        self.decrypt(&decoded)
    }

    /// Same result as [`Self::decode_string_and_decrypt`], but decodes into
    /// `out` (reusing its allocation across calls - see
    /// [`basecodec::decode_string_into`]) and decrypts in place instead of
    /// allocating a second buffer, for every method except the AEAD ones'
    /// rare "compression didn't help" fallback. Request-path callers that
    /// handle many packets per thread can keep one `out` alive across calls.
    /// On `Err`, `out`'s contents are unspecified and must not be used.
    pub fn decode_string_and_decrypt_into(&self, data: &str, out: &mut Vec<u8>) -> Result<(), SecurityError> {
        basecodec::decode_string_into(out, data).map_err(|_| SecurityError::InvalidCiphertext)?;
        if self.method == METHOD_NONE {
            return Ok(());
        }
        self.decrypt_in_place(out)
    }

    /// In-place counterpart to [`Self::decrypt`]: mutates `data` into the
    /// plaintext instead of returning a new `Vec`. XOR mutates directly;
    /// ChaCha20 and AES-GCM drop their nonce prefix with an in-place
    /// `Vec::drain` (a shift, not a new allocation) and decrypt into the
    /// remainder.
    pub fn decrypt_in_place(&self, data: &mut Vec<u8>) -> Result<(), SecurityError> {
        match self.method {
            METHOD_NONE => Ok(()),
            METHOD_XOR => {
                xor_crypto_in_place(&self.key, data);
                Ok(())
            }
            METHOD_CHACHA20 => chacha_decrypt_in_place(&self.key, data),
            METHOD_AES128GCM | METHOD_AES192GCM | METHOD_AES256GCM => {
                aes_decrypt_in_place(self.aead.as_ref().expect("aead configured"), data)
            }
            _ => Err(SecurityError::InvalidMethod),
        }
    }
}

fn xor_crypto(key: &[u8], data: &[u8]) -> Vec<u8> {
    if data.is_empty() || key.is_empty() {
        return data.to_vec();
    }
    let mut out = data.to_vec();
    xor_crypto_in_place(key, &mut out);
    out
}

fn xor_crypto_in_place(key: &[u8], data: &mut [u8]) {
    if data.is_empty() || key.is_empty() {
        return;
    }
    // XOR key-sized chunks instead of indexing `key[i % len]` per byte: same
    // output, but the compiler vectorizes it (~5-10x faster at packet sizes).
    for chunk in data.chunks_mut(key.len()) {
        for (b, k) in chunk.iter_mut().zip(key) {
            *b ^= k;
        }
    }
}

fn chacha_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, SecurityError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut nonce_buf = [0u8; CHACHA_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_buf);
    let counter = u32::from_le_bytes([nonce_buf[0], nonce_buf[1], nonce_buf[2], nonce_buf[3]]);
    let nonce = &nonce_buf[4..16];

    let mut cipher = ChaCha20::new(GenericArray::from_slice(key), GenericArray::from_slice(nonce));
    cipher
        .try_seek((counter as u64) * 64)
        .map_err(|_| SecurityError::InvalidCiphertext)?;

    let mut out = data.to_vec();
    cipher.apply_keystream(&mut out);

    let mut result = Vec::with_capacity(CHACHA_NONCE_SIZE + out.len());
    result.extend_from_slice(&nonce_buf);
    result.extend_from_slice(&out);
    Ok(result)
}

fn chacha_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, SecurityError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data.len() <= CHACHA_NONCE_SIZE {
        return Err(SecurityError::InvalidCiphertext);
    }

    let nonce_buf = &data[..CHACHA_NONCE_SIZE];
    let ciphertext = &data[CHACHA_NONCE_SIZE..];
    let counter = u32::from_le_bytes([nonce_buf[0], nonce_buf[1], nonce_buf[2], nonce_buf[3]]);
    let nonce = &nonce_buf[4..16];

    let mut cipher = ChaCha20::new(GenericArray::from_slice(key), GenericArray::from_slice(nonce));
    cipher
        .try_seek((counter as u64) * 64)
        .map_err(|_| SecurityError::InvalidCiphertext)?;

    let mut out = ciphertext.to_vec();
    cipher.apply_keystream(&mut out);
    Ok(out)
}

fn chacha_decrypt_in_place(key: &[u8], data: &mut Vec<u8>) -> Result<(), SecurityError> {
    if data.is_empty() {
        return Ok(());
    }
    if data.len() <= CHACHA_NONCE_SIZE {
        return Err(SecurityError::InvalidCiphertext);
    }

    let nonce_buf: [u8; CHACHA_NONCE_SIZE] = data[..CHACHA_NONCE_SIZE].try_into().expect("checked length above");
    let counter = u32::from_le_bytes([nonce_buf[0], nonce_buf[1], nonce_buf[2], nonce_buf[3]]);
    let nonce = &nonce_buf[4..16];

    let mut cipher = ChaCha20::new(GenericArray::from_slice(key), GenericArray::from_slice(nonce));
    cipher
        .try_seek((counter as u64) * 64)
        .map_err(|_| SecurityError::InvalidCiphertext)?;

    // Drop the nonce prefix in place (a shift within the existing
    // allocation, not a new one), then decrypt the remainder in place.
    data.drain(..CHACHA_NONCE_SIZE);
    cipher.apply_keystream(data);
    Ok(())
}

fn aes_encrypt(aead: &Aead4, data: &[u8]) -> Result<Vec<u8>, SecurityError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut nonce_buf = [0u8; AES_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_buf);
    let nonce = GenericArray::from_slice(&nonce_buf);

    let ciphertext = match aead {
        Aead4::Aes128(c) => c.encrypt(nonce, data),
        Aead4::Aes192(c) => c.encrypt(nonce, data),
        Aead4::Aes256(c) => c.encrypt(nonce, data),
    }
    .map_err(|_| SecurityError::InvalidCiphertext)?;

    let mut out = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce_buf);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn aes_decrypt(aead: &Aead4, data: &[u8]) -> Result<Vec<u8>, SecurityError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data.len() <= AES_NONCE_SIZE {
        return Err(SecurityError::InvalidCiphertext);
    }

    let nonce = GenericArray::from_slice(&data[..AES_NONCE_SIZE]);
    let ciphertext = &data[AES_NONCE_SIZE..];

    match aead {
        Aead4::Aes128(c) => c.decrypt(nonce, ciphertext),
        Aead4::Aes192(c) => c.decrypt(nonce, ciphertext),
        Aead4::Aes256(c) => c.decrypt(nonce, ciphertext),
    }
    .map_err(|_| SecurityError::InvalidCiphertext)
}

fn aes_decrypt_in_place(aead: &Aead4, data: &mut Vec<u8>) -> Result<(), SecurityError> {
    if data.is_empty() {
        return Ok(());
    }
    if data.len() <= AES_NONCE_SIZE {
        return Err(SecurityError::InvalidCiphertext);
    }

    let nonce_buf: [u8; AES_NONCE_SIZE] = data[..AES_NONCE_SIZE].try_into().expect("checked length above");
    let nonce = GenericArray::from_slice(&nonce_buf);
    // Drop the nonce prefix in place, leaving just ciphertext||tag for
    // decrypt_in_place (the AeadInPlace counterpart of `decrypt`) to
    // authenticate and decrypt/truncate directly in `data`.
    data.drain(..AES_NONCE_SIZE);

    match aead {
        Aead4::Aes128(c) => c.decrypt_in_place(nonce, b"", data),
        Aead4::Aes192(c) => c.decrypt_in_place(nonce, b"", data),
        Aead4::Aes256(c) => c.decrypt_in_place(nonce, b"", data),
    }
    .map_err(|_| SecurityError::InvalidCiphertext)
}

pub fn derive_key(method: u8, raw_key: &str) -> Vec<u8> {
    let b_key = raw_key.as_bytes();
    let target_len = required_derived_key_length(method);

    match method {
        METHOD_CHACHA20 | METHOD_AES256GCM => Sha256::digest(b_key).to_vec(),
        METHOD_AES128GCM => md5::Md5::digest(b_key).to_vec(),
        _ => {
            let mut key = vec![0u8; target_len];
            let n = b_key.len().min(target_len);
            key[..n].copy_from_slice(&b_key[..n]);
            key
        }
    }
}

fn required_derived_key_length(method: u8) -> usize {
    match method {
        METHOD_CHACHA20 | METHOD_AES256GCM => 32,
        METHOD_AES128GCM => 16,
        METHOD_AES192GCM => 24,
        _ => 32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_round_trip() {
        let codec = Codec::new(METHOD_NONE, "key").unwrap();
        let encoded = codec.encrypt_and_encode(b"hello world").unwrap();
        let decoded = codec.decode_string_and_decrypt(&encoded).unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn xor_round_trip() {
        let codec = Codec::new(METHOD_XOR, "secretkey").unwrap();
        let encoded = codec.encrypt_and_encode(b"hello world").unwrap();
        let decoded = codec.decode_string_and_decrypt(&encoded).unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn chacha20_round_trip() {
        let codec = Codec::new(METHOD_CHACHA20, "secretkey").unwrap();
        let encoded = codec.encrypt_and_encode(b"hello world, this is a longer message").unwrap();
        let decoded = codec.decode_string_and_decrypt(&encoded).unwrap();
        assert_eq!(decoded, b"hello world, this is a longer message");
    }

    #[test]
    fn aes_gcm_round_trip_all_key_sizes() {
        for method in [METHOD_AES128GCM, METHOD_AES192GCM, METHOD_AES256GCM] {
            let codec = Codec::new(method, "secretkey").unwrap();
            let encoded = codec.encrypt_and_encode(b"hello world").unwrap();
            let decoded = codec.decode_string_and_decrypt(&encoded).unwrap();
            assert_eq!(decoded, b"hello world", "failed for method {method}");
        }
    }

    #[test]
    fn derive_key_lengths() {
        assert_eq!(derive_key(METHOD_AES128GCM, "x").len(), 16);
        assert_eq!(derive_key(METHOD_AES192GCM, "x").len(), 24);
        assert_eq!(derive_key(METHOD_CHACHA20, "x").len(), 32);
        assert_eq!(derive_key(METHOD_AES256GCM, "x").len(), 32);
    }

    #[test]
    fn decode_string_and_decrypt_into_matches_allocating_version() {
        for method in [METHOD_NONE, METHOD_XOR, METHOD_CHACHA20, METHOD_AES128GCM, METHOD_AES192GCM, METHOD_AES256GCM] {
            let codec = Codec::new(method, "secretkey").unwrap();
            let mut scratch = Vec::new();
            for payload in [&b""[..], b"a", b"hello world", &[0x42u8; 5000][..]] {
                let encoded = codec.encrypt_and_encode(payload).unwrap();

                let expected = codec.decode_string_and_decrypt(&encoded).unwrap();

                // Pre-fill scratch with unrelated bytes so the _into path is
                // exercised without assuming it starts out empty/exact-sized.
                scratch.extend_from_slice(&[0xEEu8; 37]);
                codec.decode_string_and_decrypt_into(&encoded, &mut scratch).unwrap();

                assert_eq!(scratch, expected, "method={method} payload_len={}", payload.len());
                assert_eq!(scratch, *payload, "method={method} payload_len={}", payload.len());
            }
        }
    }

    #[test]
    fn decrypt_in_place_matches_decrypt_on_random_ciphertexts() {
        for method in [METHOD_NONE, METHOD_XOR, METHOD_CHACHA20, METHOD_AES128GCM, METHOD_AES192GCM, METHOD_AES256GCM] {
            let codec = Codec::new(method, "another secret").unwrap();
            for payload in [&b""[..], b"x", b"the quick brown fox jumps over the lazy dog", &[0x77u8; 4096][..]] {
                let ciphertext = codec.encrypt(payload).unwrap();

                let expected = codec.decrypt(&ciphertext).unwrap();
                let mut in_place = ciphertext.clone();
                codec.decrypt_in_place(&mut in_place).unwrap();

                assert_eq!(in_place, expected, "method={method} payload_len={}", payload.len());
            }
        }
    }

    #[test]
    fn decode_string_and_decrypt_into_rejects_invalid_ciphertext_like_allocating_version() {
        let codec = Codec::new(METHOD_CHACHA20, "secretkey").unwrap();
        // Too short to contain a nonce once decoded: `decrypt` errors, so
        // `decrypt_in_place` (called from decode_string_and_decrypt_into)
        // must error identically.
        let short = basecodec::encode(&[1, 2, 3]);
        assert!(codec.decode_string_and_decrypt(&short).is_err());
        let mut scratch = Vec::new();
        assert!(codec.decode_string_and_decrypt_into(&short, &mut scratch).is_err());
    }
}
