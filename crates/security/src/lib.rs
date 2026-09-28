//! Ports of `internal/security` (codec.go, encryption_key.go).

mod codec;
mod encryption_key;

pub use codec::*;
pub use encryption_key::*;

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("invalid encryption method")]
    InvalidMethod,
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
