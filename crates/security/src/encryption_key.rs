//! Port of `internal/security/encryption_key.go`.
//!
//! Unlike the Go version this takes the encryption method and key-file path
//! directly rather than a full `config.ServerConfig`, so this crate does not
//! need to depend on the (not-yet-written) `config` crate.

use crate::SecurityError;
use rand::RngCore;
use std::path::{Path, PathBuf};

use crate::codec::{METHOD_AES128GCM, METHOD_AES192GCM};

#[derive(Debug, Clone)]
pub struct EncryptionKeyInfo {
    pub method_id: u8,
    pub method_name: String,
    pub key: String,
    pub path: PathBuf,
    pub loaded: bool,
    pub generated: bool,
}

pub fn ensure_server_encryption_key(method: u8, path: &Path) -> Result<EncryptionKeyInfo, SecurityError> {
    let mut info = EncryptionKeyInfo {
        method_id: method,
        method_name: encryption_method_name(method).to_string(),
        key: String::new(),
        path: path.to_path_buf(),
        loaded: false,
        generated: false,
    };

    let required_length = required_key_length(method);
    if let Ok(raw) = std::fs::read_to_string(path) {
        let key = raw.trim();
        if key.len() == required_length {
            info.key = key.to_string();
            info.loaded = true;
            return Ok(info);
        }
    }

    let key = generate_hex_text(required_length);
    std::fs::write(path, &key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    info.key = key;
    info.generated = true;
    Ok(info)
}

pub fn encryption_method_name(method_id: u8) -> &'static str {
    match method_id {
        0 => "NONE",
        1 => "XOR",
        2 => "ChaCha20",
        3 => "AES-128-GCM",
        4 => "AES-192-GCM",
        5 => "AES-256-GCM",
        _ => "UNKNOWN",
    }
}

fn required_key_length(method_id: u8) -> usize {
    match method_id {
        METHOD_AES128GCM => 16,
        METHOD_AES192GCM => 24,
        _ => 32,
    }
}

fn generate_hex_text(length: usize) -> String {
    if length == 0 {
        return String::new();
    }
    let n = length.div_ceil(2);
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    hex[..length].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_reloads_key() {
        let dir = std::env::temp_dir().join(format!("masterdnsvpn-rs-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("encrypt_key.txt");
        let _ = std::fs::remove_file(&path);

        let first = ensure_server_encryption_key(3, &path).unwrap();
        assert!(first.generated);
        assert_eq!(first.key.len(), 16);

        let second = ensure_server_encryption_key(3, &path).unwrap();
        assert!(second.loaded);
        assert_eq!(second.key, first.key);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
