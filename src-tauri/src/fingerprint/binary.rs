//! Binary fingerprinting and platform identification.
//!
//! Computes a SHA-256 hash of the running executable for integrity verification.
//! The vault uses this fingerprint to detect if the desktop binary has changed
//! since registration.

use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;

use super::platform_linux::FingerprintError;

/// Compute the SHA-256 fingerprint of the currently running executable.
///
/// Reads the full binary from disk and returns the hex-encoded SHA-256 hash.
/// This allows the vault to verify that the desktop app binary has not been
/// tampered with or replaced since initial registration.
pub fn binary_fingerprint() -> Result<String, FingerprintError> {
    let exe_path = std::env::current_exe().map_err(|e| {
        FingerprintError::BinaryHashFailed(format!("get executable path: {}", e))
    })?;

    let mut file = fs::File::open(&exe_path).map_err(|e| {
        FingerprintError::BinaryHashFailed(format!("open binary {}: {}", exe_path.display(), e))
    })?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).map_err(|e| {
            FingerprintError::BinaryHashFailed(format!("read binary: {}", e))
        })?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Return the current platform as "{os}/{arch}".
///
/// Examples: "linux/x86_64", "linux/aarch64", "macos/aarch64"
///
/// Uses compile-time constants from `std::env::consts`.
pub fn platform() -> String {
    format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_fingerprint_returns_hex() {
        // This test runs against the test binary itself
        let fp = binary_fingerprint().expect("should hash the test binary");
        // SHA-256 hex is 64 characters
        assert_eq!(fp.len(), 64);
        // Should be valid hex
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_binary_fingerprint_deterministic() {
        let fp1 = binary_fingerprint().expect("first hash");
        let fp2 = binary_fingerprint().expect("second hash");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_platform_format() {
        let p = platform();
        assert!(p.contains('/'), "platform should contain a slash: {}", p);
        let parts: Vec<&str> = p.split('/').collect();
        assert_eq!(parts.len(), 2);
        assert!(!parts[0].is_empty());
        assert!(!parts[1].is_empty());
    }
}
