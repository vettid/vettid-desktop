//! Encrypted credential storage for the VettID desktop app.
//!
//! Credentials are encrypted at rest with a 32-byte master key fetched
//! from the OS keyring (Linux Secret Service / macOS Keychain), with a
//! machine-bound fallback when the keyring isn't reachable. The user
//! never enters a passphrase: every privileged vault operation already
//! requires phone authorization, and the on-disk blob — even decrypted
//! — only lets the attacker publish `device.request-session`, which
//! the phone has to authorize before it becomes a working session.
//!
//! See [`keystore`](super::keystore) for the key-source details and
//! [`DESKTOP-REWORK-PLAN.md`](../../../../DESKTOP-REWORK-PLAN.md) §4 for
//! the threat-model rationale.
//!
//! On-disk format: JSON-serialized `EncryptedStore` at
//! `~/.config/vettid-desktop/connection.enc` (Linux) or
//! `~/Library/Application Support/vettid-desktop/connection.enc` (macOS).

use std::fmt;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::credential::keystore::{self, BindingMode, KeystoreError};
use crate::fingerprint::platform_linux::FingerprintError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current version of the encrypted store format. v2 dropped the
/// Argon2id-over-passphrase step in favor of a 32-byte master key
/// sourced via [`crate::credential::keystore`]. v1 stores are
/// rejected outright (no migration — see DESKTOP-REWORK-PLAN.md §7).
const STORE_VERSION: i32 = 2;

/// Credential file name within the config directory.
const CREDENTIAL_FILE: &str = "connection.enc";

/// Subdirectory name appended to the OS config dir.
const CONFIG_SUBDIR: &str = "vettid-desktop";

/// XChaCha20-Poly1305 nonce size (24 bytes).
const NONCE_SIZE: usize = 24;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during credential store operations.
#[derive(Debug)]
pub enum CredentialError {
    /// The credential file could not be read or written.
    IoError(String),
    /// JSON serialization or deserialization failed.
    SerializationError(String),
    /// Encryption or decryption failed.
    CryptoError(String),
    /// Fingerprint collection or computation failed.
    FingerprintError(FingerprintError),
    /// The keystore couldn't fetch a master key (keyring unavailable
    /// AND machine-bound fallback failed).
    KeystoreError(String),
    /// The credential file does not exist.
    NotFound(String),
    /// The store version is not supported.
    UnsupportedVersion(i32),
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialError::IoError(msg) => write!(f, "I/O error: {}", msg),
            CredentialError::SerializationError(msg) => {
                write!(f, "serialization error: {}", msg)
            }
            CredentialError::CryptoError(msg) => write!(f, "crypto error: {}", msg),
            CredentialError::FingerprintError(e) => write!(f, "fingerprint error: {}", e),
            CredentialError::KeystoreError(msg) => write!(f, "keystore error: {}", msg),
            CredentialError::NotFound(path) => write!(f, "credential file not found: {}", path),
            CredentialError::UnsupportedVersion(v) => {
                write!(f, "unsupported store version: {}", v)
            }
        }
    }
}

impl std::error::Error for CredentialError {}

impl From<KeystoreError> for CredentialError {
    fn from(e: KeystoreError) -> Self {
        CredentialError::KeystoreError(e.to_string())
    }
}

impl From<FingerprintError> for CredentialError {
    fn from(e: FingerprintError) -> Self {
        CredentialError::FingerprintError(e)
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// All sensitive material for an active desktop-to-vault connection.
///
/// This struct is JSON-serialized before encryption. The `Zeroize` derive
/// ensures that sensitive byte fields are overwritten when the struct is dropped.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ConnectionCredentials {
    pub connection_id: String,
    /// Session key derived from X25519 + HKDF. Zeroized on expiry.
    #[serde(with = "serde_bytes")]
    pub connection_key: Vec<u8>,
    pub key_id: String,
    #[serde(with = "serde_bytes")]
    pub device_private_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub device_public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub vault_public_key: Vec<u8>,
    /// JWT+seed block for the device's scoped NATS account.
    pub message_space_token: String,
    pub message_space_url: String,
    pub owner_guid: String,
    pub owner_name: String,
    pub session_id: String,
    /// Unix seconds at which the current session expires. 0 = unknown/expired.
    #[serde(default)]
    pub session_expires_at: i64,
    /// User-approved session duration in seconds, for re-request on extension.
    #[serde(default)]
    pub session_duration_seconds: i64,
}

/// The on-disk JSON format for encrypted credentials. v2.
///
/// `binding` records which keystore path was used to encrypt the
/// store so a subsequent `load` can go straight to the right source
/// (the keyring path on a system whose keyring is now broken would
/// otherwise silently fall back to the machine-bound key and fail to
/// decrypt the keyring-bound blob).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedStore {
    pub version: i32,
    /// "keyring" or "machine". See [`BindingMode`].
    pub binding: String,
    /// 24-byte XChaCha20-Poly1305 nonce. Fresh per save.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns the OS-appropriate config directory path for credentials.
///
/// - Linux: `$XDG_CONFIG_HOME/vettid-desktop` (typically `~/.config/vettid-desktop`)
/// - macOS: `~/Library/Application Support/vettid-desktop`
pub fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(CONFIG_SUBDIR)
}

/// Encrypt credentials and write them to `connection.enc` in `config_dir`.
///
/// The encryption key comes from the OS keyring (or the machine-bound
/// fallback when the keyring is unavailable). No user input. The file
/// is written with mode 0600 (owner read/write only).
///
/// SECURITY: Intermediate key material is zeroized after use; the
/// `MasterKey` returned by the keystore zeroizes on drop.
pub fn save(config_dir: &Path, creds: &ConnectionCredentials) -> Result<BindingMode, CredentialError> {
    let master = keystore::fetch_or_create_master_key()?;
    let binding = master.binding;

    let mut plaintext = serde_json::to_vec(creds)
        .map_err(|e| CredentialError::SerializationError(format!("marshal credentials: {}", e)))?;

    let (nonce, ciphertext) = encrypt_xchacha20(&master.key, &plaintext)?;
    plaintext.zeroize();
    // `master` zeroizes on drop.

    let store = EncryptedStore {
        version: STORE_VERSION,
        binding: binding.as_str().to_string(),
        nonce,
        ciphertext,
    };

    let data = serde_json::to_vec(&store)
        .map_err(|e| CredentialError::SerializationError(format!("marshal store: {}", e)))?;

    fs::create_dir_all(config_dir)
        .map_err(|e| CredentialError::IoError(format!("create config dir: {}", e)))?;

    let path = config_dir.join(CREDENTIAL_FILE);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| CredentialError::IoError(format!("open {}: {}", path.display(), e)))?;

    file.write_all(&data)
        .map_err(|e| CredentialError::IoError(format!("write {}: {}", path.display(), e)))?;

    Ok(binding)
}

/// Read and decrypt credentials from `connection.enc` in `config_dir`.
///
/// Uses the master key from the same keystore source the file was
/// encrypted under (recorded in the file's `binding` header).
/// Returns `(credentials, binding_mode)`.
pub fn load(config_dir: &Path) -> Result<(ConnectionCredentials, BindingMode), CredentialError> {
    let store = read_store(config_dir)?;
    let binding = BindingMode::from_str(&store.binding).ok_or_else(|| {
        CredentialError::SerializationError(format!("unknown binding mode: {}", store.binding))
    })?;
    let master = keystore::fetch_for_binding(binding)?;
    let creds = decrypt_store(&store, &master.key)?;
    Ok((creds, binding))
}

/// Check whether a credential file exists in `config_dir`.
pub fn exists(config_dir: &Path) -> bool {
    let path = config_dir.join(CREDENTIAL_FILE);
    path.exists()
}

/// Delete the credential file from `config_dir`.
pub fn delete(config_dir: &Path) -> Result<(), CredentialError> {
    let path = config_dir.join(CREDENTIAL_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CredentialError::IoError(format!(
            "remove {}: {}",
            path.display(),
            e
        ))),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read and parse the encrypted store from disk.
fn read_store(config_dir: &Path) -> Result<EncryptedStore, CredentialError> {
    let path = config_dir.join(CREDENTIAL_FILE);
    let data = fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CredentialError::NotFound(path.display().to_string())
        } else {
            CredentialError::IoError(format!("read {}: {}", path.display(), e))
        }
    })?;

    let store: EncryptedStore = serde_json::from_slice(&data)
        .map_err(|e| CredentialError::SerializationError(format!("parse store: {}", e)))?;

    if store.version != STORE_VERSION {
        return Err(CredentialError::UnsupportedVersion(store.version));
    }

    Ok(store)
}

/// Decrypt the store with the given 32-byte master key.
fn decrypt_store(
    store: &EncryptedStore,
    key: &[u8; 32],
) -> Result<ConnectionCredentials, CredentialError> {
    if store.nonce.len() != NONCE_SIZE {
        return Err(CredentialError::CryptoError(format!(
            "bad nonce length: expected {}, got {}",
            NONCE_SIZE,
            store.nonce.len(),
        )));
    }
    let nonce = XNonce::from_slice(&store.nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CredentialError::CryptoError(format!("cipher: {}", e)))?;
    let mut plaintext = cipher
        .decrypt(nonce, store.ciphertext.as_slice())
        .map_err(|e| CredentialError::CryptoError(format!("decrypt: {}", e)))?;

    let creds: ConnectionCredentials = serde_json::from_slice(&plaintext)
        .map_err(|e| CredentialError::SerializationError(format!("parse credentials: {}", e)))?;

    plaintext.zeroize();
    Ok(creds)
}

/// Encrypt plaintext with XChaCha20-Poly1305. Returns `(nonce, ciphertext)`.
fn encrypt_xchacha20(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CredentialError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CredentialError::CryptoError(format!("cipher: {}", e)))?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CredentialError::CryptoError(format!("encrypt: {}", e)))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xchacha20_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello, VettID desktop!";
        let (nonce, ct) = encrypt_xchacha20(&key, plaintext).expect("encrypt");
        assert_eq!(nonce.len(), NONCE_SIZE);

        // Re-decrypt by hand (the public `decrypt_store` requires a
        // round-trip through the keystore, which the CI tests can't
        // exercise without a real Secret Service).
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let pt = cipher
            .decrypt(XNonce::from_slice(&nonce), ct.as_slice())
            .expect("decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let key = [0x42u8; 32];
        let bad = [0x43u8; 32];
        let (nonce, ct) = encrypt_xchacha20(&key, b"secret").expect("encrypt");
        let cipher = XChaCha20Poly1305::new_from_slice(&bad).unwrap();
        let result = cipher.decrypt(XNonce::from_slice(&nonce), ct.as_slice());
        assert!(result.is_err());
    }
}
