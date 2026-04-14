//! Encrypted credential storage for the VettID desktop app.
//!
//! Credentials are encrypted at rest using:
//!
//! ```text
//! passphrase + platform_key -> Argon2id -> 256-bit key -> XChaCha20-Poly1305
//! ```
//!
//! The platform key is derived from machine attributes, binding credentials
//! to the specific machine where they were created. 4-of-5 attribute tolerance
//! allows decryption after minor hardware changes (e.g., NIC replacement).
//!
//! On-disk format: JSON-serialized `EncryptedStore` at `~/.config/vettid-desktop/connection.enc`

use std::fmt;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use argon2::Argon2;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::fingerprint::platform_linux::{
    collect_machine_attributes, compute_machine_fingerprint, four_of_five_combinations,
    FingerprintError,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current version of the encrypted store format.
const STORE_VERSION: i32 = 1;

/// Credential file name within the config directory.
const CREDENTIAL_FILE: &str = "connection.enc";

/// Subdirectory name appended to the OS config dir.
const CONFIG_SUBDIR: &str = "vettid-desktop";

/// Salt size for Argon2id (16 bytes).
const ARGON2_SALT_SIZE: usize = 16;

/// Derived key size (32 bytes / 256 bits).
const ARGON2_KEY_SIZE: usize = 32;

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
    /// Key derivation (Argon2id) failed.
    KeyDerivationError(String),
    /// Fingerprint collection or computation failed.
    FingerprintError(FingerprintError),
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
            CredentialError::KeyDerivationError(msg) => {
                write!(f, "key derivation error: {}", msg)
            }
            CredentialError::FingerprintError(e) => write!(f, "fingerprint error: {}", e),
            CredentialError::NotFound(path) => write!(f, "credential file not found: {}", path),
            CredentialError::UnsupportedVersion(v) => {
                write!(f, "unsupported store version: {}", v)
            }
        }
    }
}

impl std::error::Error for CredentialError {}

impl From<FingerprintError> for CredentialError {
    fn from(e: FingerprintError) -> Self {
        CredentialError::FingerprintError(e)
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Argon2id parameters stored alongside the encrypted data so that future
/// versions can increase the work factor without breaking existing stores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Number of iterations (time cost).
    pub time: u32,
    /// Memory cost in KiB.
    pub memory: u32,
    /// Degree of parallelism (threads).
    pub threads: u32,
}

impl Default for Argon2Params {
    /// Default parameters matching the VettID design doc:
    /// Time=3, Memory=64 MB (65536 KiB), Threads=4.
    fn default() -> Self {
        Argon2Params {
            time: 3,
            memory: 65536, // 64 MB
            threads: 4,
        }
    }
}

/// All sensitive material for an active desktop-to-vault connection.
///
/// This struct is JSON-serialized before encryption. The `Zeroize` derive
/// ensures that sensitive byte fields are overwritten when the struct is dropped.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ConnectionCredentials {
    pub connection_id: String,
    #[serde(with = "serde_bytes")]
    pub connection_key: Vec<u8>,
    pub key_id: String,
    #[serde(with = "serde_bytes")]
    pub device_private_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub device_public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub vault_public_key: Vec<u8>,
    pub message_space_token: String,
    pub message_space_url: String,
    pub owner_guid: String,
    pub owner_name: String,
    pub session_id: String,
}

/// The on-disk JSON format for encrypted credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedStore {
    pub version: i32,
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    pub argon2_params: Argon2Params,
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
/// The encryption key is derived from `passphrase || platform_key` via Argon2id.
/// The file is written with mode 0600 (owner read/write only).
///
/// SECURITY: Intermediate key material is zeroized after use.
pub fn save(
    config_dir: &Path,
    creds: &ConnectionCredentials,
    passphrase: &[u8],
    platform_key: &[u8],
) -> Result<(), CredentialError> {
    // Serialize credentials to JSON
    let mut plaintext = serde_json::to_vec(creds)
        .map_err(|e| CredentialError::SerializationError(format!("marshal credentials: {}", e)))?;

    // Generate random salt
    let salt = generate_salt()?;

    // Derive key via Argon2id(passphrase || platform_key, salt)
    let params = Argon2Params::default();
    let mut key = derive_key(passphrase, platform_key, &salt, &params)?;

    // Encrypt with XChaCha20-Poly1305
    let ciphertext = encrypt_xchacha20(&key, &plaintext)?;

    // SECURITY: Zero sensitive intermediate data
    key.zeroize();
    plaintext.zeroize();

    // Build the on-disk store
    let store = EncryptedStore {
        version: STORE_VERSION,
        salt,
        ciphertext,
        argon2_params: params,
    };

    let data = serde_json::to_vec(&store)
        .map_err(|e| CredentialError::SerializationError(format!("marshal store: {}", e)))?;

    // Ensure the config directory exists
    fs::create_dir_all(config_dir)
        .map_err(|e| CredentialError::IoError(format!("create config dir: {}", e)))?;

    // Write with mode 0600
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

    Ok(())
}

/// Read and decrypt credentials from `connection.enc` in `config_dir`.
///
/// Uses a single platform key (no tolerance). For tolerance-aware loading,
/// use `load_with_tolerance`.
pub fn load(
    config_dir: &Path,
    passphrase: &[u8],
    platform_key: &[u8],
) -> Result<ConnectionCredentials, CredentialError> {
    let store = read_store(config_dir)?;
    decrypt_store(&store, passphrase, platform_key)
}

/// Load credentials with 4-of-5 fingerprint tolerance.
///
/// Attempts decryption in this order:
/// 1. Full machine fingerprint (all 5 attributes)
/// 2. Each of the 5 possible 4-of-5 attribute combinations
///
/// If a 4-of-5 combination succeeds, the store is re-encrypted with the
/// current full fingerprint to "heal" after a minor hardware change.
///
/// Returns `(credentials, was_re_encrypted)`.
pub fn load_with_tolerance(
    config_dir: &Path,
    passphrase: &str,
) -> Result<(ConnectionCredentials, bool), CredentialError> {
    let store = read_store(config_dir)?;

    // Collect current machine attributes
    let attrs = collect_machine_attributes()?;

    // Try full fingerprint first
    let full_key = compute_machine_fingerprint(&attrs);
    if let Ok(creds) = decrypt_store(&store, passphrase.as_bytes(), &full_key) {
        return Ok((creds, false));
    }

    // Full fingerprint failed -- try 4-of-5 combinations
    let combos = four_of_five_combinations(&attrs);
    for combo in &combos {
        let combo_key = compute_machine_fingerprint(combo);
        if let Ok(creds) = decrypt_store(&store, passphrase.as_bytes(), &combo_key) {
            // Re-encrypt with the current full fingerprint
            if let Err(e) = save(config_dir, &creds, passphrase.as_bytes(), &full_key) {
                eprintln!(
                    "WARNING: Failed to re-encrypt credentials with updated fingerprint: {}",
                    e
                );
                // Return creds anyway -- we decrypted successfully
            }
            return Ok((creds, true));
        }
    }

    Err(CredentialError::CryptoError(
        "decrypt credentials: wrong passphrase or different machine (all fingerprint combinations failed)".to_string(),
    ))
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

/// Decrypt the store with the given passphrase and platform key.
fn decrypt_store(
    store: &EncryptedStore,
    passphrase: &[u8],
    platform_key: &[u8],
) -> Result<ConnectionCredentials, CredentialError> {
    let mut key = derive_key(passphrase, platform_key, &store.salt, &store.argon2_params)?;

    let plaintext_result = decrypt_xchacha20(&key, &store.ciphertext);
    key.zeroize();

    let mut plaintext = plaintext_result?;

    let creds: ConnectionCredentials = serde_json::from_slice(&plaintext)
        .map_err(|e| CredentialError::SerializationError(format!("parse credentials: {}", e)))?;

    plaintext.zeroize();
    Ok(creds)
}

/// Derive a 32-byte key from passphrase + platform_key using Argon2id.
///
/// The passphrase and platform key are concatenated as the password input.
/// This matches the Go agent connector's `DeriveKey` function.
fn derive_key(
    passphrase: &[u8],
    platform_key: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<[u8; ARGON2_KEY_SIZE], CredentialError> {
    // Concatenate passphrase + platform_key as input
    let mut input = Vec::with_capacity(passphrase.len() + platform_key.len());
    input.extend_from_slice(passphrase);
    input.extend_from_slice(platform_key);

    let argon2_params = argon2::Params::new(
        params.memory,
        params.time,
        params.threads,
        Some(ARGON2_KEY_SIZE),
    )
    .map_err(|e| CredentialError::KeyDerivationError(format!("invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2_params);

    let mut key = [0u8; ARGON2_KEY_SIZE];
    argon2
        .hash_password_into(&input, salt, &mut key)
        .map_err(|e| CredentialError::KeyDerivationError(format!("Argon2id failed: {}", e)))?;

    input.zeroize();
    Ok(key)
}

/// Generate a random salt for Argon2id.
fn generate_salt() -> Result<Vec<u8>, CredentialError> {
    let mut salt = vec![0u8; ARGON2_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    Ok(salt)
}

/// Encrypt plaintext with XChaCha20-Poly1305.
///
/// Output format: nonce (24 bytes) || ciphertext + authentication tag
fn encrypt_xchacha20(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CredentialError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CredentialError::CryptoError(format!("cipher creation failed: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CredentialError::CryptoError(format!("encryption failed: {}", e)))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt ciphertext produced by `encrypt_xchacha20`.
///
/// Input format: nonce (24 bytes) || ciphertext + authentication tag
fn decrypt_xchacha20(key: &[u8; 32], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, CredentialError> {
    let min_size = NONCE_SIZE + 16; // nonce + Poly1305 tag
    if ciphertext_with_nonce.len() < min_size {
        return Err(CredentialError::CryptoError(format!(
            "ciphertext too short: need at least {} bytes, got {}",
            min_size,
            ciphertext_with_nonce.len()
        )));
    }

    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(NONCE_SIZE);
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CredentialError::CryptoError(format!("cipher creation failed: {}", e)))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CredentialError::CryptoError(format!("decryption failed: {}", e)))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_credentials() -> ConnectionCredentials {
        ConnectionCredentials {
            connection_id: "conn-test-123".to_string(),
            connection_key: vec![1, 2, 3, 4, 5, 6, 7, 8],
            key_id: "key-test-456".to_string(),
            device_private_key: vec![10, 20, 30, 40],
            device_public_key: vec![50, 60, 70, 80],
            vault_public_key: vec![90, 100, 110, 120],
            message_space_token: "nats-token-abc".to_string(),
            message_space_url: "nats://localhost:4222".to_string(),
            owner_guid: "VET-OWNER123".to_string(),
            owner_name: "Test User".to_string(),
            session_id: "session-789".to_string(),
        }
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = TempDir::new().expect("create temp dir");
        let creds = test_credentials();
        let passphrase = b"test-passphrase";
        let platform_key = [0x42u8; 32];

        save(dir.path(), &creds, passphrase, &platform_key).expect("save should succeed");

        let loaded = load(dir.path(), passphrase, &platform_key).expect("load should succeed");

        assert_eq!(loaded.connection_id, creds.connection_id);
        assert_eq!(loaded.connection_key, creds.connection_key);
        assert_eq!(loaded.key_id, creds.key_id);
        assert_eq!(loaded.device_private_key, creds.device_private_key);
        assert_eq!(loaded.device_public_key, creds.device_public_key);
        assert_eq!(loaded.vault_public_key, creds.vault_public_key);
        assert_eq!(loaded.message_space_token, creds.message_space_token);
        assert_eq!(loaded.message_space_url, creds.message_space_url);
        assert_eq!(loaded.owner_guid, creds.owner_guid);
        assert_eq!(loaded.owner_name, creds.owner_name);
        assert_eq!(loaded.session_id, creds.session_id);
    }

    #[test]
    fn test_load_wrong_passphrase() {
        let dir = TempDir::new().expect("create temp dir");
        let creds = test_credentials();
        let platform_key = [0x42u8; 32];

        save(dir.path(), &creds, b"correct", &platform_key).expect("save should succeed");

        let result = load(dir.path(), b"wrong", &platform_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_wrong_platform_key() {
        let dir = TempDir::new().expect("create temp dir");
        let creds = test_credentials();

        save(dir.path(), &creds, b"pass", &[0x42u8; 32]).expect("save should succeed");

        let result = load(dir.path(), b"pass", &[0x43u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_exists_and_delete() {
        let dir = TempDir::new().expect("create temp dir");
        let creds = test_credentials();
        let platform_key = [0x42u8; 32];

        assert!(!exists(dir.path()));

        save(dir.path(), &creds, b"pass", &platform_key).expect("save");
        assert!(exists(dir.path()));

        delete(dir.path()).expect("delete");
        assert!(!exists(dir.path()));
    }

    #[test]
    fn test_delete_nonexistent_is_ok() {
        let dir = TempDir::new().expect("create temp dir");
        // Should not error when file does not exist
        delete(dir.path()).expect("delete nonexistent should succeed");
    }

    #[test]
    fn test_load_nonexistent_returns_not_found() {
        let dir = TempDir::new().expect("create temp dir");
        let result = load(dir.path(), b"pass", &[0u8; 32]);
        assert!(matches!(result, Err(CredentialError::NotFound(_))));
    }

    #[test]
    fn test_file_permissions() {
        let dir = TempDir::new().expect("create temp dir");
        let creds = test_credentials();

        save(dir.path(), &creds, b"pass", &[0x42u8; 32]).expect("save");

        let path = dir.path().join(CREDENTIAL_FILE);
        let metadata = fs::metadata(&path).expect("stat file");
        let permissions = metadata.permissions();
        // On Unix, check that the file is 0600 (owner rw only)
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_encrypt_decrypt_xchacha20_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello, VettID desktop!";

        let encrypted = encrypt_xchacha20(&key, plaintext).expect("encrypt");
        let decrypted = decrypt_xchacha20(&key, &encrypted).expect("decrypt");

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let passphrase = b"test-passphrase";
        let platform_key = [0x42u8; 32];
        let salt = vec![0xAA; ARGON2_SALT_SIZE];
        let params = Argon2Params::default();

        let key1 = derive_key(passphrase, &platform_key, &salt, &params).expect("derive key 1");
        let key2 = derive_key(passphrase, &platform_key, &salt, &params).expect("derive key 2");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_with_different_inputs() {
        let salt = vec![0xAA; ARGON2_SALT_SIZE];
        let params = Argon2Params::default();

        let key1 = derive_key(b"pass1", &[0x42u8; 32], &salt, &params).expect("key1");
        let key2 = derive_key(b"pass2", &[0x42u8; 32], &salt, &params).expect("key2");
        assert_ne!(key1, key2);
    }
}
