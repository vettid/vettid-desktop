//! Per-call E2EE key derivation, matching Android's `CallFrameCryptor`.
//!
//! The connection key (32-byte X25519-derived secret stored in
//! [`crate::state::AppState::connection_key`]) is used as the HKDF input
//! key material. Call IDs serve as the HKDF salt so two calls between the
//! same peers produce independent keys, giving forward secrecy at the
//! per-call grain.
//!
//! Both sides (caller and callee) derive the same key independently — no
//! key exchange happens during call setup itself.
//!
//! ## Format
//!
//! - HKDF-SHA256
//! - IKM:  the connection key
//! - Salt: `call_id` bytes
//! - Info: literal `"vettid-e2ee-call-key"` (must match Android exactly)
//! - L:    16 bytes (AES-128-GCM key length)
//!
//! ## Why 128-bit and not 256-bit
//!
//! libwebrtc's SFrame implementation uses AES-128-GCM. Android pulls a
//! 32-byte secret from the vault but only the first 128 bits are used by
//! the cryptor. We mirror that here so the two stacks stay
//! bit-compatible.

use hkdf::Hkdf;
use sha2::Sha256;

const CALL_KEY_INFO: &[u8] = b"vettid-e2ee-call-key";
/// AES-128-GCM key length.
pub const CALL_KEY_LEN: usize = 16;

/// Derive a per-call AES-128-GCM key from the persistent connection key.
///
/// `connection_key` MUST be the 32-byte X25519-derived shared secret
/// stored alongside the device credentials — same key used to encrypt
/// every device_op_request. `call_id` MUST be the same string both peers
/// see in the call.initiate signaling envelope.
pub fn derive_call_key(connection_key: &[u8; 32], call_id: &str) -> [u8; CALL_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(call_id.as_bytes()), connection_key);
    let mut out = [0u8; CALL_KEY_LEN];
    hk.expand(CALL_KEY_INFO, &mut out)
        .expect("HKDF expand into 16 bytes never fails");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let conn_key = [7u8; 32];
        let a = derive_call_key(&conn_key, "call-abc");
        let b = derive_call_key(&conn_key, "call-abc");
        assert_eq!(a, b);
    }

    #[test]
    fn different_call_id_different_key() {
        let conn_key = [7u8; 32];
        let a = derive_call_key(&conn_key, "call-abc");
        let b = derive_call_key(&conn_key, "call-xyz");
        assert_ne!(a, b);
    }

    #[test]
    fn different_connection_key_different_key() {
        let a = derive_call_key(&[7u8; 32], "call-abc");
        let b = derive_call_key(&[8u8; 32], "call-abc");
        assert_ne!(a, b);
    }

    #[test]
    fn key_is_16_bytes() {
        let key = derive_call_key(&[0u8; 32], "anything");
        assert_eq!(key.len(), 16);
    }
}
