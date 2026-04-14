//! E2EE frame cryptor — placeholder for SFrame interop with Android.
//!
//! ## Status
//!
//! **Not yet implemented.** The Android side uses libwebrtc's native
//! `FrameCryptor` (SFrame, RFC 9605 draft format), which webrtc-rs does not
//! provide out of the box. To make calls between desktop and Android E2EE,
//! we need to implement an [`webrtc::interceptor::Interceptor`] that
//! encrypts outbound RTP payloads and decrypts inbound ones in a format
//! Android's libwebrtc accepts.
//!
//! The per-call AES-128-GCM key derivation is already in place — see
//! [`crate::crypto::call_key::derive_call_key`] which mirrors Android's
//! HKDF-on-connection-key+call-id construction byte-for-byte. The remaining
//! work is purely the wire format.
//!
//! ## What to implement
//!
//! 1. **SFrame header**: 1 byte config + variable-length keyId + variable
//!    counter. Spec: <https://datatracker.ietf.org/doc/draft-ietf-sframe-enc/>
//!    Reference impl: libwebrtc/api/frame_transformer_factory.cc
//!    (the C++ side of Android's FrameCryptor).
//! 2. **Nonce derivation**: 12-byte AES-GCM nonce from frame counter + key
//!    salt; matches what libwebrtc's `FrameCryptor` uses so the two stacks
//!    can decrypt each other's frames.
//! 3. **Codec-aware split**: skip the first N bytes of the payload (codec
//!    header that needs to stay readable for SFU routing). For Opus this
//!    is 0 bytes; for VP8/H.264 there's a codec-specific prefix.
//! 4. **Interceptor wiring**: implement `Interceptor`,
//!    `RTPWriterInterceptor`, `RTPReaderInterceptor`. Register via
//!    `APIBuilder::with_interceptor_registry`.
//! 5. **Plumbing**: pass `derive_call_key(connection_key, call_id)` into
//!    the interceptor at session construction time.
//!
//! ## Reference material
//!
//! - Android: `app/src/main/java/com/vettid/app/features/calling/CallFrameCryptor.kt`
//! - libwebrtc SFrame: `webrtc/api/frame_transformer_factory.h`
//! - SFrame draft: <https://datatracker.ietf.org/doc/draft-ietf-sframe-enc/>
//! - webrtc-rs interceptor sample: `examples/interceptor/`
//!
//! Until this is wired, calls between desktop and Android still establish
//! and exchange media — they're just NOT end-to-end encrypted at the media
//! layer. (The signaling channel and connection keys remain end-to-end
//! encrypted via the existing crypto stack.)

#![cfg(feature = "webrtc")]

use crate::crypto::call_key::{derive_call_key, CALL_KEY_LEN};

/// Configuration for a future SFrame interceptor.
///
/// This struct exists so call setup can pass the per-call key into the
/// session today; once the interceptor lands, it will read this directly.
#[derive(Clone, Copy)]
pub struct CryptorConfig {
    /// AES-128-GCM key derived per-call from the persistent connection key.
    pub key: [u8; CALL_KEY_LEN],
}

impl CryptorConfig {
    /// Derive the per-call configuration. `connection_key` is the 32-byte
    /// shared secret stored in `AppState.connection_key`.
    pub fn derive(connection_key: &[u8; 32], call_id: &str) -> Self {
        Self {
            key: derive_call_key(connection_key, call_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_derives_consistently() {
        let cfg_a = CryptorConfig::derive(&[1u8; 32], "call-1");
        let cfg_b = CryptorConfig::derive(&[1u8; 32], "call-1");
        assert_eq!(cfg_a.key, cfg_b.key);
    }
}
