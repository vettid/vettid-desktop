//! webrtc-rs binding for the [`crate::crypto::frame_cryptor`] wire format.
//!
//! The pure encrypt/decrypt + key derivation live in
//! [`crate::crypto::frame_cryptor`] so they can be tested without the full
//! webrtc-rs/cpal/ALSA stack. This file holds the webrtc-rs-aware glue:
//!
//! - [`CryptorConfig`] — the per-call key wrapper that the interceptor will
//!   eventually consume,
//! - the `Interceptor` / `RTPWriterInterceptor` / `RTPReaderInterceptor`
//!   impls (TODO — next session's work),
//! - the registration helper that hangs the interceptor off
//!   `APIBuilder::with_interceptor_registry` in
//!   [`crate::webrtc::session::CallSession::new`] (TODO).
//!
//! See `crypto/frame_cryptor.rs` for the wire format, the libwebrtc
//! reference, and the interop test vector.

#![cfg(feature = "webrtc")]

use crate::crypto::frame_cryptor::{derive_aes_key, AES_KEY_LEN};

/// Per-call configuration for the future webrtc-rs interceptor.
#[derive(Clone, Copy)]
pub struct CryptorConfig {
    /// AES-128-GCM key the interceptor uses for every frame of this call.
    pub key: [u8; AES_KEY_LEN],
}

impl CryptorConfig {
    /// Build a cryptor config from the 32-byte shared secret the vault hands
    /// the desktop on call setup, mirroring Android's
    /// `enableFrameEncryption(event.sharedSecret)` path in
    /// `vettid-android/.../features/calling/CallManager.kt`.
    pub fn from_vault_secret(secret: &[u8; 32]) -> Self {
        Self { key: derive_aes_key(secret) }
    }
}
