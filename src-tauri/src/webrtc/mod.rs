//! WebRTC peer-connection management for voice/video calls.
//!
//! Compiled only when the `webrtc` feature is enabled. Without it, the call
//! signaling commands continue to work (SDP/ICE messages flow through the
//! vault) but no media is exchanged — useful for validating the call UX
//! without paying the multi-minute webrtc-rs compile cost.
//!
//! ## Architecture
//!
//! Each call owns one [`session::CallSession`] which wraps an
//! `RTCPeerConnection`. The session is created on call.initiate (caller) or
//! call.answer (callee). It generates SDP via `create_offer`/`create_answer`
//! and emits ICE candidates through a Tokio mpsc channel that the call
//! signaling layer publishes to the peer's vault.
//!
//! Media is currently audio-only via webrtc-rs's built-in Opus path. Video
//! capture (camera) and screen sharing are deferred to a follow-up — the
//! `track::add_audio_track` helper is the single seam where additional
//! tracks plug in.
//!
//! ## E2EE frame encryption
//!
//! Implemented as a webrtc-rs `Interceptor` — see [`cryptor`]. Encrypts +
//! decrypts every RTP audio payload using AES-128-GCM in the LiveKit
//! `FrameCryptor` wire format that Android's libwebrtc emits. The
//! interceptor is registered on the API builder iff
//! [`session::CallSession::new`] gets a `Some(CryptorConfig)`; the vault
//! signaling path that delivers the per-call 32-byte shared secret to the
//! desktop is still TODO, so today's callers pass `None` and calls go
//! over transport SRTP only (Android-side reports MISSINGKEY).

#![cfg(feature = "webrtc")]

pub mod audio;
pub mod cryptor;
pub mod session;
pub mod turn;

pub use session::CallSession;
