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
//! Not yet implemented. The Android `CallFrameCryptor` derives a per-call
//! shared secret from the X25519 connection key + HKDF and AES-128-GCMs each
//! media frame. Plumbing the equivalent through webrtc-rs requires hooking
//! `RTCRtpSender::insertable_streams` (or its equivalent on this version of
//! the crate) — placeholder wired in [`session::CallSession::new`] so it's
//! the obvious next addition.

#![cfg(feature = "webrtc")]

pub mod audio;
pub mod cryptor;
pub mod session;

pub use session::CallSession;
