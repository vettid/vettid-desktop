//! webrtc-rs binding for the [`crate::crypto::frame_cryptor`] wire format.
//!
//! The pure encrypt/decrypt + key derivation live in
//! [`crate::crypto::frame_cryptor`] so they can be tested without the full
//! webrtc-rs/cpal/ALSA stack. This file holds the webrtc-rs-aware glue:
//!
//! - [`CryptorConfig`] — the per-call key wrapper produced from the
//!   32-byte shared secret the vault hands the desktop on call setup.
//! - [`FrameCryptorInterceptor`] — implements webrtc-rs's `Interceptor`
//!   trait. `bind_local_stream` wraps the outbound `RTPWriter` with an
//!   encrypting variant; `bind_remote_stream` wraps the inbound
//!   `RTPReader` with a decrypting variant. Built per peer-connection via
//!   [`FrameCryptorBuilder`] and registered through
//!   [`CryptorConfig::register`] before `APIBuilder::build`.
//!
//! ## IV scheme
//!
//! Outbound frames use `BE32(ssrc) || BE64(monotonic_counter)` as the
//! 12-byte AES-GCM nonce, where the counter is per-SSRC and starts at 0.
//! libwebrtc's encryptor uses a different `(ssrc, ts, ts - send_count)`
//! shape, but its DEcryptor reads the IV straight off the wire — so any
//! IV that's unique per `(key, IV)` works for interop. The counter is
//! 64-bit which gives `2^64` frames per SSRC before wrap; Opus at 50 fps
//! is `2^32` years.
//!
//! ## Codec scope
//!
//! Audio-only Opus today. Non-Opus streams pass through unchanged with a
//! warning logged. Video / H.264 / VP8 need codec-aware unencrypted
//! prefixes (and H.264 needs RBSP escape/unescape on the ciphertext);
//! those land when video lands.
//!
//! ## Failure modes
//!
//! - **Encrypt error** — propagates as `interceptor::Error::Other`. Should
//!   never happen in practice (aes-gcm's `encrypt` only fails on extreme
//!   payload sizes); if it does, the RTP write fails and the call breaks.
//! - **Decrypt error** — logged at WARN and the frame is dropped (payload
//!   replaced with an empty `Bytes`), mirroring libwebrtc's
//!   `kDecryptionFailed` behavior. The audio decoder treats the empty
//!   frame as a silence gap rather than feeding garbage to Opus. One bad
//!   frame doesn't kill the call.

#![cfg(feature = "webrtc")]

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::Mutex;
use webrtc::interceptor::registry::Registry;
use webrtc::interceptor::stream_info::StreamInfo;
use webrtc::interceptor::{
    Attributes, Error as InterceptorError, Interceptor, InterceptorBuilder, RTCPReader, RTCPWriter,
    RTPReader, RTPWriter,
};
use webrtc::rtp;

use crate::crypto::frame_cryptor::{
    decrypt_frame, derive_aes_key, encrypt_frame, AES_KEY_LEN, IV_LEN, OPUS_UNENCRYPTED_BYTES,
};

/// Per-call configuration for the webrtc-rs interceptor.
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

    /// Add the frame cryptor to an `interceptor::Registry`. Call this on
    /// the registry passed to `APIBuilder::with_interceptor_registry` so
    /// the chain wraps every outbound + inbound RTP stream with E2EE.
    pub fn register(self, registry: &mut Registry) {
        registry.add(Box::new(FrameCryptorBuilder { config: self }));
    }
}

struct FrameCryptorBuilder {
    config: CryptorConfig,
}

impl InterceptorBuilder for FrameCryptorBuilder {
    fn build(
        &self,
        _id: &str,
    ) -> std::result::Result<Arc<dyn Interceptor + Send + Sync>, InterceptorError> {
        Ok(Arc::new(FrameCryptorInterceptor { key: self.config.key }))
    }
}

/// webrtc-rs `Interceptor` that encrypts outbound + decrypts inbound RTP
/// payloads using the [LiveKit FrameCryptor wire
/// format](crate::crypto::frame_cryptor).
struct FrameCryptorInterceptor {
    key: [u8; AES_KEY_LEN],
}

#[async_trait]
impl Interceptor for FrameCryptorInterceptor {
    async fn bind_rtcp_reader(
        &self,
        reader: Arc<dyn RTCPReader + Send + Sync>,
    ) -> Arc<dyn RTCPReader + Send + Sync> {
        // RTCP is not encrypted by FrameCryptor — only RTP media payloads.
        reader
    }

    async fn bind_rtcp_writer(
        &self,
        writer: Arc<dyn RTCPWriter + Send + Sync>,
    ) -> Arc<dyn RTCPWriter + Send + Sync> {
        writer
    }

    async fn bind_local_stream(
        &self,
        info: &StreamInfo,
        writer: Arc<dyn RTPWriter + Send + Sync>,
    ) -> Arc<dyn RTPWriter + Send + Sync> {
        let codec = match CodecKind::from_mime(&info.mime_type) {
            Some(c) => c,
            None => {
                log::warn!(
                    "frame cryptor: outbound codec {:?} not supported \
                     (ssrc={}); frames will pass through unencrypted",
                    info.mime_type,
                    info.ssrc,
                );
                return writer;
            }
        };
        Arc::new(EncryptingWriter {
            key: self.key,
            ssrc: info.ssrc,
            counter: Mutex::new(0),
            unencrypted_bytes: codec.unencrypted_bytes(),
            next: writer,
        })
    }

    async fn unbind_local_stream(&self, _info: &StreamInfo) {}

    async fn bind_remote_stream(
        &self,
        info: &StreamInfo,
        reader: Arc<dyn RTPReader + Send + Sync>,
    ) -> Arc<dyn RTPReader + Send + Sync> {
        let codec = match CodecKind::from_mime(&info.mime_type) {
            Some(c) => c,
            None => {
                log::warn!(
                    "frame cryptor: inbound codec {:?} not supported \
                     (ssrc={}); frames will pass through undecrypted",
                    info.mime_type,
                    info.ssrc,
                );
                return reader;
            }
        };
        Arc::new(DecryptingReader {
            key: self.key,
            unencrypted_bytes: codec.unencrypted_bytes(),
            next: reader,
        })
    }

    async fn unbind_remote_stream(&self, _info: &StreamInfo) {}

    async fn close(&self) -> std::result::Result<(), InterceptorError> {
        Ok(())
    }
}

/// Codec-aware unencrypted-prefix policy (see `get_unencrypted_bytes` in
/// the libwebrtc C++ reference). Only Opus is supported today — extend
/// when video lands.
#[derive(Clone, Copy)]
enum CodecKind {
    Opus,
}

impl CodecKind {
    fn from_mime(mime: &str) -> Option<Self> {
        // webrtc-rs's media engine uses lowercase mime types like
        // "audio/opus"; tolerate stray case from custom codecs.
        if mime.eq_ignore_ascii_case("audio/opus") {
            Some(CodecKind::Opus)
        } else {
            None
        }
    }

    fn unencrypted_bytes(self) -> usize {
        match self {
            CodecKind::Opus => OPUS_UNENCRYPTED_BYTES,
        }
    }
}

struct EncryptingWriter {
    key: [u8; AES_KEY_LEN],
    ssrc: u32,
    /// Per-SSRC monotonic counter feeding the IV. Wrapped in a `Mutex`
    /// because `write` is called concurrently from the RTP send loop.
    counter: Mutex<u64>,
    unencrypted_bytes: usize,
    next: Arc<dyn RTPWriter + Send + Sync>,
}

impl EncryptingWriter {
    fn make_iv(&self, counter: u64) -> [u8; IV_LEN] {
        // BE32(ssrc) || BE64(counter). Unique per (key, frame) as required
        // by AES-GCM; see module doc-comment for why this differs from
        // libwebrtc's (ssrc, ts, ts-count) shape.
        let mut iv = [0u8; IV_LEN];
        iv[..4].copy_from_slice(&self.ssrc.to_be_bytes());
        iv[4..].copy_from_slice(&counter.to_be_bytes());
        iv
    }
}

#[async_trait]
impl RTPWriter for EncryptingWriter {
    async fn write(
        &self,
        pkt: &rtp::packet::Packet,
        attributes: &Attributes,
    ) -> std::result::Result<usize, InterceptorError> {
        let counter = {
            let mut g = self.counter.lock().await;
            let c = *g;
            *g = g.wrapping_add(1);
            c
        };
        let iv = self.make_iv(counter);

        let wire = match encrypt_frame(&self.key, &iv, self.unencrypted_bytes, 0, &pkt.payload) {
            Ok(w) => w,
            Err(e) => {
                log::error!(
                    "frame cryptor: encrypt failed (ssrc={}, seq={}): {}",
                    self.ssrc,
                    pkt.header.sequence_number,
                    e,
                );
                return Err(InterceptorError::Other(format!("frame cryptor: encrypt: {}", e)));
            }
        };

        let mut out = pkt.clone();
        out.payload = Bytes::from(wire);
        self.next.write(&out, attributes).await
    }
}

struct DecryptingReader {
    key: [u8; AES_KEY_LEN],
    unencrypted_bytes: usize,
    next: Arc<dyn RTPReader + Send + Sync>,
}

#[async_trait]
impl RTPReader for DecryptingReader {
    async fn read(
        &self,
        buf: &mut [u8],
        attributes: &Attributes,
    ) -> std::result::Result<(rtp::packet::Packet, Attributes), InterceptorError> {
        let (mut pkt, attrs) = self.next.read(buf, attributes).await?;

        match decrypt_frame(&self.key, self.unencrypted_bytes, &pkt.payload) {
            Ok(plaintext) => {
                pkt.payload = Bytes::from(plaintext);
            }
            Err(e) => {
                // libwebrtc's FrameCryptor logs + drops the frame here; mirror
                // that. Returning the empty payload upstream is better than
                // returning the ciphertext (which would feed garbage to Opus)
                // or returning Err (which would close the stream over a
                // single bad frame).
                log::warn!(
                    "frame cryptor: decrypt failed (ssrc={}, seq={}): {} — dropping frame",
                    pkt.header.ssrc,
                    pkt.header.sequence_number,
                    e,
                );
                pkt.payload = Bytes::new();
            }
        }
        Ok((pkt, attrs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::frame_cryptor::{decrypt_frame, derive_aes_key};

    /// Mock RTPWriter that captures the last packet it received so the
    /// test can assert on the bytes that would have gone to the wire.
    struct CaptureWriter {
        last: Mutex<Option<rtp::packet::Packet>>,
    }

    #[async_trait]
    impl RTPWriter for CaptureWriter {
        async fn write(
            &self,
            pkt: &rtp::packet::Packet,
            _attributes: &Attributes,
        ) -> std::result::Result<usize, InterceptorError> {
            *self.last.lock().await = Some(pkt.clone());
            Ok(pkt.payload.len())
        }
    }

    fn opus_stream_info(ssrc: u32) -> StreamInfo {
        StreamInfo {
            id: "test".to_string(),
            ssrc,
            mime_type: "audio/opus".to_string(),
            clock_rate: 48_000,
            channels: 1,
            ..Default::default()
        }
    }

    fn opus_packet(payload: &[u8]) -> rtp::packet::Packet {
        let mut header = rtp::header::Header::default();
        header.ssrc = 0xdead_beef;
        header.sequence_number = 1;
        rtp::packet::Packet {
            header,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[tokio::test]
    async fn encrypted_payload_round_trips_through_decrypt() {
        let key = derive_aes_key(&(0u8..32).collect::<Vec<_>>());
        let icpt = FrameCryptorInterceptor { key };

        let capture = Arc::new(CaptureWriter { last: Mutex::new(None) });
        let writer = icpt
            .bind_local_stream(&opus_stream_info(0xdead_beef), capture.clone())
            .await;

        let plaintext = b"\xf8some-opus-payload-bytes";
        let pkt = opus_packet(plaintext);
        writer.write(&pkt, &Attributes::new()).await.unwrap();

        let captured = capture.last.lock().await.clone().unwrap();
        // The TOC byte stays plaintext at the head of the payload.
        assert_eq!(captured.payload[0], 0xf8);
        // The full payload should decrypt back to the original plaintext
        // using the pure decrypt_frame — proves the interceptor produced
        // the wire format the library promises.
        let recovered = decrypt_frame(&key, OPUS_UNENCRYPTED_BYTES, &captured.payload).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn encrypt_increments_counter_per_frame() {
        // Two writes from the same encrypting writer must produce different
        // ciphertexts even for identical plaintexts — confirms the IV
        // counter actually moves between calls (would catch a Mutex
        // double-borrow or a forgotten increment).
        let key = derive_aes_key(&(0u8..32).collect::<Vec<_>>());
        let icpt = FrameCryptorInterceptor { key };

        let capture = Arc::new(CaptureWriter { last: Mutex::new(None) });
        let writer = icpt
            .bind_local_stream(&opus_stream_info(0xdead_beef), capture.clone())
            .await;

        let plaintext = b"\xf8repeated-payload-repeated-payload";
        writer
            .write(&opus_packet(plaintext), &Attributes::new())
            .await
            .unwrap();
        let first = capture.last.lock().await.clone().unwrap().payload;

        writer
            .write(&opus_packet(plaintext), &Attributes::new())
            .await
            .unwrap();
        let second = capture.last.lock().await.clone().unwrap().payload;

        assert_ne!(first, second, "identical plaintexts must encrypt to different bytes");
    }

    #[tokio::test]
    async fn non_opus_streams_pass_through_unchanged() {
        // Video / unknown codecs aren't supported yet — verify they bypass
        // the cryptor instead of producing wrong AAD against an unknown
        // unencrypted-prefix length.
        let key = derive_aes_key(&(0u8..32).collect::<Vec<_>>());
        let icpt = FrameCryptorInterceptor { key };

        let mut info = opus_stream_info(0x1234);
        info.mime_type = "video/vp8".to_string();
        let capture = Arc::new(CaptureWriter { last: Mutex::new(None) });
        let writer = icpt.bind_local_stream(&info, capture.clone()).await;

        let plaintext = b"raw-vp8-frame-bytes";
        writer
            .write(&opus_packet(plaintext), &Attributes::new())
            .await
            .unwrap();

        let captured = capture.last.lock().await.clone().unwrap();
        assert_eq!(captured.payload.as_ref(), plaintext);
    }
}
