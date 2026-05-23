//! E2EE frame cryptor — interop with Android's `FrameCryptor`.
//!
//! ## Status
//!
//! Pure encrypt/decrypt functions + PBKDF2 key derivation are implemented
//! and pinned to a libwebrtc-compatible test vector. The webrtc-rs
//! interceptor wiring (which will sit in `crate::webrtc::` once that module
//! is feature-enabled) and the vault signaling path that delivers the
//! 32-byte shared secret to the desktop both still need to land. Until
//! they do, calls between desktop and Android still establish and exchange
//! media but the desktop side has no key to decrypt Android frames
//! (libwebrtc reports `kMissingKey` on the Android side).
//!
//! ## Wire format — NOT RFC 9605 SFrame
//!
//! Android binds the LiveKit fork's `FrameCryptorTransformer`
//! (`webrtc-sdk/webrtc` @ `api/crypto/frame_crypto_transformer.{h,cc}`, m125
//! release). That class predates RFC 9605 and uses a different layout:
//!
//! ```text
//!   +---------------- header (U bytes, plaintext) -----------------+
//!   |       codec-specific prefix kept readable by the SFU         |
//!   +-------------- ciphertext (P bytes, AES-128-GCM) -------------+
//!   |        encrypted payload || 16-byte GCM authentication tag   |
//!   +------------------- iv (12 bytes, plaintext) -----------------+
//!   |        the AES-GCM nonce, emitted on the wire by the         |
//!   |        encryptor so the decryptor can read it directly       |
//!   +------------------ trailer (2 bytes, plaintext) --------------+
//!   |  [0] iv_size = 12 (AES-GCM), [1] key_index (0 for VettID)    |
//!   +--------------------------------------------------------------+
//! ```
//!
//! - `U` = `unencrypted_bytes`, codec-dependent
//!   (`get_unencrypted_bytes` in the C++):
//!   - **Opus (audio): 1** — the TOC byte stays readable
//!   - AV1: 0
//!   - VP8: 10 if keyframe, 3 otherwise
//!   - H.264: NALu-aware (`payload_start_offset + 2` for slice/IDR NALus,
//!     plus an RBSP escape/unescape pass over the ciphertext). Out of
//!     scope for the first cut; audio-only is enough to ship desktop↔Android
//!     audio calls.
//! - `P` = `data_in.size() - U`. The 16-byte GCM tag is *appended* to the
//!   ciphertext by `EVP_AEAD_CTX_seal`, so the ciphertext segment is
//!   `P_plain + 16` bytes long.
//! - The IV and trailer go AT THE END of the frame, *not* at the front
//!   like RFC 9605 SFrame.
//!
//! ### AAD (additional authenticated data)
//!
//! AAD = the unencrypted header bytes (the codec prefix). For Opus that
//! is the single TOC byte at offset 0. The IV and trailer are NOT in the
//! AAD — they ride in cleartext outside the AEAD envelope.
//!
//! ### IV derivation
//!
//! The C++ encryptor builds the 12-byte IV as
//! `BE32(ssrc) || BE32(timestamp) || BE32(timestamp - send_count)`, where
//! `send_count` is a per-SSRC counter that starts at a `rand() & 0xFFFF`
//! seed. The decryptor doesn't *re-derive* the IV — it reads the 12 bytes
//! straight from the trailer position. So this side can pick any IV
//! scheme that guarantees uniqueness per (key, frame); reproducing the
//! Android counter behavior exactly is not required for interop.
//!
//! ## Key derivation
//!
//! `CallFrameCryptor.kt` passes a **32-byte** `sharedSecret` straight into
//! `FrameCryptorFactory.createFrameCryptorKeyProvider(...)`. The C++
//! `DefaultKeyProviderImpl::SetSharedKey` then runs `PKCS5_PBKDF2_HMAC`
//! over it to derive the actual AES-128-GCM key:
//!
//! ```text
//!   aes_key = PBKDF2-HMAC-SHA256(
//!       password = shared_secret,             // raw 32 bytes
//!       salt     = "vettid-e2ee-ratchet-v1",  // KeyProviderOptions.ratchet_salt
//!       iters    = 100_000,
//!       dk_len   = 16,                        // 128 bits — AES-128-GCM
//!   )
//! ```
//!
//! [`derive_aes_key`] reproduces this on the desktop side. The 32-byte
//! shared secret itself comes from the vault on call setup — see
//! `enableFrameEncryption(event.sharedSecret)` in Android `CallManager.kt`.
//! The matching desktop receive path is still TODO.
//!
//! ## Reference material
//!
//! - Android wrapper: `vettid-android/.../features/calling/CallFrameCryptor.kt`
//! - Android setup:   `vettid-android/.../features/calling/CallManager.kt`
//!                    (`enableFrameEncryption`)
//! - C++ ground truth: webrtc-sdk/webrtc @ `api/crypto/frame_crypto_transformer.{h,cc}`,
//!   m125_release. The `encryptFrame()` and `decryptFrame()` functions are
//!   ~50 lines each — read them, don't paraphrase.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};

/// AES-128-GCM key length in bytes — the LiveKit cryptor always uses 128-bit
/// keys for `Algorithm::kAesGcm` (see `GetAesGcmAlgorithmFromKeySize` /
/// `tag_length_bits = 128` in the C++ reference).
pub const AES_KEY_LEN: usize = 16;
/// AES-GCM nonce length in bytes. Hard-coded in the C++ `getIvSize()`.
pub const IV_LEN: usize = 12;
/// AES-GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// LiveKit trailer length: `[iv_size, key_index]`.
pub const TRAILER_LEN: usize = 2;
/// Bytes of an Opus frame left in plaintext — the TOC byte. Matches
/// `get_unencrypted_bytes(MediaType::kAudioFrame)` in the C++ reference,
/// which returns 1 for audio.
pub const OPUS_UNENCRYPTED_BYTES: usize = 1;

/// Salt for the PBKDF2 derivation that turns the per-call shared secret into
/// the actual AES-128-GCM key. Must match Android's
/// `RATCHET_SALT = "vettid-e2ee-ratchet-v1"` in `CallFrameCryptor.kt`, which
/// is passed in as `KeyProviderOptions.ratchet_salt` and consumed by
/// `DerivePBKDF2KeyFromRawKey` in the C++ side.
pub const RATCHET_SALT: &[u8] = b"vettid-e2ee-ratchet-v1";
/// PBKDF2 iteration count, hard-coded to 100k in the C++ reference
/// (`DerivePBKDF2KeyFromRawKey` → `PKCS5_PBKDF2_HMAC(... 100000 ...)`).
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// Derive the AES-128-GCM key from the per-call shared secret.
///
/// Mirrors `DerivePBKDF2KeyFromRawKey(secret, ratchet_salt, 128, ...)` in
/// the C++ FrameCryptorTransformer — that's the function libwebrtc runs
/// inside `SetSharedKey` when Android calls
/// `keyProvider.setSharedKey(0, sharedSecret)`. Both peers MUST do the
/// same derivation; any drift here ends in `kMissingKey`.
pub fn derive_aes_key(secret: &[u8]) -> [u8; AES_KEY_LEN] {
    let mut out = [0u8; AES_KEY_LEN];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(secret, RATCHET_SALT, PBKDF2_ITERATIONS, &mut out);
    out
}

#[derive(Debug)]
pub enum CryptorError {
    /// Plaintext frame was shorter than the codec's unencrypted prefix.
    FrameTooShortForHeader,
    /// On-wire frame was shorter than `header + tag + iv + trailer`.
    FrameTooShortForEnvelope,
    /// AES-GCM tag failed to verify — wrong key, IV, AAD, or ciphertext tampered.
    DecryptionFailed,
    /// Trailer's `iv_size` byte didn't match the expected IV length for AES-GCM.
    UnexpectedIvSize(u8),
    /// AES-GCM encrypt step returned an error (out-of-memory or similar).
    EncryptionFailed,
}

impl std::fmt::Display for CryptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptorError::FrameTooShortForHeader => {
                write!(f, "plaintext shorter than codec unencrypted prefix")
            }
            CryptorError::FrameTooShortForEnvelope => {
                write!(f, "ciphertext shorter than header+tag+iv+trailer")
            }
            CryptorError::DecryptionFailed => write!(f, "AES-GCM tag verification failed"),
            CryptorError::UnexpectedIvSize(n) => {
                write!(f, "trailer claims iv_size={} (expected {})", n, IV_LEN)
            }
            CryptorError::EncryptionFailed => write!(f, "AES-GCM seal failed"),
        }
    }
}

impl std::error::Error for CryptorError {}

/// Encrypt one frame in the LiveKit `FrameCryptor` wire format.
///
/// On-wire layout (see module doc-comment):
/// ```text
///   header(U) || ciphertext(P + 16-byte tag) || iv(12) || trailer(2)
/// ```
/// - `key` — the AES-128-GCM key produced by [`derive_aes_key`].
/// - `iv` — the 12-byte nonce the receiver will read from the trailer.
///   Caller must guarantee uniqueness per `(key, iv)`. Any IV works for
///   interop because the decryptor reads it straight off the wire; we
///   don't need to reproduce libwebrtc's `(ssrc, ts, ts-count)` shape.
/// - `unencrypted_bytes` — `U` bytes of `frame` at offset 0 stay plaintext
///   and form the AAD. For Opus use [`OPUS_UNENCRYPTED_BYTES`].
/// - `key_index` — emitted in the trailer. VettID uses 0.
/// - `frame` — the full plaintext frame (header + payload). The function
///   slices the AAD off the front and encrypts the rest.
pub fn encrypt_frame(
    key: &[u8; AES_KEY_LEN],
    iv: &[u8; IV_LEN],
    unencrypted_bytes: usize,
    key_index: u8,
    frame: &[u8],
) -> Result<Vec<u8>, CryptorError> {
    if frame.len() < unencrypted_bytes {
        return Err(CryptorError::FrameTooShortForHeader);
    }
    let (header, payload) = frame.split_at(unencrypted_bytes);
    let cipher = Aes128Gcm::new(key.into());

    // `encrypt` returns ciphertext || tag, which is exactly the layout the
    // C++ side writes (BoringSSL's `EVP_AEAD_CTX_seal` appends the tag).
    let ciphertext_with_tag = cipher
        .encrypt(
            Nonce::from_slice(iv),
            Payload { msg: payload, aad: header },
        )
        .map_err(|_| CryptorError::EncryptionFailed)?;

    let mut out = Vec::with_capacity(
        header.len() + ciphertext_with_tag.len() + IV_LEN + TRAILER_LEN,
    );
    out.extend_from_slice(header);
    out.extend_from_slice(&ciphertext_with_tag);
    out.extend_from_slice(iv);
    out.push(IV_LEN as u8);
    out.push(key_index);
    Ok(out)
}

/// Decrypt one frame in the LiveKit `FrameCryptor` wire format.
///
/// Reads the trailer to recover `iv_size`/`key_index`, lifts the IV off the
/// wire, and runs AES-128-GCM over the ciphertext with the unencrypted
/// header as AAD. Returns the recovered plaintext frame
/// (header(U) || payload).
///
/// `unencrypted_bytes` MUST be derived from the codec the same way the
/// sender did (1 for Opus). If the sender and receiver disagree the AAD
/// won't match and the tag will reject.
pub fn decrypt_frame(
    key: &[u8; AES_KEY_LEN],
    unencrypted_bytes: usize,
    frame: &[u8],
) -> Result<Vec<u8>, CryptorError> {
    // Minimum envelope: header(U) + tag(16) + iv(12) + trailer(2).
    if frame.len() < unencrypted_bytes + TAG_LEN + IV_LEN + TRAILER_LEN {
        return Err(CryptorError::FrameTooShortForEnvelope);
    }

    let trailer_start = frame.len() - TRAILER_LEN;
    let iv_size = frame[trailer_start];
    let _key_index = frame[trailer_start + 1];
    if iv_size as usize != IV_LEN {
        return Err(CryptorError::UnexpectedIvSize(iv_size));
    }

    let iv_start = trailer_start - IV_LEN;
    let iv: [u8; IV_LEN] = frame[iv_start..trailer_start].try_into().unwrap();

    let header = &frame[..unencrypted_bytes];
    let ciphertext_with_tag = &frame[unencrypted_bytes..iv_start];

    let cipher = Aes128Gcm::new(key.into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&iv),
            Payload { msg: ciphertext_with_tag, aad: header },
        )
        .map_err(|_| CryptorError::DecryptionFailed)?;

    let mut out = Vec::with_capacity(header.len() + plaintext.len());
    out.extend_from_slice(header);
    out.extend_from_slice(&plaintext);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PBKDF2 interop oracle. Computed by an independent OpenSSL-backed
    /// implementation (Python `hashlib.pbkdf2_hmac`) over the same inputs.
    /// If this test breaks, every Android call will land in MISSINGKEY.
    #[test]
    fn derive_aes_key_matches_openssl_reference() {
        let secret: Vec<u8> = (0u8..32).collect();
        let key = derive_aes_key(&secret);
        assert_eq!(
            hex::encode(key),
            "d8ddaa6d6ca09d198c9f1f0fc23efa8e",
            "PBKDF2-HMAC-SHA256(secret=0..31, salt=ratchet_salt, iters=100k, len=16)",
        );
    }

    /// libwebrtc-FrameCryptor interop oracle. Same inputs as the OpenSSL
    /// vector hand-computed against the C++ reference: Opus frame with TOC
    /// byte as AAD, fixed IV in Android's `(ssrc, ts, ts-count)` shape,
    /// `key_index = 0`. If this output drifts, frames the desktop emits
    /// will not decrypt on Android.
    #[test]
    fn encrypt_opus_frame_matches_reference_vector() {
        let secret: Vec<u8> = (0u8..32).collect();
        let key = derive_aes_key(&secret);

        let opus_frame: [u8; 16] = [
            0xf8, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
            0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
        ];
        let iv: [u8; 12] = hex::decode("123456780000100000001000")
            .unwrap()
            .try_into()
            .unwrap();

        let wire = encrypt_frame(&key, &iv, OPUS_UNENCRYPTED_BYTES, 0, &opus_frame).unwrap();

        // Layout: header(1) || ct+tag(31) || iv(12) || trailer(2) = 46
        assert_eq!(wire.len(), 1 + 15 + 16 + 12 + 2);
        assert_eq!(
            hex::encode(&wire),
            "f840bc1d5c97e0d4a30b24cdfeec0b6314e06c4c1b1e9a9bba7338b39051eb9f1234567800001000000010000c00",
        );
    }

    #[test]
    fn decrypt_inverse_of_encrypt_for_opus() {
        let key = derive_aes_key(&(0u8..32).collect::<Vec<_>>());
        let frame = b"\xf8some-arbitrary-opus-payload-bytes-here";
        let iv = [0u8; IV_LEN];
        let wire = encrypt_frame(&key, &iv, OPUS_UNENCRYPTED_BYTES, 0, frame).unwrap();
        let recovered = decrypt_frame(&key, OPUS_UNENCRYPTED_BYTES, &wire).unwrap();
        assert_eq!(recovered, frame);
    }

    #[test]
    fn decrypt_reference_vector_recovers_plaintext() {
        let key = derive_aes_key(&(0u8..32).collect::<Vec<_>>());
        let wire = hex::decode(
            "f840bc1d5c97e0d4a30b24cdfeec0b6314e06c4c1b1e9a9bba7338b39051eb9f1234567800001000000010000c00",
        ).unwrap();
        let recovered = decrypt_frame(&key, OPUS_UNENCRYPTED_BYTES, &wire).unwrap();
        assert_eq!(
            recovered,
            vec![
                0xf8, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
            ],
        );
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = derive_aes_key(&(0u8..32).collect::<Vec<_>>());
        let iv = [0u8; IV_LEN];
        let frame = b"\xf8payload-payload-payload";
        let mut wire = encrypt_frame(&key, &iv, OPUS_UNENCRYPTED_BYTES, 0, frame).unwrap();
        // Flip one bit in the encrypted payload region.
        wire[5] ^= 0x01;
        assert!(matches!(
            decrypt_frame(&key, OPUS_UNENCRYPTED_BYTES, &wire),
            Err(CryptorError::DecryptionFailed),
        ));
    }

    #[test]
    fn decrypt_rejects_tampered_aad() {
        let key = derive_aes_key(&(0u8..32).collect::<Vec<_>>());
        let iv = [0u8; IV_LEN];
        let frame = b"\xf8payload-payload-payload";
        let mut wire = encrypt_frame(&key, &iv, OPUS_UNENCRYPTED_BYTES, 0, frame).unwrap();
        wire[0] ^= 0x01; // flip the TOC byte (AAD)
        assert!(matches!(
            decrypt_frame(&key, OPUS_UNENCRYPTED_BYTES, &wire),
            Err(CryptorError::DecryptionFailed),
        ));
    }

    #[test]
    fn decrypt_rejects_truncated_frame() {
        let key = [0u8; AES_KEY_LEN];
        let too_short = [0u8; OPUS_UNENCRYPTED_BYTES + TAG_LEN + IV_LEN + TRAILER_LEN - 1];
        assert!(matches!(
            decrypt_frame(&key, OPUS_UNENCRYPTED_BYTES, &too_short),
            Err(CryptorError::FrameTooShortForEnvelope),
        ));
    }

    #[test]
    fn decrypt_rejects_unexpected_iv_size() {
        let key = [0u8; AES_KEY_LEN];
        // Build a minimum-length frame but with iv_size byte set to 13.
        let mut buf = vec![0u8; OPUS_UNENCRYPTED_BYTES + TAG_LEN + IV_LEN + TRAILER_LEN];
        let trailer_start = buf.len() - TRAILER_LEN;
        buf[trailer_start] = 13;
        assert!(matches!(
            decrypt_frame(&key, OPUS_UNENCRYPTED_BYTES, &buf),
            Err(CryptorError::UnexpectedIvSize(13)),
        ));
    }
}
