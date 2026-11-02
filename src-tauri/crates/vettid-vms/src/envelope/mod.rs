//! The v2 envelope (VAULT-MESSAGING §5): the byte layout of session and
//! sealed modes (§5.2), the inner plaintext (§5.3), padding (§5.4) and the
//! size limit (§5.5), as the vault's `vms/envelope` builds them.
//!
//! Parsing is strict: anything a conforming sender doesn't produce is
//! refused, and the structure and sizes are checked before anything is
//! decrypted. Errors carry no input bytes, plaintext or key material.
//!
//! The claim-check blob (§5.5) is not here yet: nothing in "pairs and
//! collects" uses it.

mod inner;
mod padding;
mod seal;
mod ulid;

pub use inner::{
    format_ts, parse_ts, valid_type, Inner, Response, Status, INNER_VERSION, MAX_CLOCK_SKEW_FUTURE, MAX_DURABLE_AGE,
    MAX_ERROR_CODE_LEN, MAX_ERROR_MESSAGE_LEN, MAX_TYPE_LEN,
};
pub use padding::{pad, pad_fixed, padded_len, unpad, unpad_fixed, valid_padded_len};
pub use seal::{open_sealed, open_session, seal_sealed, seal_session, Sealer};
pub use ulid::{new_ulid, valid_ulid, ULID_LEN};

use crate::suite::kid::Kid;
use crate::suite::{check_suite, SuiteError, ENC_SIZE, KID_SIZE, SUITE_2, TAG_SIZE, XNONCE_SIZE};

/// The envelope mode byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// XChaCha20-Poly1305 under an epoch key.
    Session = 0x01,
    /// HPKE to the recipient's KEM key.
    Sealed = 0x02,
}

/// The version byte.
pub const VERSION: u8 = 0x02;

const OFF_VER: usize = 0;
const OFF_SUITE: usize = 1;
const OFF_MODE: usize = 2;
const OFF_FLAGS: usize = 3;
const OFF_SENDER_KID: usize = 4;
const OFF_RECIPIENT_KID: usize = OFF_SENDER_KID + KID_SIZE;
const OFF_BODY: usize = OFF_RECIPIENT_KID + KID_SIZE;

/// The session-mode header (the AAD): 44 bytes.
pub const HEADER_SESSION: usize = OFF_BODY + XNONCE_SIZE;
/// The sealed-mode header (the AAD): 1,140 bytes.
pub const HEADER_SEALED: usize = OFF_BODY + ENC_SIZE;
/// Session-mode overhead: 60 bytes.
pub const OVERHEAD_SESSION: usize = HEADER_SESSION + TAG_SIZE;
/// Sealed-mode overhead: 1,156 bytes.
pub const OVERHEAD_SEALED: usize = HEADER_SEALED + TAG_SIZE;

/// The smallest padded inner plaintext.
pub const MIN_PADDED: usize = 512;
/// Where 512-byte buckets give way to 16 KiB ones.
pub const SMALL_BUCKET_LIMIT: usize = 16 * 1024;
/// The largest padded inner plaintext a sender may produce (§5.5).
pub const MAX_PADDED: usize = 245_760;
/// The fixed padded size of alternate-channel plaintexts (§5.4).
pub const ALT_CHANNEL_PADDED: usize = 4096;
/// The fixed padded size of `vault.enroll` and `vault.unlock` (§5.4).
pub const ALT_CHANNEL_ENROLL_PADDED: usize = 12_288;
/// The relay's default `max_payload_bytes`.
pub const DEFAULT_MAX_PAYLOAD: usize = 262_144;

// The largest padded plaintext fits the relay's default in either mode (§5.5).
const _: () = assert!(MAX_PADDED + OVERHEAD_SEALED <= DEFAULT_MAX_PAYLOAD);

/// Why an envelope or an inner plaintext was refused. Carries no input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Shorter than its header plus the smallest ciphertext.
    Truncated,
    /// Not version 2.
    Version,
    /// Not suite 2 (suite 1 included), or a suite operation failed.
    Suite(SuiteError),
    /// Neither session nor sealed.
    Mode,
    /// A reserved flag is set.
    Flags,
    /// The ciphertext isn't the tag plus a valid padded size.
    Length,
    /// The padded plaintext would exceed [`MAX_PADDED`].
    TooLarge,
    /// The padding is malformed.
    Padding,
    /// The recipient kid isn't the key's.
    Kid,
    /// The operation is for the other mode.
    WrongMode,
    /// Decryption failed.
    Decrypt,
    /// The inner plaintext is malformed.
    Inner,
    /// `ts` is more than 5 minutes in the future.
    ClockFuture,
    /// `ts` is more than 16 days in the past (durable types).
    ClockPast,
    /// `exp` has passed.
    Expired,
    /// An ephemeral message without `exp` (§5.3 requires it).
    NoExpiry,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("envelope: truncated"),
            Self::Version => f.write_str("envelope: unsupported version"),
            Self::Suite(e) => write!(f, "envelope: {e}"),
            Self::Mode => f.write_str("envelope: invalid mode"),
            Self::Flags => f.write_str("envelope: reserved flags set"),
            Self::Length => f.write_str("envelope: invalid length"),
            Self::TooLarge => f.write_str("envelope: padded plaintext exceeds the size limit"),
            Self::Padding => f.write_str("envelope: malformed padding"),
            Self::Kid => f.write_str("envelope: kid does not match the key"),
            Self::WrongMode => f.write_str("envelope: wrong mode for this operation"),
            Self::Decrypt => f.write_str("envelope: decryption failed"),
            Self::Inner => f.write_str("envelope: malformed inner plaintext"),
            Self::ClockFuture => f.write_str("envelope: timestamp too far in the future"),
            Self::ClockPast => f.write_str("envelope: timestamp too old"),
            Self::Expired => f.write_str("envelope: message expired"),
            Self::NoExpiry => f.write_str("envelope: ephemeral message without exp"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl From<SuiteError> for EnvelopeError {
    fn from(e: SuiteError) -> Self {
        Self::Suite(e)
    }
}

/// A structurally valid, still encrypted envelope. `Debug` shows the mode,
/// the kids and the length only.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    raw: Vec<u8>,
    mode: Mode,
    sender_kid: Kid,
    recipient_kid: Kid,
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("mode", &self.mode)
            .field("sender_kid", &self.sender_kid)
            .field("recipient_kid", &self.recipient_kid)
            .field("len", &self.raw.len())
            .finish()
    }
}

impl Envelope {
    /// Check an envelope's structure without decrypting it: version 2,
    /// suite 2 (suite 1 refused), mode session or sealed, flags zero, and
    /// a ciphertext that is the tag plus a valid padded size (§5.4) no
    /// larger than [`MAX_PADDED`]. The input is copied.
    pub fn parse(b: &[u8]) -> Result<Self, EnvelopeError> {
        if b.len() < OFF_BODY {
            return Err(EnvelopeError::Truncated);
        }
        if b[OFF_VER] != VERSION {
            return Err(EnvelopeError::Version);
        }
        check_suite(b[OFF_SUITE])?;
        if b[OFF_FLAGS] != 0 {
            return Err(EnvelopeError::Flags);
        }
        let (mode, h) = match b[OFF_MODE] {
            0x01 => (Mode::Session, HEADER_SESSION),
            0x02 => (Mode::Sealed, HEADER_SEALED),
            _ => return Err(EnvelopeError::Mode),
        };
        if b.len() < h + TAG_SIZE + MIN_PADDED {
            return Err(EnvelopeError::Truncated);
        }
        if !valid_padded_len(b.len() - h - TAG_SIZE) {
            return Err(EnvelopeError::Length);
        }
        let kid = |at: usize| Kid(b[at..at + KID_SIZE].try_into().expect("size"));
        Ok(Envelope { raw: b.to_vec(), mode, sender_kid: kid(OFF_SENDER_KID), recipient_kid: kid(OFF_RECIPIENT_KID) })
    }

    /// The mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The sender kid.
    pub fn sender_kid(&self) -> Kid {
        self.sender_kid
    }

    /// The recipient kid: with the collect `sender`, the only routing hint
    /// a receiver uses (§13.6).
    pub fn recipient_kid(&self) -> Kid {
        self.recipient_kid
    }

    /// 44 (session) or 1,140 (sealed).
    pub fn header_len(&self) -> usize {
        match self.mode {
            Mode::Session => HEADER_SESSION,
            Mode::Sealed => HEADER_SEALED,
        }
    }

    /// The header, which is also the AAD.
    pub fn header(&self) -> &[u8] {
        &self.raw[..self.header_len()]
    }

    /// The whole envelope.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The length of the padded inner plaintext.
    pub fn padded_len(&self) -> usize {
        self.raw.len() - self.header_len() - TAG_SIZE
    }

    fn body(&self) -> &[u8] {
        &self.raw[OFF_BODY..self.header_len()]
    }

    fn ciphertext(&self) -> &[u8] {
        &self.raw[self.header_len()..]
    }
}

/// The header: ver, suite, mode, flags, the kids, then the nonce or `enc`.
fn header(mode: Mode, sender_kid: Kid, recipient_kid: Kid, body: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(OFF_BODY + body.len());
    h.extend_from_slice(&[VERSION, SUITE_2, mode as u8, 0x00]);
    h.extend_from_slice(&sender_kid.0);
    h.extend_from_slice(&recipient_kid.0);
    h.extend_from_slice(body);
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(len: usize) -> Vec<u8> {
        let mut b = header(Mode::Session, Kid([2; 8]), Kid([1; 8]), &[9; XNONCE_SIZE]);
        b.resize(len, 0);
        b
    }

    #[test]
    fn layout_constants() {
        assert_eq!((HEADER_SESSION, HEADER_SEALED, OVERHEAD_SESSION, OVERHEAD_SEALED), (44, 1140, 60, 1156));
        assert_eq!(MAX_PADDED + OVERHEAD_SEALED, 246_916);
        assert_eq!(ALT_CHANNEL_PADDED + OVERHEAD_SEALED, 5252);
        assert_eq!(ALT_CHANNEL_ENROLL_PADDED + OVERHEAD_SEALED, 13_444);
    }

    #[test]
    fn parse_checks_structure_before_anything_else() {
        let ok = session(OVERHEAD_SESSION + 512);
        let e = Envelope::parse(&ok).unwrap();
        assert_eq!((e.mode(), e.sender_kid(), e.recipient_kid(), e.padded_len()), (Mode::Session, Kid([2; 8]), Kid([1; 8]), 512));
        assert_eq!(e.header(), &ok[..44]);
        assert!(!format!("{e:?}").contains("9, 9"), "Debug shows no nonce or ciphertext");

        let with = |at: usize, v: u8| {
            let mut b = ok.clone();
            b[at] = v;
            Envelope::parse(&b).unwrap_err()
        };
        assert_eq!(with(0, 1), EnvelopeError::Version);
        assert_eq!(with(1, 1), EnvelopeError::Suite(SuiteError::Suite1));
        assert_eq!(with(1, 3), EnvelopeError::Suite(SuiteError::UnsupportedSuite));
        assert_eq!(with(2, 0), EnvelopeError::Mode);
        assert_eq!(with(2, 3), EnvelopeError::Mode);
        assert_eq!(with(3, 1), EnvelopeError::Flags);
        assert_eq!(with(3, 0x80), EnvelopeError::Flags);

        assert_eq!(Envelope::parse(&ok[..19]).unwrap_err(), EnvelopeError::Truncated);
        assert_eq!(Envelope::parse(&ok[..ok.len() - 1]).unwrap_err(), EnvelopeError::Truncated);
        assert_eq!(Envelope::parse(&session(OVERHEAD_SESSION + 513)).unwrap_err(), EnvelopeError::Length);
        assert_eq!(Envelope::parse(&session(OVERHEAD_SESSION + 1000)).unwrap_err(), EnvelopeError::Length);
        assert!(Envelope::parse(&session(OVERHEAD_SESSION + MAX_PADDED)).is_ok());
        assert_eq!(Envelope::parse(&session(OVERHEAD_SESSION + MAX_PADDED + 16384)).unwrap_err(), EnvelopeError::Length);
        // A session-length body read as sealed is too short.
        let mut sealed = ok.clone();
        sealed[2] = 0x02;
        assert_eq!(Envelope::parse(&sealed).unwrap_err(), EnvelopeError::Truncated);
    }

    #[test]
    fn errors_say_nothing_of_the_input() {
        assert_eq!(EnvelopeError::Decrypt.to_string(), "envelope: decryption failed");
    }
}
