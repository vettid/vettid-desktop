//! Suite 2 primitives (VAULT-MESSAGING §4.1–4.4).
//!
//! | | |
//! |---|---|
//! | KEM | MLKEM768X25519 (`0x647a`), the X-Wing combiner ([`kem`]) |
//! | KDF | HKDF-SHA256 (`0x0001`) |
//! | Sealed mode | HPKE base mode, RFC 9180, one message per context ([`hpke`]) |
//! | Session mode | XChaCha20-Poly1305, fresh random 24-byte nonce ([`aead`]) |
//! | Kid | `SHA-256("vettid/vms/2/kid" ‖ ek)[0:8]` ([`kid`]) |
//! | Signatures | Ed25519 over `label ‖ msg` ([`sign`]) |
//!
//! Suite 1 is never sent or accepted (§4.1, §13.4).

pub mod aead;
pub mod hpke;
pub mod kem;
pub mod kid;
pub mod sign;

use sha2::{Digest, Sha256};

/// Suite ids (§4.1).
pub const SUITE_1: u8 = 1;
pub const SUITE_2: u8 = 2;

/// HPKE algorithm ids for suite 2 (§4.3).
pub const KEM_ID: u16 = 0x647a;
pub const KDF_ID: u16 = 0x0001;
pub const AEAD_ID: u16 = 0x0003;

/// Sizes (§3.2, §4).
pub const EK_SIZE: usize = 1216;
pub const ENC_SIZE: usize = 1120;
pub const SEED_SIZE: usize = 32;
pub const KID_SIZE: usize = 8;
pub const KEY_SIZE: usize = 32;
pub const XNONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const HASH_SIZE: usize = 32;

/// Labels (§4.2–§6.3), as in the vault's `vms/suite`.
pub const LABEL_KID: &str = "vettid/vms/2/kid";
pub const INFO_SEALED: &str = "vettid/vms/2/sealed";
pub const LABEL_HS_KS: &str = "vettid/vms/2/hs-ks";
pub const LABEL_HS_KE: &str = "vettid/vms/2/hs-ke";
pub const LABEL_TH1: &str = "vettid/vms/2/th1";
pub const LABEL_TH: &str = "vettid/vms/2/th";
pub const LABEL_SESSION: &str = "vettid/vms/2/session";
pub const LABEL_I2R: &str = "vettid/vms/2/i2r";
pub const LABEL_R2I: &str = "vettid/vms/2/r2i";
pub const LABEL_KID_I2R: &str = "vettid/vms/2/kid-i2r";
pub const LABEL_KID_R2I: &str = "vettid/vms/2/kid-r2i";
pub const LABEL_RK: &str = "vettid/vms/2/rk";
pub const LABEL_EPOCH: &str = "vettid/vms/2/epoch";
pub const LABEL_SIG_RESP: &str = "vettid/vms/2/sig-resp";
pub const LABEL_SIG_FIN: &str = "vettid/vms/2/sig-fin";
pub const LABEL_SAS: &str = "vettid/vms/2/sas";
pub const LABEL_SAS_COMMIT: &str = "vettid/vms/2/sas-commit";
pub const LABEL_BUNDLE: &str = "vettid/vms/2/bundle";

/// Why a primitive refused. No variant carries key or message material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteError {
    /// Suite 1 is never accepted (§4.1).
    Suite1,
    /// A suite this build doesn't support.
    UnsupportedSuite,
    /// A key or encapsulation of the wrong size.
    KeySize,
    /// A key that isn't a valid, canonically encoded key.
    BadKey,
    /// Authentication failed.
    Decrypt,
    /// An HPKE context already sealed or opened its one message (§4.3).
    ContextUsed,
    /// A signature that doesn't verify.
    Signature,
    /// Sealing failed (the AEAD refused, e.g. a message past its limit).
    Encrypt,
    /// An HPKE export of a length the KDF can't produce.
    ExportLength,
    /// The system's random source failed.
    Random,
}

impl std::fmt::Display for SuiteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Suite1 => "suite 1 is never accepted",
            Self::UnsupportedSuite => "unsupported suite",
            Self::KeySize => "wrong key size",
            Self::BadKey => "invalid key",
            Self::Decrypt => "decryption failed",
            Self::ContextUsed => "HPKE context already used for a message",
            Self::Signature => "signature verification failed",
            Self::Encrypt => "encryption failed",
            Self::ExportLength => "export length not supported",
            Self::Random => "randomness unavailable",
        })
    }
}

impl std::error::Error for SuiteError {}

/// Accept a suite id: only suite 2 (§4.1). Suite 1 is refused explicitly.
pub fn check_suite(id: u8) -> Result<(), SuiteError> {
    match id {
        SUITE_2 => Ok(()),
        SUITE_1 => Err(SuiteError::Suite1),
        _ => Err(SuiteError::UnsupportedSuite),
    }
}

/// `SHA-256(label ‖ parts…)`.
pub fn labeled_hash(label: &str, parts: &[&[u8]]) -> [u8; HASH_SIZE] {
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Constant-time equality of two byte strings (§13.6).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Fill `buf` from the operating system's random source.
pub(crate) fn random(buf: &mut [u8]) -> Result<(), SuiteError> {
    use rand::RngCore;
    rand::rngs::OsRng.try_fill_bytes(buf).map_err(|_| SuiteError::Random)
}

#[cfg(test)]
pub(crate) mod vectors {
    //! The vault's known-answer vectors (vettid-vault `testdata/vectors`),
    //! vendored under `tests/vectors` with their source in `SOURCE.md`.

    pub(crate) fn load(name: &str) -> serde_json::Value {
        let text = match name {
            "keys" => include_str!("../../tests/vectors/keys.json"),
            "hpke" => include_str!("../../tests/vectors/hpke.json"),
            _ => panic!("no vector file {name}"),
        };
        serde_json::from_str(text).expect("vector JSON")
    }

    pub(crate) fn hex(v: &serde_json::Value) -> Vec<u8> {
        ::hex::decode(v.as_str().expect("hex string")).expect("hex")
    }

    pub(crate) fn b64(v: &serde_json::Value) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(v.as_str().expect("base64 string")).expect("base64")
    }

    pub(crate) fn seed(v: &serde_json::Value) -> [u8; 32] {
        hex(v).try_into().expect("32-byte seed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_suite_2_is_accepted() {
        assert_eq!(check_suite(2), Ok(()));
        assert_eq!(check_suite(1), Err(SuiteError::Suite1));
        assert_eq!(check_suite(3), Err(SuiteError::UnsupportedSuite));
        assert_eq!(check_suite(0), Err(SuiteError::UnsupportedSuite));
    }

    #[test]
    fn ct_eq_compares_length_and_bytes() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}

#[cfg(test)]
mod vendored {
    /// The vendored vector files are byte-identical to the ones SOURCE.md
    /// records.
    #[test]
    fn vendored_vectors_match_source_md() {
        use sha2::{Digest, Sha256};
        let source = include_str!("../../tests/vectors/SOURCE.md");
        for (name, text) in [
            ("keys.json", include_bytes!("../../tests/vectors/keys.json").as_slice()),
            ("hpke.json", include_bytes!("../../tests/vectors/hpke.json").as_slice()),
        ] {
            assert!(!text.contains(&b'\r'), "{name}: LF line endings, as in the vault");
            let hash = hex::encode(Sha256::digest(text));
            let row = source.lines().find(|l| l.contains(&format!("`{name}`"))).expect("a row in SOURCE.md");
            assert!(row.contains(&hash), "{name}: {hash} not in SOURCE.md");
        }
    }
}
