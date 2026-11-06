//! The passphrase protector (#13 item 3; DESKTOP-REWORK-PLAN §4 "At-rest
//! protectors", the owner's choice (c)): used only when no protector that
//! binds the pairing to this computer is present. Engine only: the app
//! wires it in with the passphrase UI (#13 item 4), so nothing chooses it
//! yet.
//!
//! **The wrap.** Argon2id (RustCrypto `argon2`) turns the passphrase and a
//! random 16-byte salt into 32 bytes; HKDF-SHA-256 with a label turns those
//! into the wrap key; XChaCha20-Poly1305 seals the data key with a random
//! nonce. The parameters (t, m, p), the salt and the format version are the
//! seal's associated data, so changing any of them makes it fail to open.
//! What goes in the header's `wrapped_key` (all big-endian):
//!
//! `version (1) | t (4) | m KiB (4) | p (4) | salt (16) | nonce (24) | sealed key (48)`
//!
//! **Parameters.** Written: t=3, m=64 MiB, p=1 (VAULT-MESSAGING §3.5.1's
//! password values). Read: t and m at least t=1, m=8 MiB, so a rewritten
//! header can't make the passphrase cheap to guess; and at most t=10,
//! m=1 GiB, p=4, so a rewritten header can't make opening it run out of
//! memory or time (lead review). Anything outside is "won't open".
//!
//! **What it protects against.** A copy of the file opens anywhere with
//! the passphrase: only Argon2id slows guessing it. It doesn't meet LEASH
//! §3.4, and Settings says "not bound to this computer" (item 4).
//!
//! SECURITY: the passphrase, the Argon2id output and the wrap key are
//! zeroized; nothing here logs them. The passphrase reaches Rust as a
//! webview string, which can't be zeroized there (§4 accepts that).

// Wired into `Protectors` by the passphrase UI (#13 item 4).
#![allow(dead_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::protector::{Availability, DataKey, Protector, ProtectorError};

/// The header's `protector` value.
pub(crate) const ID: &str = "passphrase";
/// Its plain name, for the person.
pub(crate) const NAME: &str = "your passphrase";

const FORMAT: u8 = 1;
/// The values written (VAULT-MESSAGING §3.5.1).
pub(crate) const T_COST: u32 = 3;
pub(crate) const M_COST_KIB: u32 = 64 * 1024;
pub(crate) const P_COST: u32 = 1;
/// The floor a read accepts (the vault's own floor): below it, a rewritten
/// header would make the passphrase cheap to guess.
const MIN_T: u32 = 1;
const MIN_M_KIB: u32 = 8 * 1024;
/// The ceiling a read accepts: above it, a rewritten header would make
/// opening the file exhaust memory or time.
const MAX_T: u32 = 10;
const MAX_M_KIB: u32 = 1024 * 1024;
const MAX_P: u32 = 4;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEAD_LEN: usize = 1 + 4 + 4 + 4 + SALT_LEN;
const WRAPPED_LEN: usize = HEAD_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;
/// HKDF's label: this key wraps a device data key, nothing else.
const HKDF_INFO: &[u8] = b"vettid-desktop passphrase wrap v1";

/// The protector, holding the passphrase the person entered.
pub(crate) struct Passphrase {
    secret: Zeroizing<String>,
}

impl Passphrase {
    pub(crate) fn new(secret: Zeroizing<String>) -> Self {
        Passphrase { secret }
    }
}

fn failing(what: &str, e: impl std::fmt::Display) -> ProtectorError {
    ProtectorError::Failing { by: NAME, detail: format!("{what}: {e}") }
}

/// The wrap key from the passphrase, the parameters and the salt.
fn wrap_key(secret: &str, t: u32, m_kib: u32, p: u32, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, ProtectorError> {
    let params = Params::new(m_kib, t, p, Some(KEY_LEN)).map_err(|e| failing("argon2 parameters", e))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut stretched = Zeroizing::new([0u8; KEY_LEN]);
    argon.hash_password_into(secret.as_bytes(), salt, &mut *stretched).map_err(|e| failing("argon2", e))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, &*stretched).expand(HKDF_INFO, &mut *key).map_err(|e| failing("hkdf", e))?;
    Ok(key)
}

fn head(t: u32, m_kib: u32, p: u32, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEAD_LEN);
    h.push(FORMAT);
    h.extend_from_slice(&t.to_be_bytes());
    h.extend_from_slice(&m_kib.to_be_bytes());
    h.extend_from_slice(&p.to_be_bytes());
    h.extend_from_slice(salt);
    h
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

impl Protector for Passphrase {
    fn id(&self) -> &'static str {
        ID
    }

    /// Always there: it needs nothing of this computer.
    fn availability(&self) -> Availability {
        Availability::Present
    }

    fn probe(&self) -> Result<(), ProtectorError> {
        Params::new(M_COST_KIB, T_COST, P_COST, Some(KEY_LEN)).map(drop).map_err(|e| failing("argon2 parameters", e))
    }

    fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>, ProtectorError> {
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let head = head(T_COST, M_COST_KIB, P_COST, &salt);
        let wk = wrap_key(&self.secret, T_COST, M_COST_KIB, P_COST, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*wk).map_err(|e| failing("cipher", e))?;
        let sealed = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: key, aad: &head })
            .map_err(|_| failing("seal", "the data key couldn't be sealed"))?;
        let mut out = head;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        debug_assert_eq!(out.len(), WRAPPED_LEN);
        Ok(out)
    }

    /// A wrong passphrase and a changed header look the same (the seal
    /// doesn't open): "won't open". The parameters are checked against the
    /// floor and the ceiling before Argon2id runs.
    fn unwrap(&self, wrapped: &[u8]) -> Result<DataKey, ProtectorError> {
        if wrapped.len() != WRAPPED_LEN {
            return Err(ProtectorError::WontOpen(format!("a passphrase-wrapped key of {} bytes", wrapped.len())));
        }
        if wrapped[0] != FORMAT {
            return Err(ProtectorError::WontOpen(format!("passphrase format {}", wrapped[0])));
        }
        let (t, m_kib, p) = (be32(&wrapped[1..5]), be32(&wrapped[5..9]), be32(&wrapped[9..13]));
        if !(MIN_T..=MAX_T).contains(&t) || !(MIN_M_KIB..=MAX_M_KIB).contains(&m_kib) || !(1..=MAX_P).contains(&p) {
            return Err(ProtectorError::WontOpen(format!("passphrase parameters out of bounds (t={t}, m={m_kib} KiB, p={p})")));
        }
        let (head, rest) = wrapped.split_at(HEAD_LEN);
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let wk = wrap_key(&self.secret, t, m_kib, p, &head[13..])?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*wk).map_err(|e| failing("cipher", e))?;
        let mut plain = cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: sealed, aad: head })
            .map_err(|_| ProtectorError::WontOpen("the passphrase doesn't open it (a wrong passphrase, or the file was changed)".into()))?;
        if plain.len() != KEY_LEN {
            plain.zeroize();
            return Err(ProtectorError::WontOpen("a data key of the wrong length".into()));
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&plain);
        plain.zeroize();
        Ok(key)
    }

    /// Nothing is kept outside the file.
    fn remove_external(&self) -> Result<(), ProtectorError> {
        Ok(())
    }
}

/// Why a passphrase is refused at pairing (AGENT-PLAN §1, "Passphrase
/// strength rules"; the texts for these come with the UI, item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Weakness {
    /// Fewer than 12 characters.
    TooShort,
    /// Fewer than 3 of: lower case, upper case, digits, other characters.
    TooFewKinds,
}

/// At least 12 characters (Unicode scalar values), and 3 of the 4 kinds:
/// lower case, upper case, digits, anything else.
pub(crate) fn strong_enough(passphrase: &str) -> Result<(), Weakness> {
    if passphrase.chars().count() < 12 {
        return Err(Weakness::TooShort);
    }
    let (mut lower, mut upper, mut digit, mut other) = (false, false, false, false);
    for c in passphrase.chars() {
        if c.is_lowercase() {
            lower = true;
        } else if c.is_uppercase() {
            upper = true;
        } else if c.is_numeric() {
            digit = true;
        } else {
            other = true;
        }
    }
    if [lower, upper, digit, other].iter().filter(|k| **k).count() < 3 {
        return Err(Weakness::TooFewKinds);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Passphrase {
        Passphrase::new(Zeroizing::new(s.to_string()))
    }

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = n.wrapping_add(i as u8);
        }
        k
    }

    fn wont_open(r: Result<DataKey, ProtectorError>, what: &str) {
        match r {
            Err(ProtectorError::WontOpen(_)) => {}
            other => panic!("{what}: expected won't open, got {:?}", other.map(|_| "a key")),
        }
    }

    #[test]
    fn a_passphrase_round_trips_and_a_wrong_one_wont_open() {
        let right = p("Correct horse 9 battery");
        assert_eq!(right.id(), ID);
        assert_eq!(right.availability(), Availability::Present);
        right.probe().unwrap();
        let wrapped = right.wrap(&key(1)).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_LEN);
        assert_eq!(wrapped[0], FORMAT);
        assert_eq!((be32(&wrapped[1..5]), be32(&wrapped[5..9]), be32(&wrapped[9..13])), (T_COST, M_COST_KIB, P_COST));
        assert_eq!(*right.unwrap(&wrapped).unwrap(), key(1));
        wont_open(p("Correct horse 9 batterY").unwrap(&wrapped), "wrong passphrase");
        // A fresh salt and nonce each time.
        let again = right.wrap(&key(1)).unwrap();
        assert_ne!(again, wrapped);
        assert_eq!(*right.unwrap(&again).unwrap(), key(1));
        right.remove_external().unwrap();
    }

    /// Changing any byte (version, parameters, salt, nonce, sealed key) makes
    /// it fail to open: the head is associated data, and the parameters and
    /// salt also change the key.
    #[test]
    fn a_changed_wrapped_key_wont_open() {
        let right = p("Correct horse 9 battery");
        let wrapped = right.wrap(&key(2)).unwrap();
        // One position in each part; the parameters stay within bounds
        // (t 3 -> 2), so Argon2id runs and the seal itself refuses.
        for (at, flip) in [(4usize, 1u8), (13, 1), (HEAD_LEN, 1), (HEAD_LEN + NONCE_LEN, 1), (WRAPPED_LEN - 1, 1)] {
            let mut changed = wrapped.clone();
            changed[at] ^= flip;
            wont_open(right.unwrap(&changed), &format!("byte {at}"));
        }
        let mut v2 = wrapped.clone();
        v2[0] = 2;
        wont_open(right.unwrap(&v2), "another format");
        wont_open(right.unwrap(&wrapped[..WRAPPED_LEN - 1]), "truncated");
        wont_open(right.unwrap(&[]), "empty");
    }

    /// The floor and the ceiling are checked before Argon2id runs: a
    /// rewritten header can neither make the passphrase cheap to guess nor
    /// make opening it exhaust memory.
    #[test]
    fn parameters_outside_the_bounds_wont_open() {
        let right = p("Correct horse 9 battery");
        let wrapped = right.wrap(&key(3)).unwrap();
        let with = |t: u32, m: u32, pp: u32| {
            let mut w = wrapped.clone();
            w[1..5].copy_from_slice(&t.to_be_bytes());
            w[5..9].copy_from_slice(&m.to_be_bytes());
            w[9..13].copy_from_slice(&pp.to_be_bytes());
            w
        };
        for (t, m, pp, what) in [
            (0, M_COST_KIB, 1, "t below the floor"),
            (3, MIN_M_KIB - 1, 1, "m below the floor"),
            (MAX_T + 1, M_COST_KIB, 1, "t above the ceiling"),
            (3, MAX_M_KIB + 1, 1, "m above the ceiling"),
            (3, u32::MAX, 1, "m huge"),
            (3, M_COST_KIB, 0, "p zero"),
            (3, M_COST_KIB, MAX_P + 1, "p above the ceiling"),
        ] {
            let started = std::time::Instant::now();
            wont_open(right.unwrap(&with(t, m, pp)), what);
            assert!(started.elapsed() < std::time::Duration::from_millis(200), "{what}: refused before Argon2id");
        }
    }

    #[test]
    fn the_strength_rule() {
        assert_eq!(strong_enough("Short1!"), Err(Weakness::TooShort));
        assert_eq!(strong_enough("Aa1!Aa1!Aa1"), Err(Weakness::TooShort), "11 characters");
        assert_eq!(strong_enough("alllowercaseletters"), Err(Weakness::TooFewKinds));
        assert_eq!(strong_enough("lowercase and 123"), Ok(()), "lower, digits, spaces");
        assert_eq!(strong_enough("UPPER lower words"), Ok(()), "upper, lower, spaces");
        assert_eq!(strong_enough("lowercaseUPPERCASE"), Err(Weakness::TooFewKinds), "two kinds");
        assert_eq!(strong_enough("Correct horse 9 battery"), Ok(()));
        // Characters, not bytes: 12 non-ASCII characters count as 12.
        assert_eq!(strong_enough("ÄÖÜäöü123456"), Ok(()));
        assert_eq!(strong_enough("ÄÖÜäöü12345"), Err(Weakness::TooShort));
    }
}
