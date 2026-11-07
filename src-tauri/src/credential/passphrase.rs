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
//! **One form.** The passphrase is normalized to NFC before the strength
//! rule and before Argon2id, as the vault and the apps do (VAULT-MESSAGING
//! §11.14.7). The format is bound to NFC: the same passphrase in NFD opens
//! the file; changing the normalization would lock existing files out.
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
//! SECURITY: zeroized here: the passphrase, Argon2id's working memory (64
//! MiB of blocks this module allocates, fallibly, and wipes; the crate's
//! `zeroize` feature wipes its initial and final hashes), the Argon2id
//! output, the wrap key, the decrypted key buffer, and the cipher's key (on
//! drop, by `chacha20poly1305`). Not zeroized, a residual risk: Argon2's
//! stack temporaries while it runs, the HMAC state inside `hkdf` (hmac
//! 0.12 doesn't wipe it), and the NFC normalizer's small internal buffers
//! (of a few characters). Nothing here logs a secret. The passphrase
//! reaches Rust as a webview string, which can't be zeroized there (§4
//! accepts that).
//!
//! **Errors.** A wrapped key of the wrong shape, another format or
//! parameters out of bounds "won't open" (they never will). A seal that
//! doesn't open with the passphrase given is its own answer,
//! `NotThisSecret`: a wrong passphrase and a changed file look the same, and
//! the person is asked again, never told to re-pair because of a typo
//! (review M2, lead review; the text comes with the UI, item 4). Running out
//! of memory or random bytes is `Failing`.

// Wired into `Protectors` by the passphrase UI (#13 item 4), which removes
// this.
#![cfg_attr(not(test), allow(dead_code))]

use argon2::{Algorithm, Argon2, Block, Params, Version};
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
    /// The passphrase is normalized to NFC first (see [`nfc`]).
    pub(crate) fn new(secret: Zeroizing<String>) -> Self {
        Passphrase { secret: nfc(&secret) }
    }
}

/// `s` in Unicode Normalization Form C, into a buffer that is wiped when
/// dropped. The vault and the apps normalize every password to NFC before
/// any use (VAULT-MESSAGING §11.14.7, "One form"), so the same passphrase
/// typed through another input method or operating system (NFD, say)
/// opens the same file. The format is bound to NFC: changing this would
/// lock existing files out. The buffer is sized for the worst case (NFC
/// output is at most three times the input's UTF-8 length), so it never
/// grows and leaves no copy behind.
pub(crate) fn nfc(s: &str) -> Zeroizing<String> {
    use unicode_normalization::UnicodeNormalization;
    let mut out = Zeroizing::new(String::with_capacity(s.len().saturating_mul(3)));
    out.extend(s.nfc());
    out
}

fn failing(what: &str, e: impl std::fmt::Display) -> ProtectorError {
    ProtectorError::Failing { by: NAME, detail: format!("{what}: {e}") }
}

/// The wrap key from the passphrase, the parameters and the salt.
fn wrap_key(secret: &str, t: u32, m_kib: u32, p: u32, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, ProtectorError> {
    let params = Params::new(m_kib, t, p, Some(KEY_LEN)).map_err(|e| failing("argon2 parameters", e))?;
    // Argon2's working memory, allocated here so it is wiped afterwards
    // (any block is enough to recompute the output), and fallibly, so a
    // machine without the memory gets "failing", not an abort (review).
    let n = params.block_count();
    let mut blocks: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    blocks.try_reserve_exact(n).map_err(|e| failing("argon2 memory", e))?;
    blocks.resize(n, Block::default());
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut stretched = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into_with_memory(secret.as_bytes(), salt, &mut *stretched, blocks.as_mut_slice())
        .map_err(|e| failing("argon2", e))?;
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

/// The wrap, with every input given (the known-answer test pins it).
fn wrap_with(
    secret: &str,
    key: &[u8; 32],
    t: u32,
    m_kib: u32,
    p: u32,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, ProtectorError> {
    let head = head(t, m_kib, p, salt);
    let wk = wrap_key(secret, t, m_kib, p, salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*wk).map_err(|e| failing("cipher", e))?;
    let sealed = cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: key, aad: &head })
        .map_err(|_| failing("seal", "the data key couldn't be sealed"))?;
    let mut out = head;
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    debug_assert_eq!(out.len(), WRAPPED_LEN);
    Ok(out)
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
        rand::rngs::OsRng.try_fill_bytes(&mut salt).map_err(|e| failing("random salt", e))?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut nonce).map_err(|e| failing("random nonce", e))?;
        wrap_with(&self.secret, key, T_COST, M_COST_KIB, P_COST, &salt, &nonce)
    }

    /// A wrong passphrase and a changed header look the same (the seal
    /// doesn't open): `NotThisSecret`, so the person can try again and the
    /// file is kept (see the module doc). The parameters are checked against the
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
            .map_err(|_| ProtectorError::NotThisSecret { by: NAME })?;
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

pub(crate) use super::password_rule::Weakness;

/// The vault's password rule, at the apps' floor (`password_rule`), judged
/// in NFC, the form that is used (lead decision).
pub(crate) fn strong_enough(passphrase: &str) -> Result<(), Weakness> {
    // Refused before NFC when NFC couldn't bring it under the limit (it
    // shortens UTF-8 to a third at most: three Hangul jamo of three bytes
    // each compose to one syllable of three), so a huge paste isn't
    // normalized first (lead review).
    if passphrase.len() > 3 * super::password_rule::MAX_BYTES {
        return Err(Weakness::TooLong);
    }
    super::password_rule::check(&nfc(passphrase))
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

    /// A seal that doesn't open with this passphrase: its own answer, so the
    /// person is asked again and the file kept (never "won't open", which
    /// would tell them to re-pair).
    fn not_this_passphrase(r: Result<DataKey, ProtectorError>, what: &str) {
        match r {
            Err(ProtectorError::NotThisSecret { by }) => assert_eq!(by, NAME, "{what}"),
            other => panic!("{what}: expected not this secret, got {:?}", other.map(|_| "a key")),
        }
    }

    #[test]
    fn a_passphrase_round_trips_and_a_wrong_one_is_asked_again() {
        let right = p("Correct horse 9 battery");
        assert_eq!(right.id(), ID);
        assert_eq!(right.availability(), Availability::Present);
        right.probe().unwrap();
        let wrapped = right.wrap(&key(1)).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_LEN);
        assert_eq!(wrapped[0], FORMAT);
        assert_eq!((be32(&wrapped[1..5]), be32(&wrapped[5..9]), be32(&wrapped[9..13])), (T_COST, M_COST_KIB, P_COST));
        assert_eq!(*right.unwrap(&wrapped).unwrap(), key(1));
        not_this_passphrase(p("Correct horse 9 batterY").unwrap(&wrapped), "wrong passphrase");
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
    fn a_changed_wrapped_key_doesnt_open() {
        let right = p("Correct horse 9 battery");
        let wrapped = right.wrap(&key(2)).unwrap();
        // One position in each part; the parameters stay within bounds
        // (t 3 -> 2), so Argon2id runs and the seal itself refuses.
        for (at, flip) in [(4usize, 1u8), (13, 1), (HEAD_LEN, 1), (HEAD_LEN + NONCE_LEN, 1), (WRAPPED_LEN - 1, 1)] {
            let mut changed = wrapped.clone();
            changed[at] ^= flip;
            not_this_passphrase(right.unwrap(&changed), &format!("byte {at}"));
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
            // `m = u32::MAX` alone shows the check comes first (Argon2id
            // would fail to allocate 4 TiB); the time limit is generous.
            let started = std::time::Instant::now();
            wont_open(right.unwrap(&with(t, m, pp)), what);
            assert!(started.elapsed() < std::time::Duration::from_secs(2), "{what}: refused before Argon2id");
        }
    }

    /// The floor itself is accepted (t=1, m=8 MiB, p=1), and the ceiling of
    /// p.
    #[test]
    fn the_floor_is_accepted() {
        let right = p("Correct horse 9 battery");
        let floor = wrap_with(&right.secret, &key(4), MIN_T, MIN_M_KIB, 1, &[7; SALT_LEN], &[9; NONCE_LEN]).unwrap();
        assert_eq!(*right.unwrap(&floor).unwrap(), key(4));
        let p4 = wrap_with(&right.secret, &key(5), MIN_T, MIN_M_KIB, MAX_P, &[7; SALT_LEN], &[9; NONCE_LEN]).unwrap();
        assert_eq!(*right.unwrap(&p4).unwrap(), key(5));
    }

    /// A known answer (review M3): a change to the label, the layout, the
    /// byte order, the associated data or the crates' behaviour would lock
    /// every existing passphrase file out, so the exact bytes are pinned. At
    /// the floor parameters, to stay fast.
    #[test]
    fn a_known_answer() {
        let wrapped = wrap_with("Correct horse 9 battery", &key(6), MIN_T, MIN_M_KIB, 1, &[0x11; SALT_LEN], &[0x22; NONCE_LEN]).unwrap();
        assert_eq!(hex::encode(&wrapped), KNOWN_ANSWER);
        let stored = hex::decode(KNOWN_ANSWER).unwrap();
        assert_eq!(*p("Correct horse 9 battery").unwrap(&stored).unwrap(), key(6));
    }

    const KNOWN_ANSWER: &str = concat!(
        "01000000010000200000000001",
        "11111111111111111111111111111111",
        "222222222222222222222222222222222222222222222222",
        "bf544ef7d8d0da2a9e61ad136f8abb806033c224723cd7075615ea611697e2665e33ccd14f39705f4991b5981a62ec38",
    );

    /// One form (lead decision): a passphrase wrapped as typed in NFC opens
    /// when typed in NFD, and the reverse; the strength rule judges the NFC
    /// form.
    #[test]
    fn nfd_and_nfc_open_the_same_file() {
        use unicode_normalization::UnicodeNormalization;
        let composed: String = "Pässwörd Ünïcode 9".nfc().collect();
        let decomposed: String = composed.nfd().collect();
        assert_ne!(composed.as_bytes(), decomposed.as_bytes(), "the two forms differ in bytes");
        let wrapped = p(&composed).wrap(&key(7)).unwrap();
        assert_eq!(*p(&decomposed).unwrap(&wrapped).unwrap(), key(7));
        let wrapped_nfd = p(&decomposed).wrap(&key(8)).unwrap();
        assert_eq!(*p(&composed).unwrap(&wrapped_nfd).unwrap(), key(8));
        // 12 characters in NFC, 14 code points in NFD: judged as 12.
        let twelve: String = "ÄÖÜäöü123456".nfd().collect();
        assert!(twelve.chars().count() > 12);
        assert_eq!(strong_enough(&twelve), Ok(()));
        let eleven: String = "ÄÖÜäöü12345".nfd().collect();
        assert_eq!(strong_enough(&eleven), Err(Weakness::Short), "NFD's extra code points don't count");
    }

    #[test]
    fn the_strength_rule() {
        // The vault's rule (password_rule has the full checks); judged in NFC.
        assert_eq!(strong_enough("Short1!"), Err(Weakness::Short));
        assert_eq!(strong_enough("zzzzzzzzzzzzzzzz"), Err(Weakness::Repeated));
        assert_eq!(strong_enough("Password1234"), Err(Weakness::Common));
        assert_eq!(strong_enough("qwertyuiopasdf"), Err(Weakness::Guessable));
        assert_eq!(strong_enough("correct horse battery staple"), Ok(()));
        assert_eq!(strong_enough("glacier mango tuesday piano"), Ok(()), "no capitals or digits needed");
    }

    /// The length limit before NFC never refuses what NFC would bring under
    /// 1,024 bytes: Hangul, decomposed, is three times as long.
    #[test]
    fn the_length_before_nfc() {
        use unicode_normalization::UnicodeNormalization;
        assert_eq!(strong_enough(&"x".repeat(3 * 1024 + 1)), Err(Weakness::TooLong));
        // 341 syllables with a final consonant: 1,023 bytes in NFC, 3,069 in NFD.
        let syllables: String = (0..341).map(|i| char::from_u32(0xAC01 + 28 * (i % 399)).unwrap()).collect();
        let decomposed: String = syllables.nfd().collect();
        assert_eq!((syllables.len(), decomposed.len()), (1023, 3069));
        assert_ne!(strong_enough(&decomposed), Err(Weakness::TooLong));
        assert_eq!(strong_enough(&decomposed), strong_enough(&syllables));
    }
}
