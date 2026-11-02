//! Invitations and pairing codes, scanner side (VAULT-MESSAGING §6.4):
//! the QR / link payload, the claim bundle it points to, and the checks
//! a scanner MUST make before it trusts the bundle: `SHA-256(blob)` = `h`
//! (constant time) before decrypting, then the bundle's `kind` against
//! `t`, its `exp` against `e`, and expiry.
//!
//! A desktop scans; the vault creates invitations, so sealing a bundle is
//! here only for the known-answer test. A phone's transfer (`t` = `p`,
//! kind `app`, with its `capabilities` and `time_scale`) is refused: a
//! desktop never takes one.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, NaiveDateTime, Utc};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::handshake::{valid_relay_url, valid_token, Principal, Purpose};
use crate::strict_json::{self, Builder};
use crate::suite::aead::open_x;
use crate::suite::{check_suite, ct_eq, SuiteError, KEY_SIZE, LABEL_BUNDLE, TAG_SIZE, XNONCE_SIZE};

/// The QR payload version.
pub const QR_VERSION: u64 = 2;
/// The bundle version.
pub const BUNDLE_VERSION: u64 = 1;
/// A claim id's length.
pub const CLAIM_ID_LEN: usize = 26;
/// The longest `hint.name` kept (the vault's bound).
pub const MAX_HINT_NAME: usize = 128;
/// The longest link payload decoded, and its base64url length.
pub const MAX_LINK_PAYLOAD: usize = 1024;
const MAX_LINK_LEN: usize = 1366;

const EXP_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

/// Why an invitation was refused. Carries no input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteError {
    /// A malformed QR or link payload.
    Qr,
    /// A malformed bundle.
    Bundle,
    /// `SHA-256(blob)` isn't the QR's `h`.
    Hash,
    /// The bundle didn't decrypt under `k`.
    Decrypt,
    /// The invitation has expired.
    Expired,
    /// The bundle's `kind` doesn't match the QR's `t`.
    Kind,
    /// The bundle's suite was refused.
    Suite(SuiteError),
}

impl std::fmt::Display for InviteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Qr => f.write_str("invite: malformed QR / link payload"),
            Self::Bundle => f.write_str("invite: malformed bundle"),
            Self::Hash => f.write_str("invite: bundle does not match the commitment"),
            Self::Decrypt => f.write_str("invite: bundle decryption failed"),
            Self::Expired => f.write_str("invite: invite expired"),
            Self::Kind => f.write_str("invite: bundle kind does not match the QR"),
            Self::Suite(e) => write!(f, "invite: {e}"),
        }
    }
}

impl std::error::Error for InviteError {}

/// The QR's `t`: what the invitation is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `c`: a connection between vaults.
    Connection,
    /// `p`: a transfer to a new phone.
    App,
    /// `d`: pair a desktop.
    Desktop,
    /// `a`: pair an agent.
    Agent,
}

impl Kind {
    fn letter(self) -> &'static str {
        match self {
            Self::Connection => "c",
            Self::App => "p",
            Self::Desktop => "d",
            Self::Agent => "a",
        }
    }

    fn from_letter(s: &str) -> Option<Self> {
        [Self::Connection, Self::App, Self::Desktop, Self::Agent].into_iter().find(|k| k.letter() == s)
    }

    /// The bundle `kind`, which is also the handshake purpose.
    pub fn purpose(self) -> Purpose {
        match self {
            Self::Connection => Purpose::Connection,
            Self::App => Purpose::App,
            Self::Desktop => Purpose::Desktop,
            Self::Agent => Purpose::Agent,
        }
    }
}

/// The QR / link payload. `Debug` leaves out `k`.
#[derive(Clone, PartialEq, Eq)]
pub struct Qr {
    pub kind: Kind,
    /// The relay base URL (`r`): it decides the relay, whatever host a
    /// link's URL had.
    pub relay: String,
    pub claim_id: String,
    /// `SHA-256(blob)`.
    pub hash: [u8; 32],
    /// `k_b`, the bundle key.
    pub key: Zeroizing<[u8; KEY_SIZE]>,
    /// The invitation's expiry, Unix seconds.
    pub exp: u64,
}

impl std::fmt::Debug for Qr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Qr").field("kind", &self.kind).field("relay", &self.relay).field("exp", &self.exp).finish_non_exhaustive()
    }
}

fn valid_claim_id(s: &str) -> bool {
    s.len() == CLAIM_ID_LEN && s.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
}

/// Decode canonical unpadded base64url of exactly `n` bytes (`None`: any
/// length): no padding, CR or LF, and no other spelling of the same bytes.
fn decode_raw_url(s: &str, n: Option<usize>) -> Option<Vec<u8>> {
    let b = URL_SAFE_NO_PAD.decode(s).ok()?;
    if n.is_some_and(|n| b.len() != n) || URL_SAFE_NO_PAD.encode(&b) != s {
        return None;
    }
    Some(b)
}

impl Qr {
    fn validate(&self) -> Result<(), InviteError> {
        // A transfer to a new phone is never for a desktop.
        if self.kind == Kind::App || !valid_relay_url(&self.relay) || !valid_claim_id(&self.claim_id) || self.exp == 0 {
            return Err(InviteError::Qr);
        }
        Ok(())
    }

    /// The compact JSON a QR code holds.
    pub fn marshal(&self) -> Result<String, InviteError> {
        self.validate()?;
        Ok(Builder::new()
            .uint("v", QR_VERSION)
            .string("t", self.kind.letter())
            .string("r", &self.relay)
            .string("c", &self.claim_id)
            .string("h", &URL_SAFE_NO_PAD.encode(self.hash))
            .string("k", &URL_SAFE_NO_PAD.encode(&self.key[..]))
            .uint("e", self.exp)
            .finish())
    }

    /// The link: the unpadded base64url of [`Qr::marshal`].
    pub fn link(&self) -> Result<String, InviteError> {
        Ok(URL_SAFE_NO_PAD.encode(self.marshal()?))
    }

    /// Parse the compact JSON strictly.
    pub fn parse(b: &[u8]) -> Result<Self, InviteError> {
        let qr = |_| InviteError::Qr;
        let o = strict_json::parse_object(b).map_err(qr)?;
        o.uint("v", QR_VERSION, QR_VERSION).map_err(qr)?;
        let kind = Kind::from_letter(&o.string("t").map_err(qr)?).ok_or(InviteError::Qr)?;
        let hash = decode_raw_url(&o.string("h").map_err(qr)?, Some(32)).ok_or(InviteError::Qr)?;
        let key = decode_raw_url(&o.string("k").map_err(qr)?, Some(KEY_SIZE)).ok_or(InviteError::Qr)?;
        let q = Qr {
            kind,
            relay: o.string("r").map_err(qr)?,
            claim_id: o.string("c").map_err(qr)?,
            hash: hash.try_into().expect("checked length"),
            key: Zeroizing::new(key.try_into().expect("checked length")),
            exp: o.uint("e", 1, strict_json::MAX_SAFE_INTEGER).map_err(qr)?,
        };
        q.validate()?;
        Ok(q)
    }

    /// Parse a link payload (unpadded base64url of the compact JSON).
    pub fn parse_link(s: &str) -> Result<Self, InviteError> {
        // The length is checked before decoding anything.
        if s.len() > MAX_LINK_LEN {
            return Err(InviteError::Qr);
        }
        let b = decode_raw_url(s, None).ok_or(InviteError::Qr)?;
        if b.len() > MAX_LINK_PAYLOAD {
            return Err(InviteError::Qr);
        }
        Self::parse(&b)
    }

    /// Whatever a scan or a paste gave (§6.4): the compact JSON of a QR
    /// code, a bare link payload, or a URL whose whole fragment is the
    /// payload (`<relay>/connect#<link>`, `vettid://connect#<link>`). The
    /// URL's host is not trusted: the payload's `r` decides the relay.
    pub fn parse_any(text: &str) -> Result<Self, InviteError> {
        let t = text.trim_matches(|c: char| c.is_ascii_whitespace());
        if t.starts_with('{') {
            return Self::parse(t.as_bytes());
        }
        match t.split_once('#') {
            Some((url, frag)) if url.ends_with("/connect") => Self::parse_link(frag),
            Some(_) => Err(InviteError::Qr),
            None => Self::parse_link(t),
        }
    }
}

/// The claim bundle. `Debug` leaves out the token.
#[derive(Clone)]
pub struct Bundle {
    /// `connection`, `app`, `desktop` or `agent`.
    pub kind: Purpose,
    /// The invite id, or for pairing the pairing id.
    pub invite_id: String,
    pub remote: bool,
    pub vault: Principal,
    /// The open token (its `exp` is the invite's).
    pub token: String,
    /// Whole seconds.
    pub exp: DateTime<Utc>,
    /// The inviter's display name (anyone with the link can read it).
    pub hint_name: Option<String>,
    /// `peer_kind: "service"` (connections only; anything else ignored).
    pub service: bool,
}

impl std::fmt::Debug for Bundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bundle")
            .field("kind", &self.kind)
            .field("invite_id", &self.invite_id)
            .field("exp", &self.exp)
            .finish_non_exhaustive()
    }
}

fn format_exp(t: DateTime<Utc>) -> String {
    t.format(EXP_FORMAT).to_string()
}

fn parse_exp(s: &str) -> Option<DateTime<Utc>> {
    let t = NaiveDateTime::parse_from_str(s, EXP_FORMAT).ok()?.and_utc();
    (s.len() == 20 && format_exp(t) == s).then_some(t)
}

impl Bundle {
    fn validate(&self) -> Result<(), InviteError> {
        let bad = |c: bool| if c { Err(InviteError::Bundle) } else { Ok(()) };
        bad(matches!(self.kind, Purpose::Rekey | Purpose::Reconnect))?;
        bad(self.remote && self.kind != Purpose::Connection)?;
        bad(!crate::envelope::valid_ulid(&self.invite_id) || !valid_token(&self.token))?;
        bad(self.hint_name.as_ref().is_some_and(|n| n.len() > MAX_HINT_NAME))?;
        bad(self.exp.timestamp_subsec_nanos() != 0)?;
        self.vault.relay.validate().map_err(|_| InviteError::Bundle)
    }

    /// The canonical JSON, in the vault's member order.
    pub fn marshal(&self) -> Result<String, InviteError> {
        self.validate()?;
        let mut b = Builder::new()
            .uint("v", BUNDLE_VERSION)
            .uint("suite", u64::from(crate::suite::SUITE_2))
            .string("kind", self.kind.as_str())
            .string("invite_id", &self.invite_id)
            .bool("remote", self.remote)
            .raw("vault", &self.vault.marshal())
            .string("token", &self.token)
            .string("exp", &format_exp(self.exp));
        if let Some(n) = self.hint_name.as_deref().filter(|n| !n.is_empty()) {
            b = b.raw("hint", &Builder::new().string("name", n).finish());
        }
        if self.service && self.kind == Purpose::Connection {
            b = b.string("peer_kind", "service");
        }
        Ok(b.finish())
    }

    /// Parse a bundle strictly.
    pub fn parse(raw: &[u8]) -> Result<Self, InviteError> {
        let bundle = |_| InviteError::Bundle;
        let o = strict_json::parse_object(raw).map_err(bundle)?;
        o.uint("v", BUNDLE_VERSION, BUNDLE_VERSION).map_err(bundle)?;
        let suite = o.uint("suite", 0, 255).map_err(bundle)?;
        check_suite(suite as u8).map_err(InviteError::Suite)?;
        if o.has("capabilities") || o.has("time_scale") {
            return Err(InviteError::Bundle);
        }
        let kind = Purpose::parse(&o.string("kind").map_err(bundle)?).ok_or(InviteError::Bundle)?;
        let hint_name = if o.has("hint") {
            o.object("hint", 1).map_err(bundle)?.opt_string("name").map_err(bundle)?
        } else {
            None
        };
        let service = kind == Purpose::Connection && o.opt_string("peer_kind").ok().flatten().as_deref() == Some("service");
        let b = Bundle {
            kind,
            invite_id: o.string("invite_id").map_err(bundle)?,
            remote: o.bool("remote").map_err(bundle)?,
            vault: Principal::parse(&o.object("vault", 1).map_err(bundle)?, 2).map_err(|_| InviteError::Bundle)?,
            token: o.string("token").map_err(bundle)?,
            exp: parse_exp(&o.string("exp").map_err(bundle)?).ok_or(InviteError::Bundle)?,
            hint_name,
            service,
        };
        b.validate()?;
        Ok(b)
    }
}

/// Open a claim's `blob` with the QR that points to it, as a scanner
/// MUST: `SHA-256(blob)` = `h` in constant time before decrypting, then
/// decrypt under `k`, then refuse a bundle whose `kind` isn't `t`, whose
/// `exp` isn't `e`, or that has expired at `now`.
pub fn open_bundle(blob: &[u8], qr: &Qr, now: DateTime<Utc>) -> Result<Bundle, InviteError> {
    let got: [u8; 32] = Sha256::digest(blob).into();
    if !ct_eq(&got, &qr.hash) {
        return Err(InviteError::Hash);
    }
    if blob.len() < XNONCE_SIZE + TAG_SIZE {
        return Err(InviteError::Decrypt);
    }
    let nonce: &[u8; XNONCE_SIZE] = blob[..XNONCE_SIZE].try_into().expect("checked length");
    let json = open_x(&qr.key, nonce, LABEL_BUNDLE.as_bytes(), &blob[XNONCE_SIZE..]).map_err(|_| InviteError::Decrypt)?;
    let b = Bundle::parse(&json)?;
    if b.kind != qr.kind.purpose() {
        return Err(InviteError::Kind);
    }
    if b.exp.timestamp() < 0 || b.exp.timestamp() as u64 != qr.exp {
        return Err(InviteError::Bundle);
    }
    if now >= b.exp {
        return Err(InviteError::Expired);
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::aead::seal_x;
    use crate::suite::vectors;

    fn s(v: &serde_json::Value) -> &str {
        v.as_str().unwrap()
    }

    /// `blob = nonce || XChaCha20-Poly1305(k_b, nonce, "vettid/vms/2/bundle",
    /// json)`, with the key and nonce given (the vault seals; tests only).
    fn seal_bundle(json: &str, key: &[u8; 32], nonce: &[u8; 24]) -> Vec<u8> {
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&seal_x(key, nonce, LABEL_BUNDLE.as_bytes(), json.as_bytes()).unwrap());
        blob
    }

    fn vector() -> (serde_json::Value, Qr, Vec<u8>, DateTime<Utc>) {
        let v = vectors::load("invite");
        let qr = Qr::parse(s(&v["qr_json"]).as_bytes()).unwrap();
        let blob = vectors::b64(&v["blob_b64"]);
        let now = DateTime::parse_from_rfc3339(s(&v["now"])).unwrap().with_timezone(&Utc);
        (v, qr, blob, now)
    }

    /// invite.json, byte for byte: the blob from its key and nonce, h, the
    /// QR JSON and the link, and the bundle opened back.
    #[test]
    fn invite_vector() {
        let (v, qr, blob, now) = vector();
        let key: [u8; 32] = vectors::hex(&v["k_b_hex"]).try_into().unwrap();
        let nonce: [u8; 24] = vectors::hex(&v["nonce_hex"]).try_into().unwrap();
        assert_eq!(seal_bundle(s(&v["bundle_json"]), &key, &nonce), blob);
        let h: [u8; 32] = Sha256::digest(&blob).into();
        assert_eq!(h.to_vec(), vectors::hex(&v["h_hex"]));
        assert_eq!((qr.hash, *qr.key), (h, key));
        assert_eq!(qr.marshal().unwrap(), s(&v["qr_json"]));
        assert_eq!(qr.link().unwrap(), s(&v["link"]));
        assert_eq!(Qr::parse_link(s(&v["link"])).unwrap(), qr);
        let b = open_bundle(&blob, &qr, now).unwrap();
        assert_eq!(b.marshal().unwrap(), s(&v["bundle_json"]));
        assert_eq!((b.kind, b.hint_name.as_deref(), b.remote, b.service), (Purpose::Connection, Some("Test Vault"), false, false));
        let keys = vectors::load("keys");
        assert_eq!(b.vault.kem.as_bytes().to_vec(), vectors::b64(&keys["vault"]["ek_b64"]));
        assert_eq!(format!("{qr:?}"), r#"Qr { kind: Connection, relay: "https://relay.vettid.org", exp: 1790856600, .. }"#);
        assert_eq!(format!("{b:?}"), r#"Bundle { kind: Connection, invite_id: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", exp: 2026-10-01T12:10:00Z, .. }"#);
    }

    #[test]
    fn scanner_checks() {
        let (_, qr, blob, now) = vector();
        let mut tampered = blob.clone();
        tampered[30] ^= 1;
        assert_eq!(open_bundle(&tampered, &qr, now).unwrap_err(), InviteError::Hash, "the hash before decrypting");
        let mut wrong_key = qr.clone();
        wrong_key.key = Zeroizing::new([1; 32]);
        assert_eq!(open_bundle(&blob, &wrong_key, now).unwrap_err(), InviteError::Decrypt);
        let mut desktop = qr.clone();
        desktop.kind = Kind::Desktop;
        assert_eq!(open_bundle(&blob, &desktop, now).unwrap_err(), InviteError::Kind);
        let mut other_exp = qr.clone();
        other_exp.exp += 1;
        assert_eq!(open_bundle(&blob, &other_exp, now).unwrap_err(), InviteError::Bundle);
        let at_exp = DateTime::from_timestamp(qr.exp as i64, 0).unwrap();
        assert_eq!(open_bundle(&blob, &qr, at_exp).unwrap_err(), InviteError::Expired);
        assert!(open_bundle(&blob, &qr, at_exp - chrono::TimeDelta::seconds(1)).is_ok());
        let short_hash = Qr { hash: Sha256::digest(&blob[..10]).into(), ..qr.clone() };
        assert_eq!(open_bundle(&blob[..10], &short_hash, now).unwrap_err(), InviteError::Decrypt);
    }

    #[test]
    fn link_forms() {
        let (v, qr, _, _) = vector();
        let link = s(&v["link"]);
        for text in [
            link.to_string(),
            format!("  {link}\n"),
            format!("https://relay.vettid.org/connect#{link}"),
            format!("https://some.other.host/connect#{link}"),
            format!("vettid://connect#{link}"),
            s(&v["qr_json"]).to_string(),
        ] {
            assert_eq!(Qr::parse_any(&text).unwrap(), qr, "{text}");
        }
        for bad in [
            format!("https://relay.vettid.org/other#{link}"),
            format!("{link}="),
            format!("{link}!"),
            String::new(),
            format!("vettid://connect/#{link}"),
        ] {
            assert_eq!(Qr::parse_any(&bad).unwrap_err(), InviteError::Qr, "{bad}");
        }
        // The cap: a valid payload padded (with JSON whitespace) to 1,024
        // bytes is read, one byte more is not.
        let json = s(&v["qr_json"]);
        let padded = |n: usize| URL_SAFE_NO_PAD.encode(format!("{json}{}", " ".repeat(n - json.len())));
        assert_eq!(Qr::parse_link(&padded(MAX_LINK_PAYLOAD)).unwrap(), qr);
        assert_eq!(padded(MAX_LINK_PAYLOAD).len(), MAX_LINK_LEN);
        assert_eq!(Qr::parse_link(&padded(MAX_LINK_PAYLOAD + 1)).unwrap_err(), InviteError::Qr);
    }

    #[test]
    fn qr_rules() {
        let (v, _, _, _) = vector();
        let good: serde_json::Value = serde_json::from_str(s(&v["qr_json"])).unwrap();
        let with = |k: &str, val: serde_json::Value| {
            let mut m = good.clone();
            if val.is_null() {
                m.as_object_mut().unwrap().remove(k);
            } else {
                m[k] = val;
            }
            Qr::parse(serde_json::to_string(&m).unwrap().as_bytes())
        };
        use serde_json::json;
        for (k, val) in [
            ("v", json!(1)),
            ("t", json!("x")),
            ("t", json!("C")),
            ("t", json!("p")),
            ("r", json!("http://relay.vettid.org")),
            ("c", json!("TESTCLAIMIDAAAAAAAAAAAAAAA")),
            ("c", json!("short")),
            ("h", json!("3IInuX43e1sMeCmuM03vngkxfYg_j-QQomOXuuLthk4=")),
            ("h", json!("AAAA")),
            ("k", json!("FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBR")),
            ("e", json!(0)),
            ("e", json!("1790856600")),
            ("e", serde_json::Value::Null),
        ] {
            assert_eq!(with(k, val.clone()).unwrap_err(), InviteError::Qr, "{k} = {val}");
        }
    }

    #[test]
    fn bundle_rules() {
        let (v, _, _, _) = vector();
        let good: serde_json::Value = serde_json::from_str(s(&v["bundle_json"])).unwrap();
        let with = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut m = good.clone();
            f(&mut m);
            Bundle::parse(serde_json::to_string(&m).unwrap().as_bytes())
        };
        use serde_json::json;
        type Edit = Box<dyn Fn(&mut serde_json::Value)>;
        let cases: Vec<(&str, InviteError, Edit)> = vec![
            ("v 2", InviteError::Bundle, Box::new(|m| m["v"] = json!(2))),
            ("unknown kind", InviteError::Bundle, Box::new(|m| m["kind"] = json!("rekey"))),
            ("remote pairing", InviteError::Bundle, Box::new(|m| { m["kind"] = json!("desktop"); m["remote"] = json!(true); })),
            ("bad invite id", InviteError::Bundle, Box::new(|m| m["invite_id"] = json!("x"))),
            ("bad token", InviteError::Bundle, Box::new(|m| m["token"] = json!("v4.local.x"))),
            ("exp with millis", InviteError::Bundle, Box::new(|m| m["exp"] = json!("2026-10-01T12:10:00.000Z"))),
            ("exp with offset", InviteError::Bundle, Box::new(|m| m["exp"] = json!("2026-10-01T12:10:00+00:00"))),
            ("hint name too long", InviteError::Bundle, Box::new(|m| m["hint"]["name"] = json!("n".repeat(129)))),
            ("hint not an object", InviteError::Bundle, Box::new(|m| m["hint"] = json!("x"))),
            ("hint name null", InviteError::Bundle, Box::new(|m| m["hint"]["name"] = json!(null))),
            ("capabilities", InviteError::Bundle, Box::new(|m| m["capabilities"] = json!([]))),
            ("time_scale", InviteError::Bundle, Box::new(|m| m["time_scale"] = json!(1))),
            ("remote not bool", InviteError::Bundle, Box::new(|m| m["remote"] = json!(0))),
            ("vault mailbox mismatch", InviteError::Bundle, Box::new(|m| m["vault"]["relay"]["mailbox"] = json!("aaaaaaaaaaaaaaaaaaaaaaaaaa"))),
        ];
        for (why, want, f) in cases {
            assert_eq!(with(&*f).unwrap_err(), want, "{why}");
        }
        // The edges that are allowed.
        assert_eq!(with(&|m| m["hint"]["name"] = json!("n".repeat(128))).unwrap().hint_name.map(|n| n.len()), Some(128));
        assert!(with(&|m| m["remote"] = json!(true)).unwrap().remote, "remote on a connection");
        assert_eq!(with(&|m| m["suite"] = json!(1)).unwrap_err(), InviteError::Suite(SuiteError::Suite1));
        // peer_kind: only "service" on a connection counts; anything else is ignored.
        assert!(with(&|m| m["peer_kind"] = json!("service")).unwrap().service);
        assert!(!with(&|m| m["peer_kind"] = json!("robot")).unwrap().service);
        assert!(!with(&|m| m["peer_kind"] = json!(7)).unwrap().service);
        assert!(!with(&|m| { m["kind"] = json!("desktop"); m["peer_kind"] = json!("service"); }).unwrap().service);
        let desktop = with(&|m| m["kind"] = json!("desktop")).unwrap();
        assert_eq!(desktop.kind, Purpose::Desktop);
    }
}
