//! The `hs.init`, `hs.resp` and `hs.fin` bodies (§6.2): strict parsing and
//! canonical marshalling, with the per-purpose field rules.
//!
//! Fields this client never sends or receives are refused when present:
//! `rotations` (reconnects, between vaults), and `device_attest`,
//! `api_key` and `unlock_secret` (purpose `app`, a phone). A desktop never
//! handles a handshake that carries them.

use ed25519_dalek::VerifyingKey;

use super::{validate_offer, HandshakeError, Purpose, MAX_CTX_LEN, MAX_PROFILE_LEN, MAX_TOKEN_LEN, MAX_URL_LEN, SAS_NONCE_SIZE};
use crate::strict_json::{self, as_uint, compact_object, Builder, Object};
use crate::suite::kem::PublicKey;
use crate::suite::EK_SIZE;

const BODY: HandshakeError = HandshakeError::Body;

/// A principal's relay address (`relay`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAddr {
    pub url: String,
    pub mailbox: String,
    pub pk: VerifyingKey,
}

/// The `from` of `hs.init`, and the `vault` of a claim bundle.
#[derive(Debug, Clone)]
pub struct Principal {
    pub ik: VerifyingKey,
    pub kem: PublicKey,
    pub relay: RelayAddr,
}

/// The `hs.init` body. `Debug` leaves out the tokens and the profile.
#[derive(Clone)]
pub struct Init {
    pub purpose: Purpose,
    pub ctx: String,
    pub from: Principal,
    pub eph: PublicKey,
    pub token: Option<String>,
    pub reconnect_token: Option<String>,
    pub suites: Vec<u64>,
    /// An optional object, as compact JSON text.
    pub profile: Option<String>,
    /// `SHA-256("vettid/vms/2/sas-commit" || n_I)`, exactly for purposes
    /// with a SAS.
    pub sas_commit: Option<[u8; SAS_NONCE_SIZE]>,
}

/// The `hs.resp` body. `Debug` leaves out the tokens.
#[derive(Clone, PartialEq, Eq)]
pub struct Resp {
    pub token: Option<String>,
    pub reconnect_token: Option<String>,
    pub suite: u64,
    /// `n_R`, exactly for purposes with a SAS.
    pub sas_nonce: Option<[u8; SAS_NONCE_SIZE]>,
    pub sig: [u8; 64],
}

/// The `hs.fin` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fin {
    pub sig: [u8; 64],
    /// `n_I`, revealed here, exactly for purposes with a SAS.
    pub sas_nonce: Option<[u8; SAS_NONCE_SIZE]>,
}

impl std::fmt::Debug for Init {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Init")
            .field("purpose", &self.purpose)
            .field("ctx", &self.ctx)
            .field("suites", &self.suites)
            .field("token", &self.token.as_ref().map(|_| ".."))
            .field("reconnect_token", &self.reconnect_token.as_ref().map(|_| ".."))
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Resp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resp")
            .field("suite", &self.suite)
            .field("token", &self.token.as_ref().map(|_| ".."))
            .field("reconnect_token", &self.reconnect_token.as_ref().map(|_| ".."))
            .finish_non_exhaustive()
    }
}

/// A relay base URL (§6.2): absolute, `https` (`http` only for a loopback
/// host, in development), no user info, query or fragment, at most 256
/// bytes, no whitespace.
pub fn valid_relay_url(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_URL_LEN || s.contains([' ', '\t', '\r', '\n']) {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return false;
    }
    let Ok(u) = url::Url::parse(s) else { return false };
    if !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() {
        return false;
    }
    match (u.scheme(), u.host()) {
        ("https", Some(_)) => true,
        ("http", Some(url::Host::Domain(d))) => d == "localhost",
        ("http", Some(url::Host::Ipv4(ip))) => ip.is_loopback(),
        ("http", Some(url::Host::Ipv6(ip))) => ip.is_loopback(),
        _ => false,
    }
}

/// The shape of a PASETO v4.public token: `v4.public.` then base64url and
/// `.` characters, at most 4,096 bytes. Its signature is the relay's to
/// check.
pub fn valid_token(s: &str) -> bool {
    const PREFIX: &str = "v4.public.";
    s.len() > PREFIX.len()
        && s.len() <= MAX_TOKEN_LEN
        && s.starts_with(PREFIX)
        && s[PREFIX.len()..].bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

/// `ctx`: 1–128 bytes of printable ASCII (`0x21`–`0x7e`).
pub fn valid_ctx(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_CTX_LEN && s.bytes().all(|c| (0x21..=0x7e).contains(&c))
}

impl RelayAddr {
    /// A 32-byte relay key, a mailbox id derived from it, and a valid URL.
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.mailbox != vettid_relay::auth::mailbox_id(&self.pk) || !valid_relay_url(&self.url) {
            return Err(BODY);
        }
        Ok(())
    }

    fn marshal(&self) -> String {
        Builder::new().string("url", &self.url).string("mailbox", &self.mailbox).base64("pk", self.pk.as_bytes()).finish()
    }
}

fn verifying_key(o: &Object<'_>, name: &str) -> Result<VerifyingKey, HandshakeError> {
    let b: [u8; 32] = o.base64(name, Some(32)).map_err(|_| BODY)?.try_into().map_err(|_| BODY)?;
    VerifyingKey::from_bytes(&b).map_err(|_| BODY)
}

fn kem_key(o: &Object<'_>, name: &str) -> Result<PublicKey, HandshakeError> {
    PublicKey::parse(&o.base64(name, Some(EK_SIZE)).map_err(|_| BODY)?).map_err(|_| BODY)
}

impl Principal {
    /// `{ik, kem, relay}`.
    pub fn marshal(&self) -> String {
        Builder::new()
            .base64("ik", self.ik.as_bytes())
            .base64("kem", self.kem.as_bytes())
            .raw("relay", &self.relay.marshal())
            .finish()
    }

    /// Parse and check `{ik, kem, relay}` at nesting `level`.
    pub fn parse(o: &Object<'_>, level: usize) -> Result<Self, HandshakeError> {
        let ik = verifying_key(o, "ik")?;
        let kem = kem_key(o, "kem")?;
        let r = o.object("relay", level).map_err(|_| BODY)?;
        let relay = RelayAddr {
            url: r.string("url").map_err(|_| BODY)?,
            mailbox: r.string("mailbox").map_err(|_| BODY)?,
            pk: verifying_key(&r, "pk")?,
        };
        relay.validate()?;
        Ok(Principal { ik, kem, relay })
    }
}

/// `token`/`reconnect_token` against its rule: required, optional or
/// forbidden; present ones must be PASETO-shaped.
fn check_token(rule: Option<bool>, v: &Option<String>) -> Result<(), HandshakeError> {
    match (rule, v) {
        (Some(true), None) | (Some(false), Some(_)) => Err(BODY),
        (_, Some(t)) if !valid_token(t) => Err(BODY),
        _ => Ok(()),
    }
}

/// The SAS field rule: present exactly for purposes with a SAS.
fn check_sas<T>(p: Purpose, v: &Option<T>) -> Result<(), HandshakeError> {
    if p.has_sas() != v.is_some() {
        return Err(BODY);
    }
    Ok(())
}

fn opt_token(o: &Object<'_>, name: &str) -> Result<Option<String>, HandshakeError> {
    match o.opt_string(name).map_err(|_| BODY)? {
        Some(t) if t.is_empty() => Err(BODY),
        t => Ok(t),
    }
}

fn opt_nonce(o: &Object<'_>, name: &str) -> Result<Option<[u8; SAS_NONCE_SIZE]>, HandshakeError> {
    if !o.has(name) {
        return Ok(None);
    }
    let b = o.base64(name, Some(SAS_NONCE_SIZE)).map_err(|_| BODY)?;
    Ok(Some(b.try_into().expect("checked length")))
}

fn sig(o: &Object<'_>) -> Result<[u8; 64], HandshakeError> {
    Ok(o.base64("sig", Some(64)).map_err(|_| BODY)?.try_into().expect("checked length"))
}

/// Refuse members this client never handles (see the module doc).
fn refuse(o: &Object<'_>, names: &[&str]) -> Result<(), HandshakeError> {
    if names.iter().any(|n| o.has(n)) {
        return Err(BODY);
    }
    Ok(())
}

impl Init {
    fn validate(&self) -> Result<(), HandshakeError> {
        if !valid_ctx(&self.ctx) {
            return Err(BODY);
        }
        self.from.relay.validate()?;
        // The ephemeral key is fresh: never the initiator's static key.
        if self.eph.ct_eq(&self.from.kem) {
            return Err(BODY);
        }
        let (tr, rr) = self.purpose.token_rules();
        check_token(tr, &self.token)?;
        check_token(rr, &self.reconnect_token)?;
        validate_offer(&self.suites)?;
        if let Some(p) = &self.profile {
            if !(self.purpose.is_pairing() || self.purpose == Purpose::Connection) || p.len() > MAX_PROFILE_LEN {
                return Err(BODY);
            }
        }
        check_sas(self.purpose, &self.sas_commit)
    }

    /// The canonical body: purpose, ctx, from, eph, token, reconnect_token,
    /// suites, profile, sas_commit (the vault's member order).
    pub fn marshal(&self) -> Result<String, HandshakeError> {
        self.validate()?;
        let mut b = Builder::new()
            .string("purpose", self.purpose.as_str())
            .string("ctx", &self.ctx)
            .raw("from", &self.from.marshal())
            .base64("eph", self.eph.as_bytes());
        if let Some(t) = &self.token {
            b = b.string("token", t);
        }
        if let Some(t) = &self.reconnect_token {
            b = b.string("reconnect_token", t);
        }
        let suites: Vec<String> = self.suites.iter().map(u64::to_string).collect();
        b = b.raw("suites", &format!("[{}]", suites.join(",")));
        if let Some(p) = &self.profile {
            b = b.raw("profile", &compact_object(p, 2).map_err(|_| BODY)?);
        }
        if let Some(c) = &self.sas_commit {
            b = b.base64("sas_commit", c);
        }
        Ok(b.finish())
    }

    /// Parse and check a body (on its own: level 1).
    pub fn parse(body: &str) -> Result<Self, HandshakeError> {
        let o = strict_json::parse_object(body.as_bytes()).map_err(|_| BODY)?;
        refuse(&o, &["rotations", "device_attest", "api_key", "unlock_secret"])?;
        let purpose = Purpose::parse(&o.string("purpose").map_err(|_| BODY)?).ok_or(BODY)?;
        let suites = o
            .array("suites")
            .map_err(|_| BODY)?
            .into_iter()
            .map(|raw| as_uint(raw, 0, 255).map_err(|_| BODY))
            .collect::<Result<Vec<_>, _>>()?;
        let profile = match o.get("profile") {
            None => None,
            Some(raw) => {
                if raw.len() > MAX_PROFILE_LEN {
                    return Err(BODY);
                }
                Some(compact_object(raw, 2).map_err(|_| BODY)?)
            }
        };
        let init = Init {
            purpose,
            ctx: o.string("ctx").map_err(|_| BODY)?,
            from: Principal::parse(&o.object("from", 1).map_err(|_| BODY)?, 2)?,
            eph: kem_key(&o, "eph")?,
            token: opt_token(&o, "token")?,
            reconnect_token: opt_token(&o, "reconnect_token")?,
            suites,
            profile,
            sas_commit: opt_nonce(&o, "sas_commit")?,
        };
        init.validate()?;
        Ok(init)
    }
}

impl Resp {
    fn validate(&self, p: Purpose) -> Result<(), HandshakeError> {
        let (tr, rr) = p.token_rules();
        check_token(tr, &self.token)?;
        check_token(rr, &self.reconnect_token)?;
        if self.suite > 255 {
            return Err(BODY);
        }
        check_sas(p, &self.sas_nonce)
    }

    /// The canonical body for a handshake of purpose `p`: token,
    /// reconnect_token, suite, sas_nonce, sig.
    pub fn marshal(&self, p: Purpose) -> Result<String, HandshakeError> {
        self.validate(p)?;
        let mut b = Builder::new();
        if let Some(t) = &self.token {
            b = b.string("token", t);
        }
        if let Some(t) = &self.reconnect_token {
            b = b.string("reconnect_token", t);
        }
        b = b.uint("suite", self.suite);
        if let Some(n) = &self.sas_nonce {
            b = b.base64("sas_nonce", n);
        }
        Ok(b.base64("sig", &self.sig).finish())
    }

    /// Parse and check a body for a handshake of purpose `p`.
    pub fn parse(body: &str, p: Purpose) -> Result<Self, HandshakeError> {
        let o = strict_json::parse_object(body.as_bytes()).map_err(|_| BODY)?;
        refuse(&o, &["rotations"])?;
        let r = Resp {
            token: opt_token(&o, "token")?,
            reconnect_token: opt_token(&o, "reconnect_token")?,
            suite: o.uint("suite", 0, 255).map_err(|_| BODY)?,
            sas_nonce: opt_nonce(&o, "sas_nonce")?,
            sig: sig(&o)?,
        };
        r.validate(p)?;
        Ok(r)
    }
}

impl Fin {
    /// `{sig, sas_nonce?}` for a handshake of purpose `p`.
    pub fn marshal(&self, p: Purpose) -> Result<String, HandshakeError> {
        check_sas(p, &self.sas_nonce)?;
        let mut b = Builder::new().base64("sig", &self.sig);
        if let Some(n) = &self.sas_nonce {
            b = b.base64("sas_nonce", n);
        }
        Ok(b.finish())
    }

    /// Parse a body for a handshake of purpose `p`.
    pub fn parse(body: &str, p: Purpose) -> Result<Self, HandshakeError> {
        let o = strict_json::parse_object(body.as_bytes()).map_err(|_| BODY)?;
        let f = Fin { sig: sig(&o)?, sas_nonce: opt_nonce(&o, "sas_nonce")? };
        check_sas(p, &f.sas_nonce)?;
        Ok(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::vectors;

    fn init_body() -> String {
        vectors::load("handshake")["hs_init_body"].as_str().unwrap().to_string()
    }

    /// handshake.json's hs.init body parses and marshals back byte for
    /// byte; its from is keys.json's initiator.
    #[test]
    fn init_vector_round_trips() {
        let body = init_body();
        let i = Init::parse(&body).unwrap();
        assert_eq!(i.purpose, Purpose::Connection);
        assert_eq!(i.marshal().unwrap(), body);
        let keys = vectors::load("keys");
        assert_eq!(i.from.kem.as_bytes().to_vec(), vectors::b64(&keys["initiator"]["ek_b64"]));
        assert_eq!(i.from.relay.mailbox, keys["initiator"]["mailbox"].as_str().unwrap());
        assert_eq!(i.eph.as_bytes().to_vec(), vectors::b64(&keys["initiator_ephemeral"]["ek_b64"]));
    }

    #[test]
    fn init_rules() {
        let body = init_body();
        let with = |f: &dyn Fn(&mut serde_json::Map<String, serde_json::Value>)| {
            let mut m: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&body).unwrap();
            f(&mut m);
            Init::parse(&serde_json::to_string(&m).unwrap())
        };
        use serde_json::json;
        type Edit = Box<dyn Fn(&mut serde_json::Map<String, serde_json::Value>)>;
        let cases: Vec<(&str, Edit)> = vec![
            ("bad purpose", Box::new(|m| { m.insert("purpose".into(), json!("Desktop")); })),
            ("empty ctx", Box::new(|m| { m.insert("ctx".into(), json!("")); })),
            ("ctx with space", Box::new(|m| { m.insert("ctx".into(), json!("a b")); })),
            ("long ctx", Box::new(|m| { m.insert("ctx".into(), json!("a".repeat(129))); })),
            ("no token", Box::new(|m| { m.remove("token"); })),
            ("empty token", Box::new(|m| { m.insert("token".into(), json!("")); })),
            ("bad token", Box::new(|m| { m.insert("token".into(), json!("v4.local.x")); })),
            ("reconnect token on a connection", Box::new(|m| { m.insert("reconnect_token".into(), json!("v4.public.x")); })),
            ("suite 1", Box::new(|m| { m.insert("suites".into(), json!([1, 2])); })),
            ("descending suites", Box::new(|m| { m.insert("suites".into(), json!([3, 2])); })),
            ("no sas_commit", Box::new(|m| { m.remove("sas_commit"); })),
            ("short sas_commit", Box::new(|m| { m.insert("sas_commit".into(), json!("AAAA")); })),
            ("eph equals from.kem", Box::new(|m| { let k = m["from"]["kem"].clone(); m.insert("eph".into(), k); })),
            ("rotations", Box::new(|m| { m.insert("rotations".into(), json!([])); })),
            ("device_attest", Box::new(|m| { m.insert("device_attest".into(), json!({})); })),
            ("profile not an object", Box::new(|m| { m.insert("profile".into(), json!([])); })),
            ("mailbox mismatch", Box::new(|m| { m["from"]["relay"]["mailbox"] = json!("aaaaaaaaaaaaaaaaaaaaaaaaaa"); })),
            ("http relay", Box::new(|m| { m["from"]["relay"]["url"] = json!("http://relay.example"); })),
            ("short ik", Box::new(|m| { m["from"]["ik"] = json!("AAAA"); })),
        ];
        for (why, f) in cases {
            assert!(with(&*f).is_err(), "{why}");
        }
        // A profile is kept compact; a rekey has none and no sas_commit.
        let ok = with(&|m| { m.insert("profile".into(), json!({"name": "Laptop"})); }).unwrap();
        assert_eq!(ok.profile.as_deref(), Some(r#"{"name":"Laptop"}"#));
        let rekey = with(&|m| { m.insert("purpose".into(), json!("rekey")); m.remove("sas_commit"); m.remove("token"); }).unwrap();
        assert_eq!((rekey.purpose, rekey.sas_commit), (Purpose::Rekey, None));
        assert!(with(&|m| { m.insert("purpose".into(), json!("rekey")); m.insert("profile".into(), json!({})); m.remove("sas_commit"); }).is_err());
    }

    #[test]
    fn resp_and_fin_rules() {
        let v = vectors::load("handshake");
        // The body's own text (serde_json would reorder its members).
        let inner_text = v["hs_resp_inner"].as_str().unwrap();
        let body = strict_json::parse_object(inner_text.as_bytes()).unwrap().get("body").unwrap().to_string();
        let r = Resp::parse(&body, Purpose::Connection).unwrap();
        assert_eq!(r.marshal(Purpose::Connection).unwrap(), body);
        assert_eq!(r.sig.to_vec(), vectors::b64(&v["sig_R_b64"]));
        // The SAS nonce is wrong for a rekey; a desktop's resp needs a token.
        assert_eq!(Resp::parse(&body, Purpose::Rekey), Err(HandshakeError::Body));
        let no_token = body.replacen(r#""token":"v4.public.VEVTVC1PTkxZLXJlc3Atc3RhbmRpbmc","#, "", 1);
        assert_eq!(Resp::parse(&no_token, Purpose::Desktop), Err(HandshakeError::Body));
        let rotations = body.replacen(r#""suite":2"#, r#""suite":2,"rotations":[]"#, 1);
        assert_eq!(Resp::parse(&rotations, Purpose::Connection), Err(HandshakeError::Body));
        let short_sig = body.replacen(r#""sig":""#, r#""sig":"AAAA","x":""#, 1);
        assert_eq!(Resp::parse(&short_sig, Purpose::Connection), Err(HandshakeError::Body));

        let f = Fin { sig: [7; 64], sas_nonce: Some([1; 32]) };
        let fb = f.marshal(Purpose::Desktop).unwrap();
        assert_eq!(Fin::parse(&fb, Purpose::Desktop).unwrap(), f);
        assert_eq!(Fin::parse(&fb, Purpose::Rekey), Err(HandshakeError::Body));
        assert_eq!(f.marshal(Purpose::Rekey), Err(HandshakeError::Body));
    }

    /// Tokens are bearer secrets: `Debug` never prints them.
    #[test]
    fn debug_prints_no_token_material() {
        let i = Init::parse(&init_body()).unwrap();
        let s = format!("{i:?}");
        assert!(s.contains("Connection") && !s.contains("VEVTVC") && !s.contains("v4.public"), "{s}");
        let v = vectors::load("handshake");
        let inner_text = v["hs_resp_inner"].as_str().unwrap();
        let body = strict_json::parse_object(inner_text.as_bytes()).unwrap().get("body").unwrap().to_string();
        let r = Resp::parse(&body, Purpose::Connection).unwrap();
        assert_eq!(format!("{r:?}"), r#"Resp { suite: 2, token: Some(".."), reconnect_token: None, .. }"#);
    }

    #[test]
    fn relay_urls_and_tokens() {
        for ok in ["https://relay.vettid.dev", "https://relay.example:8443/", "http://localhost:8080", "http://127.0.0.1:1", "http://[::1]:2"] {
            assert!(valid_relay_url(ok), "{ok}");
        }
        for bad in ["", "relay.example", "ftp://relay.example", "http://relay.example", "http://10.0.0.1", "https://u:p@relay.example", "https://relay.example/?q", "https://relay.example/#f", "https://relay .example", "https:relay.example"] {
            assert!(!valid_relay_url(bad), "{bad}");
        }
        assert!(!valid_relay_url(&format!("https://{}.example", "a".repeat(250))));
        assert!(valid_token("v4.public.abc-_.DEF"));
        for bad in ["v4.public.", "v4.local.abc", "v4.public.a+b", "v4.public.a=b"] {
            assert!(!valid_token(bad), "{bad}");
        }
        assert!(!valid_token(&format!("v4.public.{}", "a".repeat(4087))));
    }
}
