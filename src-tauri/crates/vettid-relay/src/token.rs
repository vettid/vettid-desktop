//! Deposit tokens: PASETO v4.public (RELAY-PROTOCOL §5).
//!
//! Signing and verification are the `pasetors` crate's (v4.public); this
//! module adds the protocol's rules on top: the form checks, the claim
//! JSON in spec order, and the claim rules. Footer and implicit assertion
//! are empty in protocol v1 (§5.1); a token carrying a footer is refused.

#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(test)]
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey};
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use pasetors::Public;
use serde::Deserialize;

use crate::auth;

const HEADER: &str = "v4.public.";

/// The longest token parsed (a deposit token is about 450 bytes).
pub const MAX_TOKEN_LEN: usize = 4096;

/// The longest `jti` accepted.
pub const MAX_JTI_LEN: usize = 128;

/// Token scopes (§5.2, §5.6).
pub const SCOPE_DEPOSIT: &str = "deposit";
pub const SCOPE_DEPOSIT_OPEN: &str = "deposit_open";
/// The `sub` of a one-shot open token.
pub const OPEN_SUB: &str = "*";

/// Why a token was refused. Neither variant carries token material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Malformed, badly signed, or with invalid claims (`token_invalid`).
    Invalid,
    /// Outside `[iat, exp)` (`token_expired`).
    Expired,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "deposit token invalid",
            Self::Expired => "deposit token expired",
        })
    }
}

impl std::error::Error for TokenError {}

/// A deposit token as sent (`v4.public.…`). An open token is a bearer
/// capability (§5.6), so its `Debug` prints nothing and it has no
/// `Display`: use [`Token::as_str`] where it's sent. It has no `PartialEq`
/// either, so it isn't compared in variable time by accident.
#[derive(Clone)]
pub struct Token(String);

impl Token {
    /// A token received from a peer, kept as is. It isn't checked here:
    /// only the mailbox owner (the relay) can verify it.
    pub fn from_received(token: String) -> Self {
        Self(token)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

/// A v4.public token over the exact message bytes `m` (empty footer and
/// implicit assertion). Ed25519 is deterministic: the same key and bytes
/// always give the same token.
///
/// Refuses an empty message (`pasetors` does).
pub fn sign_token(key: &SigningKey, m: &[u8]) -> Result<Token, TokenError> {
    // The 64-byte keypair copy is wiped when dropped; pasetors' key type
    // wipes its own.
    let keypair = zeroize::Zeroizing::new(key.to_keypair_bytes());
    let secret = AsymmetricSecretKey::<V4>::from(&keypair[..]).map_err(|_| TokenError::Invalid)?;
    PublicToken::sign(&secret, m, None, None).map(Token).map_err(|_| TokenError::Invalid)
}

/// Check a token's form and signature against `issuer`, and return the
/// signed message bytes.
pub fn verify_token(token: &str, issuer: &VerifyingKey) -> Result<Vec<u8>, TokenError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(TokenError::Invalid);
    }
    let rest = token.strip_prefix(HEADER).ok_or(TokenError::Invalid)?;
    // No footer, and only the base64url alphabet, so a token has one
    // spelling.
    if !rest.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        return Err(TokenError::Invalid);
    }
    let untrusted = UntrustedToken::<Public, V4>::try_from(token).map_err(|_| TokenError::Invalid)?;
    let issuer = AsymmetricPublicKey::<V4>::from(issuer.as_bytes()).map_err(|_| TokenError::Invalid)?;
    // Footer `None`: pasetors then accepts any footer, and `Some(b"")`
    // refuses footer-less tokens too, so the "no footer" rule is the
    // alphabet check above (a footer needs a second '.'), tested below.
    //
    // pasetors verifies with ed25519-compact: non-canonical S, non-canonical
    // points and small-order keys and R are refused (as strict as Go's
    // `ed25519.Verify`, stricter on small order), but its final equation is
    // cofactored where Go's is not. Only the issuer's own key could make a
    // token that passes here and fails at the relay; that is no forgery, and
    // the deposit would fail as `token_invalid`.
    let trusted = PublicToken::verify(&issuer, &untrusted, None, None).map_err(|_| TokenError::Invalid)?;
    Ok(trusted.payload().as_bytes().to_vec())
}

/// The optional per-token deposit cap (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Quota {
    pub msgs: Option<i64>,
    pub bytes: Option<i64>,
}

/// Deposit-token claims (§5.2). `Debug` leaves out `sub` (a relay key)
/// and `jti` (the revocation handle).
#[derive(Clone, PartialEq, Eq)]
pub struct Claims {
    /// The issuing (recipient) mailbox id.
    pub iss: String,
    /// The sender's relay key, canonical base64, or `*` for an open token.
    pub sub: String,
    /// The relay base URL the token is for.
    pub aud: String,
    pub iat: DateTime<Utc>,
    pub exp: DateTime<Utc>,
    pub jti: String,
    pub scope: String,
    pub quota: Option<Quota>,
    /// (0.9.2) Minted by the mailbox owner for one of its own devices.
    pub owner_device: bool,
}

impl std::fmt::Debug for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Claims")
            .field("iss", &self.iss)
            .field("sub", &"..")
            .field("aud", &self.aud)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .field("jti", &"..")
            .field("scope", &self.scope)
            .field("quota", &self.quota)
            .field("owner_device", &self.owner_device)
            .finish()
    }
}

impl Claims {
    /// Whether this is a one-shot open token (§5.6).
    pub fn is_open(&self) -> bool {
        self.scope == SCOPE_DEPOSIT_OPEN
    }

    /// The sender's relay key, for a sender-bound token.
    pub fn sub_key(&self) -> Option<VerifyingKey> {
        if self.is_open() {
            None
        } else {
            auth::decode_key(&self.sub)
        }
    }

    /// The compact JSON claims in spec key order (iss, sub, aud, iat, exp,
    /// jti, scope[, quota][, owner_device]), timestamps in whole seconds,
    /// escaped as Go's encoder does (U+2028 and U+2029 too), so the bytes
    /// match the relay's own `MintToken`.
    pub fn to_json(&self) -> String {
        let s = |v: &str| {
            serde_json::to_string(v)
                .expect("a string always serializes")
                .replace('\u{2028}', "\\u2028")
                .replace('\u{2029}', "\\u2029")
        };
        let t = |v: &DateTime<Utc>| s(&v.to_rfc3339_opts(SecondsFormat::Secs, true));
        let mut out = format!(
            "{{\"iss\":{},\"sub\":{},\"aud\":{},\"iat\":{},\"exp\":{},\"jti\":{},\"scope\":{}",
            s(&self.iss),
            s(&self.sub),
            s(&self.aud),
            t(&self.iat),
            t(&self.exp),
            s(&self.jti),
            s(if self.scope.is_empty() { SCOPE_DEPOSIT } else { &self.scope }),
        );
        if let Some(q) = &self.quota {
            let mut parts = Vec::new();
            if let Some(m) = q.msgs {
                parts.push(format!("\"msgs\":{m}"));
            }
            if let Some(b) = q.bytes {
                parts.push(format!("\"bytes\":{b}"));
            }
            out.push_str(&format!(",\"quota\":{{{}}}", parts.join(",")));
        }
        if self.owner_device {
            out.push_str(",\"owner_device\":true");
        }
        out.push('}');
        out
    }
}

/// Sign `claims` as a deposit token (§5). Claims this crate would refuse
/// to parse (a negative quota, an empty `jti`, a scope that doesn't fit
/// `sub`, a year past 9999) aren't signed; nor are claims whose `iss`
/// isn't the signing key's own mailbox (the relay would refuse them,
/// §5.3 step 3), or whose `exp` isn't after `iat` in whole seconds.
pub fn mint_token(key: &SigningKey, claims: &Claims) -> Result<Token, TokenError> {
    if claims.iss != auth::mailbox_id(&key.verifying_key()) || claims.exp.timestamp() <= claims.iat.timestamp() {
        return Err(TokenError::Invalid);
    }
    let json = claims.to_json();
    parse_claims(json.as_bytes())?;
    sign_token(key, json.as_bytes())
}

// Unknown quota members are ignored, as unknown claims are.
#[derive(Deserialize)]
struct WireQuota {
    msgs: Option<i64>,
    bytes: Option<i64>,
}

#[derive(Deserialize)]
struct WireClaims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
    iat: Option<String>,
    exp: Option<String>,
    jti: Option<String>,
    scope: Option<String>,
    quota: Option<WireQuota>,
    // Read from the map below (null must be told from absent); declared
    // here so a duplicated claim is still refused.
    #[allow(dead_code)]
    owner_device: Option<serde_json::Value>,
}

/// Decode and structurally check claim JSON. Every required claim must be
/// present with the right type; unknown claims are ignored; a duplicated
/// claim is refused. Timestamps must be RFC 3339 as Go's `time.RFC3339`
/// parses them. It has no length cap of its own: tokens reach it through
/// [`verify_token`] (at most [`MAX_TOKEN_LEN`]).
pub fn parse_claims(m: &[u8]) -> Result<Claims, TokenError> {
    let text = std::str::from_utf8(m).map_err(|_| TokenError::Invalid)?;
    // The typed parse refuses a duplicated claim; the map tells a present
    // owner_device (null included) from an absent one.
    let w: WireClaims = serde_json::from_str(text).map_err(|_| TokenError::Invalid)?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(text).map_err(|_| TokenError::Invalid)?;
    let (Some(iss), Some(sub), Some(aud), Some(iat), Some(exp), Some(jti), Some(scope)) =
        (w.iss, w.sub, w.aud, w.iat, w.exp, w.jti, w.scope)
    else {
        return Err(TokenError::Invalid);
    };
    // Only the literal true is valid (§5.2).
    let owner_device = match map.get("owner_device") {
        None => false,
        Some(serde_json::Value::Bool(true)) => true,
        Some(_) => return Err(TokenError::Invalid),
    };
    let time = |v: &str| strict_time(v).ok_or(TokenError::Invalid);
    let claims = Claims {
        iat: time(&iat)?,
        exp: time(&exp)?,
        iss,
        sub,
        aud,
        jti,
        scope,
        quota: w.quota.map(|q| Quota { msgs: q.msgs, bytes: q.bytes }),
        owner_device,
    };
    match claims.scope.as_str() {
        SCOPE_DEPOSIT if auth::decode_key(&claims.sub).is_some() => {}
        SCOPE_DEPOSIT_OPEN if claims.sub == OPEN_SUB => {}
        _ => return Err(TokenError::Invalid),
    }
    if claims.jti.is_empty() || claims.jti.len() > MAX_JTI_LEN || !auth::valid_mailbox_id(&claims.iss) {
        return Err(TokenError::Invalid);
    }
    if let Some(q) = claims.quota {
        if q.msgs.is_some_and(|n| n < 0) || q.bytes.is_some_and(|n| n < 0) {
            return Err(TokenError::Invalid);
        }
    }
    Ok(claims)
}

/// An RFC 3339 timestamp in the shape Go's `time.RFC3339` accepts:
/// `YYYY-MM-DDTHH:MM:SS[.frac](Z|±hh:mm)`, uppercase `T` and `Z`, seconds
/// at most 59. chrono alone also takes a lowercase `t` or `z`, a space for
/// `T`, and a leap second, which the relay refuses.
fn strict_time(v: &str) -> Option<DateTime<Utc>> {
    let b = v.as_bytes();
    let digits = |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    let shape = b.len() >= 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && &v[17..19] <= "59";
    if !shape {
        return None;
    }
    let mut rest = &v[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        rest = &frac[n..];
    }
    let zone = rest == "Z"
        || (rest.len() == 6
            && matches!(rest.as_bytes()[0], b'+' | b'-')
            && rest.as_bytes()[1..3].iter().all(u8::is_ascii_digit)
            && rest.as_bytes()[3] == b':'
            && rest.as_bytes()[4..6].iter().all(u8::is_ascii_digit));
    if !zone {
        return None;
    }
    DateTime::parse_from_rfc3339(v).ok().map(|t| t.with_timezone(&Utc))
}

/// Verify a token against the issuer's key and parse its claims.
pub fn parse_token(token: &str, issuer: &VerifyingKey) -> Result<Claims, TokenError> {
    parse_claims(&verify_token(token, issuer)?)
}

/// Whether `claims` are in force at `now`: `iat <= now < exp`.
pub fn check_time(claims: &Claims, now: DateTime<Utc>) -> Result<(), TokenError> {
    if now < claims.iat || now >= claims.exp {
        Err(TokenError::Expired)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{recipient, sender};

    const VECTOR_CLAIMS: &str = r#"{"iss":"gr2q7gf5lh6pzfdnurnkvputhp","sub":"gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=","aud":"https://relay.example.vettid.org","iat":"2026-06-10T00:00:00Z","exp":"2026-07-10T00:00:00Z","jti":"01JXAMPLE0000000000000000","scope":"deposit"}"#;
    const VECTOR_TOKEN: &str = "v4.public.eyJpc3MiOiJncjJxN2dmNWxoNnB6ZmRudXJua3ZwdXRocCIsInN1YiI6ImdUbDNEcWg5RjE5V28xUm13MHgrek11TmlwRzA3amVpWGZZUFc0L0pzNVE9IiwiYXVkIjoiaHR0cHM6Ly9yZWxheS5leGFtcGxlLnZldHRpZC5vcmciLCJpYXQiOiIyMDI2LTA2LTEwVDAwOjAwOjAwWiIsImV4cCI6IjIwMjYtMDctMTBUMDA6MDA6MDBaIiwianRpIjoiMDFKWEFNUExFMDAwMDAwMDAwMDAwMDAwMCIsInNjb3BlIjoiZGVwb3NpdCJ9rWQjEmgif2o_c9SNTUXzHPPLWKZCPMAPUk3VPpbWkTIY0pfihNHpVZeX-YDM35FN_u1FVYPHj4BrO4sGJQj6BA";

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn vector_claims() -> Claims {
        Claims {
            iss: "gr2q7gf5lh6pzfdnurnkvputhp".into(),
            sub: auth::encode_key(&sender().verifying_key()),
            aud: "https://relay.example.vettid.org".into(),
            iat: t("2026-06-10T00:00:00Z"),
            exp: t("2026-07-10T00:00:00Z"),
            jti: "01JXAMPLE0000000000000000".into(),
            scope: SCOPE_DEPOSIT.into(),
            quota: None,
            owner_device: false,
        }
    }

    /// §9.2: signing the exact claim bytes reproduces the token, byte for
    /// byte; minting from the claims gives the same bytes; it verifies and
    /// parses back.
    #[test]
    fn vector_9_2_deposit_token() {
        assert_eq!(sign_token(&recipient(), VECTOR_CLAIMS.as_bytes()).unwrap().as_str(), VECTOR_TOKEN);
        assert_eq!(vector_claims().to_json(), VECTOR_CLAIMS);
        assert_eq!(mint_token(&recipient(), &vector_claims()).unwrap().as_str(), VECTOR_TOKEN);
        let claims = parse_token(VECTOR_TOKEN, &recipient().verifying_key()).unwrap();
        assert_eq!(claims, vector_claims());
        assert_eq!(claims.sub_key(), Some(sender().verifying_key()));
        assert!(!claims.is_open());
    }

    /// Optional claims serialize in spec order and parse back.
    #[test]
    fn quota_owner_device_and_open_tokens_round_trip() {
        let mut c = vector_claims();
        c.quota = Some(Quota { msgs: Some(5), bytes: None });
        c.owner_device = true;
        assert!(c.to_json().ends_with(r#""scope":"deposit","quota":{"msgs":5},"owner_device":true}"#));
        assert_eq!(parse_token(mint_token(&recipient(), &c).unwrap().as_str(), &recipient().verifying_key()).unwrap(), c);

        let mut open = vector_claims();
        open.scope = SCOPE_DEPOSIT_OPEN.into();
        open.sub = OPEN_SUB.into();
        let parsed = parse_token(mint_token(&recipient(), &open).unwrap().as_str(), &recipient().verifying_key()).unwrap();
        assert!(parsed.is_open());
        assert_eq!(parsed.sub_key(), None);
    }

    /// A token that isn't exactly what was signed, by this key, is refused.
    #[test]
    fn malformed_or_foreign_tokens_are_refused() {
        let key = recipient().verifying_key();
        let mut tampered = VECTOR_TOKEN.to_string();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        for bad in [
            tampered.as_str(),
            &VECTOR_TOKEN.replacen("v4.public.", "v4.local.", 1),
            &format!("{VECTOR_TOKEN}.e30"),     // a footer
            &PublicTokenWithFooter::make(),     // a validly signed token with a footer
            &format!("{VECTOR_TOKEN}="),        // padding
            &VECTOR_TOKEN.replacen('_', "/", 1), // standard alphabet
            &format!("{}\n{}", &VECTOR_TOKEN[..20], &VECTOR_TOKEN[20..]),
            &format!("{}\r{}", &VECTOR_TOKEN[..20], &VECTOR_TOKEN[20..]),
            "v4.public.",
            "v4.public.AAAA",
            &format!("v4.public.{}", "A".repeat(MAX_TOKEN_LEN)),
        ] {
            assert_eq!(verify_token(bad, &key), Err(TokenError::Invalid), "{bad:.40}");
        }
        assert_eq!(verify_token(VECTOR_TOKEN, &sender().verifying_key()), Err(TokenError::Invalid), "another key");
    }

    /// Claims that break §5.2's rules are refused.
    #[test]
    fn invalid_claims_are_refused() {
        let base = VECTOR_CLAIMS;
        let edit = |from: &str, to: &str| base.replacen(from, to, 1);
        for (what, bad) in [
            ("missing jti", edit(r#","jti":"01JXAMPLE0000000000000000""#, "")),
            ("unknown scope", edit(r#""scope":"deposit""#, r#""scope":"read""#)),
            ("open token naming a sender", edit(r#""scope":"deposit""#, r#""scope":"deposit_open""#)),
            ("sender-bound with sub *", edit(r#""sub":"gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=""#, r#""sub":"*""#)),
            ("non-canonical sub", edit("Js5Q=", "Js5R=")),
            ("bad iss", edit("gr2q7gf5lh6pzfdnurnkvputhp", "GR2Q7GF5LH6PZFDNURNKVPUTHP")),
            ("empty jti", edit("01JXAMPLE0000000000000000", "")),
            ("bad time", edit("2026-06-10T00:00:00Z", "2026-06-10")),
            ("wrong type", edit(r#""jti":"01JXAMPLE0000000000000000""#, r#""jti":7"#)),
            ("owner_device false", base.replacen('}', r#","owner_device":false}"#, 1)),
            ("owner_device null", base.replacen('}', r#","owner_device":null}"#, 1)),
            ("negative quota", base.replacen('}', r#","quota":{"msgs":-1}}"#, 1)),
            ("duplicate claim", base.replacen('}', r#","jti":"other"}"#, 1)),
            ("trailing data", format!("{base}{{}}")),
            ("trailing brace", format!("{base}}}")),
            ("duplicate owner_device", base.replacen('}', r#","owner_device":false,"owner_device":true}"#, 1)),
            ("lowercase t", edit("2026-06-10T00:00:00Z", "2026-06-10t00:00:00Z")),
            ("lowercase z", edit("2026-06-10T00:00:00Z", "2026-06-10T00:00:00z")),
            ("space for T", edit("2026-06-10T00:00:00Z", "2026-06-10 00:00:00Z")),
            ("leap second", edit("2026-06-10T00:00:00Z", "2026-06-10T23:59:60Z")),
            ("comma fraction", edit("2026-06-10T00:00:00Z", "2026-06-10T00:00:00,5Z")),
        ] {
            assert_eq!(parse_claims(bad.as_bytes()), Err(TokenError::Invalid), "{what}");
        }
        assert_eq!(parse_claims(&[0xff, 0xfe]), Err(TokenError::Invalid), "not UTF-8");
        let unknown = base.replacen('}', r#","extra":1}"#, 1);
        assert!(parse_claims(unknown.as_bytes()).is_ok(), "unknown claims are ignored");
        let unknown_quota = base.replacen('}', r#","quota":{"msgs":1,"x":2}}"#, 1);
        assert!(parse_claims(unknown_quota.as_bytes()).is_ok(), "unknown quota members are ignored");
        for ok in ["2026-06-10T00:00:00.5Z", "2026-06-10T02:00:00+02:00", "2026-06-10T00:00:00.000Z"] {
            assert!(parse_claims(edit("2026-06-10T00:00:00Z", ok).as_bytes()).is_ok(), "{ok}");
        }
    }

    struct PublicTokenWithFooter;
    impl PublicTokenWithFooter {
        /// A token signed by the recipient with a non-empty footer.
        fn make() -> String {
            let secret = AsymmetricSecretKey::<V4>::from(&recipient().to_keypair_bytes()).unwrap();
            PublicToken::sign(&secret, VECTOR_CLAIMS.as_bytes(), Some(b"footer"), None).unwrap()
        }
    }

    /// An empty message isn't signed.
    #[test]
    fn an_empty_message_is_not_signed() {
        assert!(matches!(sign_token(&recipient(), b""), Err(TokenError::Invalid)));
    }

    /// A byte changed inside the signed message, re-encoded, fails the
    /// signature check itself.
    #[test]
    fn a_changed_message_byte_fails_the_signature() {
        let rest = VECTOR_TOKEN.strip_prefix("v4.public.").unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(rest).unwrap();
        raw[3] ^= 0x01;
        let tampered = format!("v4.public.{}", URL_SAFE_NO_PAD.encode(raw));
        assert_eq!(verify_token(&tampered, &recipient().verifying_key()), Err(TokenError::Invalid));
    }

    /// Tokens of the shapes the vault issues, minted by the relay's own Go
    /// `relayauth.MintToken` (vettid-relay 3d7ce03): a standing token with
    /// a full quota and owner_device, and an open token with a message
    /// quota. Rust mints the same bytes and parses them back.
    #[test]
    fn go_minted_tokens_match() {
        const GO_STANDING: &str = "v4.public.eyJpc3MiOiJncjJxN2dmNWxoNnB6ZmRudXJua3ZwdXRocCIsInN1YiI6ImdUbDNEcWg5RjE5V28xUm13MHgrek11TmlwRzA3amVpWGZZUFc0L0pzNVE9IiwiYXVkIjoiaHR0cHM6Ly9yZWxheS52ZXR0aWQudGVzdCIsImlhdCI6IjIwMjYtMDYtMTBUMDA6MDA6MDBaIiwiZXhwIjoiMjAyNi0wNy0xMFQwMDowMDowMFoiLCJqdGkiOiIwMUpTVEFORElORzAwMDAwMDAwMDAwMDAwIiwic2NvcGUiOiJkZXBvc2l0IiwicXVvdGEiOnsibXNncyI6MTAwLCJieXRlcyI6MTA0ODU3Nn0sIm93bmVyX2RldmljZSI6dHJ1ZX1g9SgDbxAzDWYLXeFQNsOb-tX2vZfe_m2DlQihHs8v5P8wyFIuL0zUnvNqtme1pEXq7EaO75K3uFkht0GTnXUJ";
        const GO_OPEN: &str = "v4.public.eyJpc3MiOiJncjJxN2dmNWxoNnB6ZmRudXJua3ZwdXRocCIsInN1YiI6IioiLCJhdWQiOiJodHRwczovL3JlbGF5LnZldHRpZC50ZXN0IiwiaWF0IjoiMjAyNi0wNi0xMFQwMDowMDowMFoiLCJleHAiOiIyMDI2LTA2LTEwVDAwOjEwOjAwWiIsImp0aSI6IjAxSk9QRU4wMDAwMDAwMDAwMDAwMDAwMDAiLCJzY29wZSI6ImRlcG9zaXRfb3BlbiIsInF1b3RhIjp7Im1zZ3MiOjF9fQV8XGpR1h4ru-LVKX3RI5h3ldnQ6eqSBTzvqN8YgtkajA6fQXSH_xYVvk59dyzTIZlNiVQmrzPljEPe8Ab8uAo";
        let standing = Claims {
            iss: "gr2q7gf5lh6pzfdnurnkvputhp".into(),
            sub: auth::encode_key(&sender().verifying_key()),
            aud: "https://relay.vettid.test".into(),
            iat: t("2026-06-10T00:00:00Z"),
            exp: t("2026-07-10T00:00:00Z"),
            jti: "01JSTANDING00000000000000".into(),
            scope: SCOPE_DEPOSIT.into(),
            quota: Some(Quota { msgs: Some(100), bytes: Some(1_048_576) }),
            owner_device: true,
        };
        let open = Claims {
            sub: OPEN_SUB.into(),
            exp: t("2026-06-10T00:10:00Z"),
            jti: "01JOPEN000000000000000000".into(),
            scope: SCOPE_DEPOSIT_OPEN.into(),
            quota: Some(Quota { msgs: Some(1), bytes: None }),
            owner_device: false,
            ..standing.clone()
        };
        for (claims, go) in [(&standing, GO_STANDING), (&open, GO_OPEN)] {
            assert_eq!(mint_token(&recipient(), claims).unwrap().as_str(), go);
            assert_eq!(&parse_token(go, &recipient().verifying_key()).unwrap(), claims);
        }
    }

    /// Optional quota shapes round trip: bytes only, and empty.
    #[test]
    fn quota_shapes_round_trip() {
        for quota in [Quota { msgs: None, bytes: Some(9) }, Quota::default()] {
            let c = Claims { quota: Some(quota), ..vector_claims() };
            let token = mint_token(&recipient(), &c).unwrap();
            assert_eq!(parse_token(token.as_str(), &recipient().verifying_key()).unwrap(), c);
        }
        let empty = Claims { quota: Some(Quota::default()), ..vector_claims() };
        assert!(empty.to_json().contains(r#","quota":{}"#));
    }

    /// U+2028 and U+2029 are escaped as Go's encoder does.
    #[test]
    fn line_separators_are_escaped_as_go_does() {
        let c = Claims { aud: "https://r\u{2028}\u{2029}".into(), ..vector_claims() };
        assert!(c.to_json().contains(r#""aud":"https://r\u2028\u2029""#), "{}", c.to_json());
    }

    /// Claims the parser would refuse are not minted.
    #[test]
    fn invalid_claims_are_not_minted() {
        let bad = [
            Claims { quota: Some(Quota { msgs: Some(-1), bytes: None }), ..vector_claims() },
            Claims { jti: String::new(), ..vector_claims() },
            Claims { scope: SCOPE_DEPOSIT_OPEN.into(), ..vector_claims() },
            Claims {
                exp: chrono::NaiveDate::from_ymd_opt(10000, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc(),
                ..vector_claims()
            },
            // Another mailbox's iss: the recipient key signs only its own.
            Claims { iss: auth::mailbox_id(&sender().verifying_key()), ..vector_claims() },
            // exp not after iat once both are in whole seconds.
            Claims { exp: t("2026-06-10T00:00:00Z") + chrono::Duration::milliseconds(500), ..vector_claims() },
        ];
        for c in bad {
            assert!(matches!(mint_token(&recipient(), &c), Err(TokenError::Invalid)), "{c:?}");
        }
    }

    /// Neither a token nor the sender key or jti in claims is printed.
    #[test]
    fn debug_prints_no_token_material() {
        let token = mint_token(&recipient(), &vector_claims()).unwrap();
        assert_eq!(format!("{token:?}"), "Token(..)");
        let claims = format!("{:?}", vector_claims());
        assert!(!claims.contains("gTl3Dqh9"), "{claims}");
        assert!(!claims.contains("01JXAMPLE"), "{claims}");
    }

    /// Hostile input never panics the parsers (a stable stand-in until
    /// the fuzz target lands).
    #[test]
    fn hostile_input_never_panics() {
        let key = recipient().verifying_key();
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.=\r\n{}\":,[]";
        for _ in 0..2000 {
            let len = (next() % 600) as usize;
            let s: String = (0..len).map(|_| alphabet[(next() % alphabet.len() as u64) as usize] as char).collect();
            let _ = verify_token(&format!("v4.public.{s}"), &key);
            let _ = parse_claims(s.as_bytes());
            let bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = parse_claims(&bytes);
            let _ = strict_time(&s);
        }
    }

    /// `iat <= now < exp`.
    #[test]
    fn time_window() {
        let c = vector_claims();
        assert_eq!(check_time(&c, t("2026-06-09T23:59:59Z")), Err(TokenError::Expired));
        assert_eq!(check_time(&c, t("2026-06-10T00:00:00Z")), Ok(()));
        assert_eq!(check_time(&c, t("2026-07-09T23:59:59Z")), Ok(()));
        assert_eq!(check_time(&c, t("2026-07-10T00:00:00Z")), Err(TokenError::Expired));
    }
}
