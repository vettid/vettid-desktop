//! Deposit tokens: PASETO v4.public (RELAY-PROTOCOL §5).
//!
//! Implemented directly on Ed25519, as the relay's Go `relayauth` does.
//! Footer and implicit assertion are empty in protocol v1 (§5.1); a token
//! carrying a footer is refused.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
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

/// PASETO Pre-Authentication Encoding.
fn pae(pieces: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + pieces.iter().map(|p| 8 + p.len()).sum::<usize>());
    out.extend_from_slice(&((pieces.len() as u64) & !(1 << 63)).to_le_bytes());
    for p in pieces {
        out.extend_from_slice(&((p.len() as u64) & !(1 << 63)).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// A v4.public token over the exact message bytes `m` (empty footer and
/// implicit assertion). Ed25519 is deterministic: the same key and bytes
/// always give the same token.
pub fn sign_token(key: &SigningKey, m: &[u8]) -> String {
    let sig = key.sign(&pae(&[HEADER.as_bytes(), m, b"", b""]));
    let mut body = Vec::with_capacity(m.len() + 64);
    body.extend_from_slice(m);
    body.extend_from_slice(&sig.to_bytes());
    format!("{HEADER}{}", URL_SAFE_NO_PAD.encode(body))
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
    let raw = URL_SAFE_NO_PAD.decode(rest).map_err(|_| TokenError::Invalid)?;
    if raw.len() < 64 {
        return Err(TokenError::Invalid);
    }
    let (m, sig) = raw.split_at(raw.len() - 64);
    let sig = Signature::from_slice(sig).map_err(|_| TokenError::Invalid)?;
    issuer
        .verify_strict(&pae(&[HEADER.as_bytes(), m, b"", b""]), &sig)
        .map_err(|_| TokenError::Invalid)?;
    Ok(m.to_vec())
}

/// The optional per-token deposit cap (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Quota {
    pub msgs: Option<i64>,
    pub bytes: Option<i64>,
}

/// Deposit-token claims (§5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// jti, scope[, quota][, owner_device]), timestamps in whole seconds.
    pub fn to_json(&self) -> String {
        let s = |v: &str| serde_json::to_string(v).expect("a string always serializes");
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

/// Sign `claims` as a deposit token (§5).
pub fn mint_token(key: &SigningKey, claims: &Claims) -> String {
    sign_token(key, claims.to_json().as_bytes())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
/// claim is refused.
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
    let time = |v: &str| DateTime::parse_from_rfc3339(v).map(|t| t.with_timezone(&Utc)).map_err(|_| TokenError::Invalid);
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
        assert_eq!(sign_token(&recipient(), VECTOR_CLAIMS.as_bytes()), VECTOR_TOKEN);
        assert_eq!(vector_claims().to_json(), VECTOR_CLAIMS);
        assert_eq!(mint_token(&recipient(), &vector_claims()), VECTOR_TOKEN);
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
        assert_eq!(parse_token(&mint_token(&recipient(), &c), &recipient().verifying_key()).unwrap(), c);

        let mut open = vector_claims();
        open.scope = SCOPE_DEPOSIT_OPEN.into();
        open.sub = OPEN_SUB.into();
        let parsed = parse_token(&mint_token(&recipient(), &open), &recipient().verifying_key()).unwrap();
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
            &format!("{VECTOR_TOKEN}="),        // padding
            &VECTOR_TOKEN.replacen('_', "/", 1), // standard alphabet
            &format!("{}\n{}", &VECTOR_TOKEN[..20], &VECTOR_TOKEN[20..]),
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
        ] {
            assert_eq!(parse_claims(bad.as_bytes()), Err(TokenError::Invalid), "{what}");
        }
        assert_eq!(parse_claims(&[0xff, 0xfe]), Err(TokenError::Invalid), "not UTF-8");
        let unknown = base.replacen('}', r#","extra":1}"#, 1);
        assert!(parse_claims(unknown.as_bytes()).is_ok(), "unknown claims are ignored");
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
