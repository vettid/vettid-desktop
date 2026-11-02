//! Mailbox ids (RELAY-PROTOCOL §3.2) and signed requests (§4.1).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Signed-request header names (§4.1).
pub const HEADER_KEY: &str = "X-VettID-Key";
pub const HEADER_TIMESTAMP: &str = "X-VettID-Timestamp";
pub const HEADER_SIG: &str = "X-VettID-Sig";

/// The mailbox id of a raw 32-byte Ed25519 public key (§3.2):
/// `lowercase(base32(SHA-256(pubkey)))` without padding, truncated to 26
/// characters.
pub fn mailbox_id(pubkey: &VerifyingKey) -> String {
    let hash = Sha256::digest(pubkey.as_bytes());
    let mut id = data_encoding::BASE32_NOPAD.encode(&hash).to_ascii_lowercase();
    id.truncate(26);
    id
}

/// Whether `s` has the shape of a mailbox id: 26 characters of `a-z2-7`.
pub fn valid_mailbox_id(s: &str) -> bool {
    s.len() == 26 && s.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
}

/// The canonical (standard, padded) base64 of a public key.
pub fn encode_key(pubkey: &VerifyingKey) -> String {
    STANDARD.encode(pubkey.as_bytes())
}

/// Strictly decode standard padded base64: canonical padding and trailing
/// bits, and no whitespace, so every value has exactly one spelling.
pub fn decode_std(s: &str) -> Option<Vec<u8>> {
    // The engine already refuses whitespace and non-canonical input; the
    // explicit check documents the rule.
    if s.contains(['\r', '\n']) {
        return None;
    }
    STANDARD.decode(s).ok()
}

/// Strictly decode a base64 raw Ed25519 public key.
pub fn decode_key(s: &str) -> Option<VerifyingKey> {
    if s.len() != 44 {
        return None;
    }
    let bytes: [u8; 32] = decode_std(s)?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// SHA-256 of the raw request body (empty for bodiless requests).
pub fn body_hash(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

/// The canonical request string (§4.1):
/// `METHOD "\n" PATH "\n" timestamp "\n" lowercase-hex(SHA-256(body))`.
/// `path` includes the `/v1` prefix and excludes the query string;
/// `timestamp` is used verbatim, exactly as sent in the header.
pub fn canonical(method: &str, path: &str, timestamp: &str, body_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(method.len() + path.len() + timestamp.len() + 3 + 64);
    out.extend_from_slice(method.to_ascii_uppercase().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(path.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(timestamp.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(hex::encode(body_hash).as_bytes());
    out
}

/// SHA-256 of [`canonical`]: the value that is Ed25519-signed.
pub fn digest(method: &str, path: &str, timestamp: &str, body_hash: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(canonical(method, path, timestamp, body_hash)).into()
}

/// Sign a request (client side).
pub fn sign_request(key: &SigningKey, method: &str, path: &str, timestamp: &str, body_hash: &[u8; 32]) -> [u8; 64] {
    key.sign(&digest(method, path, timestamp, body_hash)).to_bytes()
}

/// A request timestamp: RFC 3339 UTC with millisecond precision. The
/// canonical string omits the query and Ed25519 is deterministic, so a
/// whole-second timestamp would make a long-poll re-issued within the same
/// second a replay (§4.1).
pub fn timestamp(now: chrono::DateTime<chrono::Utc>) -> String {
    now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// The three signed-request headers for one request (§4.1). Sign again for
/// every attempt: the relay keeps a replay cache.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    pub key: String,
    pub timestamp: String,
    pub sig: String,
}

impl std::fmt::Debug for SignedHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keys and signatures are never printed (VM §13.6).
        f.write_str("SignedHeaders(..)")
    }
}

impl SignedHeaders {
    /// Headers for `method path` with `body`, signed at `now`.
    pub fn new(key: &SigningKey, method: &str, path: &str, body: &[u8], now: chrono::DateTime<chrono::Utc>) -> Self {
        let ts = timestamp(now);
        let sig = sign_request(key, method, path, &ts, &body_hash(body));
        Self { key: encode_key(&key.verifying_key()), timestamp: ts, sig: STANDARD.encode(sig) }
    }

    /// As `(name, value)` pairs.
    pub fn pairs(&self) -> [(&'static str, &str); 3] {
        [(HEADER_KEY, &self.key), (HEADER_TIMESTAMP, &self.timestamp), (HEADER_SIG, &self.sig)]
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// RELAY-PROTOCOL §9 test keys: seeds of all-0x01 and all-0x02 bytes.
    pub(crate) fn recipient() -> SigningKey {
        SigningKey::from_bytes(&[0x01; 32])
    }
    pub(crate) fn sender() -> SigningKey {
        SigningKey::from_bytes(&[0x02; 32])
    }

    /// §9.1: seeds, public keys and mailbox ids.
    #[test]
    fn vector_9_1_keys_and_mailbox_ids() {
        assert_eq!(STANDARD.encode([0x01; 32]), "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=");
        assert_eq!(encode_key(&recipient().verifying_key()), "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=");
        assert_eq!(mailbox_id(&recipient().verifying_key()), "gr2q7gf5lh6pzfdnurnkvputhp");
        assert_eq!(encode_key(&sender().verifying_key()), "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=");
        assert_eq!(mailbox_id(&sender().verifying_key()), "ni4ahvpqlgicuhdnv66jxjdssi");
        assert!(valid_mailbox_id("gr2q7gf5lh6pzfdnurnkvputhp"));
    }

    /// §9.3: a signed deposit request, byte for byte.
    #[test]
    fn vector_9_3_signed_deposit_request() {
        let path = "/v1/mailbox/gr2q7gf5lh6pzfdnurnkvputhp";
        let body = br#"{"payload":"b3BhcXVlLWNpcGhlcnRleHQtYnl0ZXM="}"#;
        let ts = "2026-06-10T12:00:00Z";
        let bh = body_hash(body);
        assert_eq!(hex::encode(bh), "0237514b3df17b219036f1b8fa6ca70d4ca597eb630933841707380055d7e12a");
        assert_eq!(
            canonical("POST", path, ts, &bh),
            b"POST\n/v1/mailbox/gr2q7gf5lh6pzfdnurnkvputhp\n2026-06-10T12:00:00Z\n0237514b3df17b219036f1b8fa6ca70d4ca597eb630933841707380055d7e12a"
        );
        assert_eq!(STANDARD.encode(digest("POST", path, ts, &bh)), "l+mc5XMNElCBLC49xJH4Lc8LHEAlAK1HunqaS+LZ33k=");
        assert_eq!(
            STANDARD.encode(sign_request(&sender(), "post", path, ts, &bh)),
            "pOZT7Pb981+3K4wWv6Zryb43miSLBfKdCZ4Wc/qNzQyxFtOPrsSSkK1Gj5mF+Zb3z3yC4Bi7AyjIyVkeN+nsDA==",
            "the method is uppercased"
        );
    }

    /// §4.1: the empty body hashes as given, and headers carry millisecond
    /// timestamps, so two requests within a second sign differently.
    #[test]
    fn headers_use_millisecond_timestamps() {
        assert_eq!(hex::encode(body_hash(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let t0 = chrono::DateTime::parse_from_rfc3339("2026-06-10T12:00:00Z").unwrap().with_timezone(&chrono::Utc);
        let t1 = t0 + chrono::Duration::milliseconds(1);
        let a = SignedHeaders::new(&sender(), "GET", "/v1/mailbox", b"", t0);
        let b = SignedHeaders::new(&sender(), "GET", "/v1/mailbox", b"", t1);
        assert_eq!(a.timestamp, "2026-06-10T12:00:00.000Z");
        assert_eq!(b.timestamp, "2026-06-10T12:00:00.001Z");
        assert_ne!(a.sig, b.sig);
        assert_eq!(a.key, encode_key(&sender().verifying_key()));
        assert_eq!(format!("{a:?}"), "SignedHeaders(..)", "nothing secret or signed is printed");
    }

    /// Keys decode in exactly one spelling.
    #[test]
    fn keys_decode_strictly() {
        let good = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=";
        assert_eq!(decode_key(good), Some(sender().verifying_key()));
        for bad in [
            "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q",   // no padding
            "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",  // url alphabet
            "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5R=",  // non-canonical trailing bits
            "gTl3Dqh9F19Wo1Rmw0x+zMuN\nipG07jeiXfYPW4/Js5Q=", // embedded newline
            "",
        ] {
            assert_eq!(decode_key(bad), None, "{bad:?}");
        }
        for bad in ["GR2Q7GF5LH6PZFDNURNKVPUTHP", "gr2q7gf5lh6pzfdnurnkvputh", "gr2q7gf5lh6pzfdnurnkvputh1"] {
            assert!(!valid_mailbox_id(bad), "{bad}");
        }
    }
}
