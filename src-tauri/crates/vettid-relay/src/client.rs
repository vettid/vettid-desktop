//! The relay transport (RELAY-PROTOCOL §6, §7; VAULT-MESSAGING §8.6,
//! §13.6): register, deposit, long-poll collect, ack, and the claim fetch.
//!
//! - Every authenticated request is signed afresh for each attempt (§4.1).
//! - Retries: `429 rate_limited`, `5xx` and transport errors, with full
//!   jitter from 0.25 s × 2ⁿ capped at 30 s, honouring `retry_after`
//!   (§7.2, VM §8.6). Any other 4xx, and `429 quota_exceeded`, is never
//!   retried. A claim GET is never retried (§6.9).
//! - The User-Agent is `VettID-Desktop` on every request (VM §13.6).
//! - Ids that go into a URL path are checked for shape first.
//! - The base URL must be `https://`. Only tests, and builds with the
//!   non-default `devstack` feature (the local dev stack's plain-HTTP
//!   relay), may use `http://`.
//! - Every response body is read with a size cap, checked while reading,
//!   so a hostile or broken relay can't make the client buffer without
//!   bound.
//! - A deposit that fails in a way that may still have delivered it says
//!   so ([`RelayError::possibly_delivered`]): the caller must neither show
//!   it as sent nor assume it wasn't.
//! - Nothing here logs; errors and `Debug` carry no key, signature, token
//!   or payload material.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde::Deserialize;

use crate::auth::{self, SignedHeaders};
use crate::token::Token;

/// The User-Agent for every request (VM §13.6).
pub const USER_AGENT: &str = "VettID-Desktop";

/// The longest long-poll wait the relay honours (§6.3).
pub const MAX_WAIT_SECS: u64 = 25;

/// How much longer than its `wait` a long-poll may take before it is
/// treated as a transport failure.
const WAIT_MARGIN: Duration = Duration::from_secs(15);

/// The timeout for a request that doesn't wait.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The most bytes read from an error body, a claim, and any other small
/// answer (register, deposit, ack).
const MAX_ERROR_BODY: usize = 4096;
const MAX_CLAIM_BODY: usize = 1 << 20;
const MAX_SMALL_BODY: usize = 64 << 10;

/// The default `max_payload_bytes` (§6.2), and the most this client will
/// accept as a relay's advertised value when sizing a collect.
pub const DEFAULT_MAX_PAYLOAD: usize = 262_144;
const MAX_PAYLOAD_CEILING: usize = 8 << 20;

/// Room for one collected message's JSON besides its base64 payload.
const PER_MESSAGE_OVERHEAD: usize = 1024;

/// The largest collect answer for `max` messages of at most `payload`
/// bytes each: base64 grows by 4/3.
fn collect_limit(max: u32, payload: usize) -> usize {
    let b64 = payload.min(MAX_PAYLOAD_CEILING).div_ceil(3) * 4;
    (max as usize) * (b64 + PER_MESSAGE_OVERHEAD) + PER_MESSAGE_OVERHEAD
}

/// What went wrong. No variant carries key, token or payload material; a
/// relay `message` is kept only for diagnosis and is bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// The relay answered with an error body (§7.1).
    Relay {
        status: u16,
        code: String,
        retry_after: Option<u64>,
        quota: Option<String>,
    },
    /// The request didn't complete (network, TLS, timeout).
    Transport,
    /// A response that isn't what the protocol says.
    Malformed,
    /// A base URL or an id this client refuses to put in a request.
    Invalid,
}

impl RelayError {
    /// The relay's error code, if it answered with one.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Relay { code, .. } => Some(code),
            _ => None,
        }
    }

    /// Whether the request may be retried unchanged (§7.2): `429`
    /// `rate_limited`, `5xx`, or a transport failure. Never
    /// `quota_exceeded` or another 4xx.
    pub fn retryable(&self) -> bool {
        match self {
            Self::Relay { status, code, .. } => (*status == 429 && code != "quota_exceeded") || *status >= 500,
            Self::Transport => true,
            Self::Malformed | Self::Invalid => false,
        }
    }

    /// For a deposit: whether it may have been stored despite the error.
    /// A transport failure or a `5xx` may come after the relay stored it;
    /// `409 token_used` means a one-shot token was already spent, perhaps
    /// by an earlier attempt of this same deposit whose answer was lost
    /// (§5.6). The caller must not show such a deposit as sent, nor as
    /// failed: it is unconfirmed (the receiver dedupes a resend, VM §8.2).
    pub fn possibly_delivered(&self) -> bool {
        match self {
            Self::Relay { status, code, .. } => (*status == 409 && code == "token_used") || *status >= 500,
            Self::Transport => true,
            Self::Malformed => true,
            Self::Invalid => false,
        }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relay { status, code, .. } => write!(f, "relay: {status} {code}"),
            Self::Transport => f.write_str("relay: the request did not complete"),
            Self::Malformed => f.write_str("relay: malformed response"),
            Self::Invalid => f.write_str("relay: invalid request"),
        }
    }
}

impl std::error::Error for RelayError {}

#[derive(Deserialize)]
struct ErrorBody {
    code: Option<String>,
    retry_after: Option<u64>,
    quota: Option<String>,
}

/// The relay's advertised limits (§6.1). Members this client doesn't know
/// are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
pub struct Limits {
    pub max_payload_bytes: u64,
    pub message_ttl_seconds: u64,
    pub visibility_timeout_seconds: u64,
    pub max_token_lifetime_seconds: u64,
    pub open_token_max_lifetime_seconds: u64,
    pub max_claim_bytes: u64,
    pub claim_ttl_seconds: u64,
}

/// A registration (§6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub mailbox_id: String,
    pub limits: Limits,
    /// `201` (a new mailbox) rather than `200` (already registered).
    pub created: bool,
}

/// A collected message (§6.3). `Debug` leaves out the sender and payload.
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    pub msg_id: String,
    pub deposited_at: String,
    /// The base64 relay key that signed the deposit. The relay vouches only
    /// for that; the payload's own authentication decides who wrote it.
    pub sender: String,
    /// The deposit token's `jti` (0.4.0); may be absent.
    pub jti: Option<String>,
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("msg_id", &self.msg_id)
            .field("deposited_at", &self.deposited_at)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct WireMessage {
    msg_id: String,
    deposited_at: String,
    sender: String,
    jti: Option<String>,
    payload: String,
}

/// Whether `s` is a relay message id: a ULID, 26 Crockford base32
/// characters, upper case (§2).
pub fn valid_msg_id(s: &str) -> bool {
    s.len() == 26 && s.bytes().all(|c| c.is_ascii_digit() || (c.is_ascii_uppercase() && !b"ILOU".contains(&c)))
}

/// Whether `s` is a claim id: 26 lowercase base32 characters (§6.9), the
/// same shape as a mailbox id.
pub fn valid_claim_id(s: &str) -> bool {
    auth::valid_mailbox_id(s)
}

/// One request, before signing.
struct Request<'a> {
    method: reqwest::Method,
    path: String,
    query: Option<String>,
    body: Option<Vec<u8>>,
    token: Option<&'a Token>,
    timeout: Duration,
    /// The most bytes of a success body read.
    limit: usize,
}

/// A client for one relay key (the desktop's mailbox).
pub struct RelayClient {
    base_url: String,
    key: SigningKey,
    http: reqwest::Client,
    /// Attempts for retryable failures (at least 1).
    pub max_attempts: u32,
    /// The relay's `max_payload_bytes` (from [`Registration::limits`]),
    /// which sizes the cap on a collect answer. Values above 8 MiB are
    /// treated as 8 MiB.
    pub max_payload_bytes: usize,
}

impl std::fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayClient").field("base_url", &self.base_url).finish_non_exhaustive()
    }
}

impl RelayClient {
    /// A client for `base_url` (`https://…`, no trailing slash) signing as
    /// `key`.
    pub fn new(base_url: &str, key: SigningKey) -> Result<Self, RelayError> {
        let base_url = base_url.trim_end_matches('/').to_string();
        if !(base_url.starts_with("https://") || (http_allowed() && base_url.starts_with("http://"))) {
            return Err(RelayError::Invalid);
        }
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .https_only(!http_allowed())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| RelayError::Invalid)?;
        Ok(Self { base_url, key, http, max_attempts: 3, max_payload_bytes: DEFAULT_MAX_PAYLOAD })
    }

    /// This client's mailbox id (§3.2).
    pub fn mailbox_id(&self) -> String {
        auth::mailbox_id(&self.key.verifying_key())
    }

    /// `POST /v1/register` (§6.1). Idempotent: send it at every start.
    pub async fn register(&self) -> Result<Registration, RelayError> {
        #[derive(Deserialize)]
        struct Wire {
            mailbox_id: String,
            #[serde(default)]
            limits: Limits,
        }
        let body = serde_json::json!({ "pubkey": auth::encode_key(&self.key.verifying_key()) });
        let (status, bytes) = self
            .send(Request {
                method: reqwest::Method::POST,
                path: "/v1/register".into(),
                query: None,
                body: Some(body.to_string().into_bytes()),
                token: None,
                timeout: REQUEST_TIMEOUT,
                limit: MAX_SMALL_BODY,
            })
            .await?;
        let w: Wire = serde_json::from_slice(&bytes).map_err(|_| RelayError::Malformed)?;
        if w.mailbox_id != self.mailbox_id() {
            return Err(RelayError::Malformed);
        }
        Ok(Registration { mailbox_id: w.mailbox_id, limits: w.limits, created: status == 201 })
    }

    /// `POST /v1/mailbox/{mailbox_id}` (§6.2): deposit `payload` with
    /// `token` (a sender-bound or a one-shot open token, §5.6), returning
    /// the relay's `msg_id`. A retried deposit whose first attempt
    /// succeeded leaves a second message (the receiver dedupes, VM §8.2),
    /// or, with an open token, ends in `409 token_used`. On error, see
    /// [`RelayError::possibly_delivered`].
    pub async fn deposit(&self, mailbox_id: &str, token: &Token, payload: &[u8]) -> Result<String, RelayError> {
        if !auth::valid_mailbox_id(mailbox_id) {
            return Err(RelayError::Invalid);
        }
        #[derive(Deserialize)]
        struct Wire {
            msg_id: String,
        }
        let body = serde_json::json!({ "payload": STANDARD.encode(payload) });
        let (_, bytes) = self
            .send(Request {
                method: reqwest::Method::POST,
                path: format!("/v1/mailbox/{mailbox_id}"),
                query: None,
                body: Some(body.to_string().into_bytes()),
                token: Some(token),
                timeout: REQUEST_TIMEOUT,
                limit: MAX_SMALL_BODY,
            })
            .await?;
        let w: Wire = serde_json::from_slice(&bytes).map_err(|_| RelayError::Malformed)?;
        if !valid_msg_id(&w.msg_id) {
            return Err(RelayError::Malformed);
        }
        Ok(w.msg_id)
    }

    /// `GET /v1/mailbox?wait=…&max=…` (§6.3): long-poll this mailbox.
    /// `wait` is capped at 25 s. Re-issue at once after every answer,
    /// empty ones included.
    pub async fn collect(&self, wait_secs: u64, max: u32) -> Result<Vec<Message>, RelayError> {
        let wait = wait_secs.min(MAX_WAIT_SECS);
        let max = max.clamp(1, 100);
        #[derive(Deserialize)]
        struct Wire {
            messages: Vec<WireMessage>,
        }
        let (_, bytes) = self
            .send(Request {
                method: reqwest::Method::GET,
                path: "/v1/mailbox".into(),
                query: Some(format!("wait={wait}&max={max}")),
                body: None,
                token: None,
                timeout: Duration::from_secs(wait) + WAIT_MARGIN,
                limit: collect_limit(max, self.max_payload_bytes),
            })
            .await?;
        let w: Wire = serde_json::from_slice(&bytes).map_err(|_| RelayError::Malformed)?;
        w.messages
            .into_iter()
            .map(|m| {
                if !valid_msg_id(&m.msg_id) || auth::decode_key(&m.sender).is_none() {
                    return Err(RelayError::Malformed);
                }
                let payload = STANDARD.decode(&m.payload).map_err(|_| RelayError::Malformed)?;
                Ok(Message { msg_id: m.msg_id, deposited_at: m.deposited_at, sender: m.sender, jti: m.jti, payload })
            })
            .collect()
    }

    /// `DELETE /v1/mailbox/{msg_id}` (§6.5): ack. Always `204`.
    pub async fn ack(&self, msg_id: &str) -> Result<(), RelayError> {
        if !valid_msg_id(msg_id) {
            return Err(RelayError::Invalid);
        }
        self.send(Request {
            method: reqwest::Method::DELETE,
            path: format!("/v1/mailbox/{msg_id}"),
            query: None,
            body: None,
            token: None,
            timeout: REQUEST_TIMEOUT,
            limit: MAX_SMALL_BODY,
        })
        .await
        .map(|_| ())
    }

    /// `GET /v1/claim/{claim_id}` (§6.9): unsigned, and **never retried**:
    /// if the answer is lost the claim is gone, and the owner makes a new
    /// one.
    pub async fn get_claim(&self, claim_id: &str) -> Result<Vec<u8>, RelayError> {
        if !valid_claim_id(claim_id) {
            return Err(RelayError::Invalid);
        }
        let url = format!("{}/v1/claim/{claim_id}", self.base_url);
        let resp = self.http.get(url).timeout(REQUEST_TIMEOUT).send().await.map_err(|_| RelayError::Transport)?;
        let (_, bytes) = read_response(resp, MAX_CLAIM_BODY).await?;
        Ok(bytes)
    }

    /// Send `r`, retrying retryable failures (§7.2), each attempt signed
    /// afresh.
    async fn send(&self, r: Request<'_>) -> Result<(u16, Vec<u8>), RelayError> {
        let attempts = self.max_attempts.max(1);
        let mut last = RelayError::Transport;
        for attempt in 0..attempts {
            if attempt > 0 {
                tokio::time::sleep(retry_delay(attempt, &last)).await;
            }
            match self.once(&r).await {
                Ok(ok) => return Ok(ok),
                Err(e) if e.retryable() => last = e,
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }

    async fn once(&self, r: &Request<'_>) -> Result<(u16, Vec<u8>), RelayError> {
        let mut url = format!("{}{}", self.base_url, r.path);
        if let Some(q) = &r.query {
            url.push('?');
            url.push_str(q);
        }
        let body = r.body.clone().unwrap_or_default();
        let signed = SignedHeaders::new(&self.key, r.method.as_str(), &r.path, &body, chrono::Utc::now());
        let mut req = self.http.request(r.method.clone(), url).timeout(r.timeout);
        for (name, value) in signed.pairs() {
            req = req.header(name, value);
        }
        if let Some(token) = r.token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("VettID-Deposit {}", token.as_str()));
        }
        if r.body.is_some() {
            req = req.header(reqwest::header::CONTENT_TYPE, "application/json").body(body);
        }
        let resp = req.send().await.map_err(|_| RelayError::Transport)?;
        read_response(resp, r.limit).await
    }
}

/// Read at most `limit` bytes of a body, checking as it arrives: `None` if
/// it is longer (by its declared length, or while reading).
async fn read_capped(resp: &mut reqwest::Response, limit: usize) -> Result<Option<Vec<u8>>, RelayError> {
    if resp.content_length().is_some_and(|n| n > limit as u64) {
        return Ok(None);
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| RelayError::Transport)? {
        if out.len() + chunk.len() > limit {
            return Ok(None);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Some(out))
}

/// Read a response: a success's body (up to `limit` bytes, else
/// `Malformed`), or the error body of §7.1 (up to 4 KiB; a longer or
/// unparsable one gives the code `http_<status>`).
async fn read_response(mut resp: reqwest::Response, limit: usize) -> Result<(u16, Vec<u8>), RelayError> {
    let status = resp.status().as_u16();
    if status >= 400 {
        let body = read_capped(&mut resp, MAX_ERROR_BODY).await?.unwrap_or_default();
        let e: Option<ErrorBody> = serde_json::from_slice(&body).ok();
        let (code, retry_after, quota) = match e {
            Some(ErrorBody { code: Some(code), retry_after, quota }) if !code.is_empty() => (code, retry_after, quota),
            _ => (format!("http_{status}"), None, None),
        };
        return Err(RelayError::Relay { status, code, retry_after, quota });
    }
    let bytes = read_capped(&mut resp, limit).await?.ok_or(RelayError::Malformed)?;
    Ok((status, bytes))
}

/// The wait before retry `attempt` (1-based): `retry_after` if the relay
/// gave one (plus up to 250 ms), else full jitter over 0.25 s × 2ⁿ, capped
/// at 30 s (VM §8.6).
fn retry_delay(attempt: u32, last: &RelayError) -> Duration {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    if let RelayError::Relay { retry_after: Some(s), .. } = last {
        return Duration::from_secs(*s) + Duration::from_millis(rng.gen_range(0..250));
    }
    let cap_ms = (250u64 << attempt.min(7)).min(30_000);
    Duration::from_millis(rng.gen_range(0..=cap_ms))
}

/// Whether a plain-HTTP relay is allowed: tests, and the dev stack only.
const fn http_allowed() -> bool {
    cfg!(test) || cfg!(feature = "devstack")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::sender;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// What the stub relay saw of one request.
    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        target: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Seen {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
        }
    }

    /// A one-thread HTTP/1.1 stub: answers each connection with the next
    /// scripted `(status, body)` and records what it got.
    fn stub(responses: Vec<(u16, &str)>) -> (String, Arc<Mutex<Vec<Seen>>>) {
        let responses: Vec<(u16, String)> = responses.into_iter().map(|(s, b)| (s, b.to_string())).collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let Ok((mut stream, _)) = listener.accept() else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut parts = line.split_whitespace();
                let (method, target) = (parts.next().unwrap().to_string(), parts.next().unwrap().to_string());
                let mut headers = Vec::new();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    let h = h.trim_end();
                    if h.is_empty() {
                        break;
                    }
                    let (n, v) = h.split_once(':').unwrap();
                    if n.eq_ignore_ascii_case("content-length") {
                        len = v.trim().parse().unwrap();
                    }
                    headers.push((n.to_string(), v.trim().to_string()));
                }
                let mut req_body = vec![0u8; len];
                reader.read_exact(&mut req_body).unwrap();
                log.lock().unwrap().push(Seen { method, target, headers, body: req_body });
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).unwrap();
            }
        });
        (format!("http://{addr}"), seen)
    }

    fn client(base: &str) -> RelayClient {
        let mut c = RelayClient::new(base, sender()).unwrap();
        c.max_attempts = 3;
        c
    }

    const MSG_ID: &str = "01JXAMPE00000000000000000A";

    /// Register sends the key it signs with, and checks the mailbox id.
    #[tokio::test]
    async fn register_signs_and_checks_the_mailbox() {
        let mailbox = auth::mailbox_id(&sender().verifying_key());
        let body: &'static str = Box::leak(
            format!(r#"{{"mailbox_id":"{mailbox}","limits":{{"max_payload_bytes":262144,"message_ttl_seconds":1209600,"visibility_timeout_seconds":60,"max_token_lifetime_seconds":34560000,"open_token_max_lifetime_seconds":604800,"max_claim_bytes":16384,"claim_ttl_seconds":604800,"max_blob_bytes":8388608,"future":1}}}}"#)
                .into_boxed_str(),
        );
        let (base, seen) = stub(vec![(201, body)]);
        let reg = client(&base).register().await.unwrap();
        assert!(reg.created);
        assert_eq!(reg.limits.max_payload_bytes, 262_144);
        let s = seen.lock().unwrap()[0].clone();
        assert_eq!((s.method.as_str(), s.target.as_str()), ("POST", "/v1/register"));
        assert_eq!(s.header("user-agent"), Some(USER_AGENT));
        let key = auth::encode_key(&sender().verifying_key());
        assert_eq!(s.header("x-vettid-key"), Some(key.as_str()));
        assert!(String::from_utf8(s.body.clone()).unwrap().contains(&key));
        // The signature is over this exact request.
        let ts = s.header("x-vettid-timestamp").unwrap();
        let want = auth::sign_request(&sender(), "POST", "/v1/register", ts, &auth::body_hash(&s.body));
        assert_eq!(s.header("x-vettid-sig"), Some(STANDARD.encode(want).as_str()));
    }

    /// A deposit carries the token and the base64 payload, and returns the
    /// msg_id.
    #[tokio::test]
    async fn deposit_sends_token_and_payload() {
        let (base, seen) = stub(vec![(201, r#"{"msg_id":"01JXAMPE00000000000000000A"}"#)]);
        let token = Token::from_received("v4.public.test".into());
        let id = client(&base).deposit("gr2q7gf5lh6pzfdnurnkvputhp", &token, b"ciphertext").await.unwrap();
        assert_eq!(id, MSG_ID);
        let s = seen.lock().unwrap()[0].clone();
        assert_eq!(s.target, "/v1/mailbox/gr2q7gf5lh6pzfdnurnkvputhp");
        assert_eq!(s.header("authorization"), Some("VettID-Deposit v4.public.test"));
        assert_eq!(s.header("content-type"), Some("application/json"));
        assert_eq!(String::from_utf8(s.body).unwrap(), format!(r#"{{"payload":"{}"}}"#, STANDARD.encode(b"ciphertext")));
    }

    /// Collect sends wait and max (capped), signs only the path, and decodes
    /// messages; Debug shows no payload.
    #[tokio::test]
    async fn collect_long_polls_and_decodes() {
        let key = auth::encode_key(&sender().verifying_key());
        let body: &'static str = Box::leak(
            format!(r#"{{"messages":[{{"msg_id":"{MSG_ID}","deposited_at":"2026-06-10T12:00:00Z","sender":"{key}","jti":"j1","payload":"{}"}}]}}"#, STANDARD.encode(b"hello"))
                .into_boxed_str(),
        );
        let (base, seen) = stub(vec![(200, body)]);
        let msgs = client(&base).collect(99, 500).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, b"hello");
        assert_eq!(msgs[0].jti.as_deref(), Some("j1"));
        assert!(!format!("{:?}", msgs[0]).contains("hello"));
        let s = seen.lock().unwrap()[0].clone();
        assert_eq!(s.target, "/v1/mailbox?wait=25&max=100");
        let ts = s.header("x-vettid-timestamp").unwrap();
        let want = auth::sign_request(&sender(), "GET", "/v1/mailbox", ts, &auth::body_hash(b""));
        assert_eq!(s.header("x-vettid-sig"), Some(STANDARD.encode(want).as_str()), "the query isn't signed");
    }

    /// 5xx and 429 rate_limited are retried, each attempt freshly signed;
    /// retry_after is honoured.
    #[tokio::test]
    async fn retryable_failures_are_retried_and_resigned() {
        let (base, seen) = stub(vec![
            (503, r#"{"code":"internal","message":"x"}"#),
            (429, r#"{"code":"rate_limited","message":"x","retry_after":0}"#),
            (204, ""),
        ]);
        client(&base).ack(MSG_ID).await.unwrap();
        let s = seen.lock().unwrap();
        assert_eq!(s.len(), 3);
        let sigs: Vec<_> = s.iter().map(|x| x.header("x-vettid-sig").unwrap().to_string()).collect();
        assert!(sigs[0] != sigs[1] && sigs[1] != sigs[2], "each attempt signed afresh");
    }

    /// quota_exceeded and other 4xx are never retried; the code and quota
    /// come back.
    #[tokio::test]
    async fn quota_and_other_4xx_are_not_retried() {
        let (base, seen) = stub(vec![(429, r#"{"code":"quota_exceeded","message":"x","quota":"token"}"#)]);
        let token = Token::from_received("v4.public.t".into());
        let err = client(&base).deposit("gr2q7gf5lh6pzfdnurnkvputhp", &token, b"x").await.unwrap_err();
        assert_eq!(err, RelayError::Relay { status: 429, code: "quota_exceeded".into(), retry_after: None, quota: Some("token".into()) });
        assert!(!err.retryable());
        assert_eq!(seen.lock().unwrap().len(), 1);

        let (base, seen) = stub(vec![(404, r#"{"code":"mailbox_unknown","message":"x"}"#)]);
        let err = client(&base).collect(0, 1).await.unwrap_err();
        assert_eq!(err.code(), Some("mailbox_unknown"));
        assert_eq!(seen.lock().unwrap().len(), 1);

        let (base, _) = stub(vec![(400, "not json")]);
        assert_eq!(client(&base).collect(0, 1).await.unwrap_err().code(), Some("http_400"));
    }

    /// A claim GET is unsigned and never retried, even on 5xx.
    #[tokio::test]
    async fn claim_get_is_unsigned_and_not_retried() {
        let (base, seen) = stub(vec![(503, r#"{"code":"internal"}"#), (200, "bundle")]);
        let err = client(&base).get_claim("gr2q7gf5lh6pzfdnurnkvputhp").await.unwrap_err();
        assert_eq!(err.code(), Some("internal"));
        let s = seen.lock().unwrap();
        assert_eq!(s.len(), 1, "not retried");
        assert_eq!(s[0].header("x-vettid-sig"), None, "unsigned");
        assert_eq!(s[0].header("user-agent"), Some(USER_AGENT));
    }

    /// Ids are checked before they go into a path; a non-https base is
    /// refused outside tests and the dev stack.
    #[tokio::test]
    async fn ids_and_base_urls_are_checked() {
        let c = client("http://127.0.0.1:1");
        let token = Token::from_received("v4.public.t".into());
        for bad in ["../register", "GR2Q7GF5LH6PZFDNURNKVPUTHP", "gr2q7gf5lh6pzfdnurnkvputhp/x"] {
            assert_eq!(c.deposit(bad, &token, b"x").await.unwrap_err(), RelayError::Invalid, "{bad}");
            assert_eq!(c.get_claim(bad).await.unwrap_err(), RelayError::Invalid, "{bad}");
        }
        assert_eq!(c.ack("01jxample0000000000000000a").await.unwrap_err(), RelayError::Invalid);
        assert_eq!(c.ack("01JXAMPLE000000000000000IL").await.unwrap_err(), RelayError::Invalid);
        assert!(RelayClient::new("ftp://relay.example", sender()).is_err());
        assert!(RelayClient::new("https://relay.example/", sender()).is_ok());
    }

    /// A malformed answer is Malformed, not a crash: a bad msg_id, sender
    /// or payload.
    #[tokio::test]
    async fn malformed_answers_are_refused() {
        for body in [
            r#"{"messages":[{"msg_id":"x","deposited_at":"t","sender":"gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=","payload":""}]}"#,
            r#"{"messages":[{"msg_id":"01JXAMPE00000000000000000A","deposited_at":"t","sender":"nope","payload":""}]}"#,
            r#"{"messages":[{"msg_id":"01JXAMPE00000000000000000A","deposited_at":"t","sender":"gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=","payload":"%%"}]}"#,
            r#"{"nope":1}"#,
        ] {
            let (base, _) = stub(vec![(200, body)]);
            assert_eq!(client(&base).collect(0, 1).await.unwrap_err(), RelayError::Malformed, "{body}");
        }
    }

    /// A one-shot token's retry that finds it spent is unconfirmed, not a
    /// failure: the first attempt may have landed.
    #[tokio::test]
    async fn a_spent_open_token_is_possibly_delivered() {
        let (base, seen) = stub(vec![
            (503, r#"{"code":"internal","message":"x"}"#),
            (409, r#"{"code":"token_used","message":"x"}"#),
        ]);
        let token = Token::from_received("v4.public.open".into());
        let err = client(&base).deposit("gr2q7gf5lh6pzfdnurnkvputhp", &token, b"x").await.unwrap_err();
        assert_eq!(err.code(), Some("token_used"));
        assert!(err.possibly_delivered() && !err.retryable());
        assert_eq!(seen.lock().unwrap().len(), 2);
        assert!(RelayError::Transport.possibly_delivered());
        let refused = RelayError::Relay { status: 401, code: "token_invalid".into(), retry_after: None, quota: None };
        assert!(!refused.possibly_delivered(), "a refusal before storing is a plain failure");
        assert!(!RelayError::Invalid.possibly_delivered(), "never sent");
    }

    /// Bodies over their cap are refused, not buffered: a claim over 1 MiB,
    /// a collect over what `max` messages can need, an error over 4 KiB.
    #[tokio::test]
    async fn oversized_answers_are_refused() {
        let big = "a".repeat(MAX_CLAIM_BODY + 1);
        let (base, _) = stub(vec![(200, big.as_str())]);
        assert_eq!(client(&base).get_claim("gr2q7gf5lh6pzfdnurnkvputhp").await.unwrap_err(), RelayError::Malformed);

        let body = format!(r#"{{"messages":[],"pad":"{}"}}"#, "x".repeat(collect_limit(1, 30)));
        let (base, _) = stub(vec![(200, body.as_str())]);
        let mut c = client(&base);
        c.max_payload_bytes = 30;
        assert_eq!(c.collect(0, 1).await.unwrap_err(), RelayError::Malformed);

        let long_err = format!(r#"{{"code":"bad_request","message":"{}"}}"#, "m".repeat(MAX_ERROR_BODY));
        let (base, _) = stub(vec![(400, long_err.as_str())]);
        assert_eq!(client(&base).collect(0, 1).await.unwrap_err().code(), Some("http_400"));
    }

    /// A full collect of the largest messages fits its cap.
    #[test]
    fn collect_limit_fits_a_full_answer() {
        let b64 = DEFAULT_MAX_PAYLOAD.div_ceil(3) * 4;
        assert!(collect_limit(100, DEFAULT_MAX_PAYLOAD) >= 100 * (b64 + 300));
        assert_eq!(collect_limit(1, usize::MAX), collect_limit(1, MAX_PAYLOAD_CEILING));
    }

    /// The retry delay: full jitter within 0.25 s × 2ⁿ, capped at 30 s; or
    /// retry_after.
    #[test]
    fn retry_delays_follow_section_8_6() {
        for attempt in 1..12 {
            let d = retry_delay(attempt, &RelayError::Transport);
            assert!(d <= Duration::from_millis((250u64 << attempt.min(7)).min(30_000)), "{attempt}: {d:?}");
        }
        let after = RelayError::Relay { status: 429, code: "rate_limited".into(), retry_after: Some(3), quota: None };
        let d = retry_delay(1, &after);
        assert!(d >= Duration::from_secs(3) && d < Duration::from_millis(3250));
    }
}
