//! The relay transport (RELAY-PROTOCOL §6, §7; VAULT-MESSAGING §8.6,
//! §13.6): register, deposit, long-poll collect, ack, and the claim fetch.
//!
//! - Every authenticated request is signed afresh for each attempt (§4.1).
//! - Retries: `429 rate_limited`, `5xx` and transport errors, with full
//!   jitter from 0.25 s × 2ⁿ capped at 30 s, honouring `retry_after` up to
//!   60 s (§7.2, VM §8.6); a longer `retry_after` ends the attempts. Any
//!   other 4xx, `429 quota_exceeded` and a `429` without a readable code,
//!   is never retried. A claim GET is never retried (§6.9).
//! - Each call accepts only the success status the protocol gives it;
//!   any other (a 3xx included: redirects are off) is `Malformed`.
//! - The User-Agent is `VettID-Desktop` on every request (VM §13.6).
//! - Ids that go into a URL path are checked for shape first.
//! - The base URL must be `https://`. Only this crate's own tests may use
//!   `http://`. The local dev stack's relay is reached over TLS, through
//!   [`RelayClient::new_dev`] (development builds only, `dev-relay`).
//! - Every response body is read with a size cap, checked while reading,
//!   so a hostile or broken relay can't make the client buffer without
//!   bound.
//! - A deposit that fails in a way that may still have delivered it, in
//!   any of its attempts, says so ([`DepositError::possibly_delivered`]):
//!   the caller must neither show it as sent nor assume it wasn't.
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

/// The most one call may take, all attempts and waits included, except a
/// collect (its wait plus [`WAIT_MARGIN`]): VM §8.1's 30 s for an
/// interactive request. A retry that wouldn't fit is not started.
const CALL_DEADLINE: Duration = Duration::from_secs(30);

/// The most bytes read from an error body, a claim, and any other small
/// answer (register, deposit, ack).
const MAX_ERROR_BODY: usize = 4096;
const MAX_CLAIM_BODY: usize = 1 << 20;
const MAX_SMALL_BODY: usize = 64 << 10;

/// The default `max_payload_bytes` (§6.2): the least a collect is sized
/// for, whatever the relay advertised (a missing or zero limit included).
pub const DEFAULT_MAX_PAYLOAD: usize = 262_144;
const MAX_PAYLOAD_CEILING: usize = 8 << 20;

/// Room for one collected message's JSON besides its base64 payload.
const PER_MESSAGE_OVERHEAD: usize = 1024;

/// The most bytes one collect answer may take, whatever the relay
/// advertises: `max` is lowered to fit.
const MAX_COLLECT_BODY: usize = 64 << 20;

/// The longest `retry_after` waited out within one call; a longer one
/// ends the attempts and is returned to the caller.
const MAX_RETRY_AFTER_SECS: u64 = 60;

/// One collected message's largest size: base64 grows by 4/3. The
/// payload limit counts as at least the default, so a relay that leaves it
/// out, or lowers it after storing larger messages, can't wedge collect.
fn per_message(payload: usize) -> usize {
    payload.clamp(DEFAULT_MAX_PAYLOAD, MAX_PAYLOAD_CEILING).div_ceil(3) * 4 + PER_MESSAGE_OVERHEAD
}

/// `max` (1..=100), lowered so `max` messages fit [`MAX_COLLECT_BODY`].
fn collect_max(max: u32, payload: usize) -> u32 {
    let fit = (MAX_COLLECT_BODY - PER_MESSAGE_OVERHEAD) / per_message(payload);
    max.clamp(1, 100).min(fit.max(1) as u32)
}

/// The largest collect answer for `max` messages of at most `payload`
/// bytes each.
fn collect_limit(max: u32, payload: usize) -> usize {
    (max as usize) * per_message(payload) + PER_MESSAGE_OVERHEAD
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
    /// The relay couldn't be reached (DNS, TCP or the TLS handshake):
    /// nothing was sent.
    Connect,
    /// The request was sent, or may have been, but no answer came (the
    /// connection broke, or a timeout).
    Transport,
    /// A response that isn't what the protocol says. Never retried: a
    /// success status counts as the answer, even if its body is broken.
    Malformed,
    /// A success answer larger than this client reads. For a collect, the
    /// relay's limits may have risen since [`RelayClient::register`]:
    /// register again and set [`RelayClient::max_payload_bytes`], or
    /// collect with `max = 1`.
    TooLarge,
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
    /// `quota_exceeded`, a `429` whose code couldn't be read, or another
    /// 4xx.
    pub fn retryable(&self) -> bool {
        match self {
            Self::Relay { status, code, .. } => (*status == 429 && code == "rate_limited") || *status >= 500,
            Self::Connect | Self::Transport => true,
            Self::Malformed | Self::TooLarge | Self::Invalid => false,
        }
    }

    /// Whether this one attempt may have reached the relay and been stored
    /// before it failed: a transport failure, a `5xx`, or a success answer
    /// that isn't the protocol's. Not a connection that never opened.
    fn may_have_stored(&self) -> bool {
        match self {
            Self::Relay { status, .. } => *status >= 500,
            Self::Transport | Self::Malformed | Self::TooLarge => true,
            Self::Connect | Self::Invalid => false,
        }
    }

    /// Classify a `reqwest` failure: a request that couldn't be built is
    /// ours (`Invalid`), a connection that never opened sent nothing
    /// (`Connect`), anything else may have reached the relay.
    fn from_reqwest(e: &reqwest::Error) -> Self {
        if e.is_builder() {
            Self::Invalid
        } else if e.is_connect() {
            Self::Connect
        } else {
            Self::Transport
        }
    }
}

/// A failed deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositError {
    /// The last attempt's error.
    pub error: RelayError,
    /// Whether the message may have been stored anyway: some attempt
    /// failed after the request may have reached the relay (a transport
    /// failure, a `5xx`, a malformed answer), or the last one found its
    /// one-shot token spent (`409 token_used`, §5.6), perhaps by an earlier
    /// attempt whose answer was lost. The caller must show such a deposit
    /// as unconfirmed, neither sent nor failed (the receiver dedupes a
    /// resend, VM §8.2). `false` only when every attempt was refused.
    pub possibly_delivered: bool,
}

impl std::fmt::Display for DepositError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.possibly_delivered {
            write!(f, "{} (the message may have been delivered)", self.error)
        } else {
            self.error.fmt(f)
        }
    }
}

impl std::error::Error for DepositError {}

/// A call that failed: the last error, and whether any attempt may have
/// been stored.
struct Failure {
    error: RelayError,
    may_have_stored: bool,
}

impl From<Failure> for RelayError {
    fn from(f: Failure) -> Self {
        f.error
    }
}

impl From<RelayError> for Failure {
    fn from(error: RelayError) -> Self {
        Failure { may_have_stored: error.may_have_stored(), error }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relay { status, code, .. } => write!(f, "relay: {status} {code}"),
            Self::Connect => f.write_str("relay: could not connect"),
            Self::Transport => f.write_str("relay: the request did not complete"),
            Self::Malformed => f.write_str("relay: malformed response"),
            Self::TooLarge => f.write_str("relay: response too large"),
            Self::Invalid => f.write_str("relay: invalid request"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Whether a relay error `code` or `quota` is one this client passes on:
/// `[a-z_]{1,32}`, so relay text can't inject into a caller's log.
fn valid_code(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
}

/// The §7.1 error body, read leniently: a member of the wrong type is
/// ignored rather than losing the whole body (so a `quota_exceeded` with a
/// fractional `retry_after` still reads as `quota_exceeded`).
fn parse_error(status: u16, body: &[u8]) -> RelayError {
    let v: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let field = |k: &str| v.as_ref().and_then(|v| v.get(k));
    let code = field("code")
        .and_then(|c| c.as_str())
        .filter(|c| valid_code(c))
        .map_or_else(|| format!("http_{status}"), str::to_string);
    let retry_after = field("retry_after").and_then(|r| {
        r.as_u64().or_else(|| r.as_f64().filter(|f| f.is_finite() && *f >= 0.0).map(|f| f.ceil() as u64))
    });
    let quota = field("quota").and_then(|q| q.as_str()).filter(|q| valid_code(q)).map(str::to_string);
    RelayError::Relay { status, code, retry_after, quota }
}

/// The relay's advertised limits (§6.1). Members this client doesn't know
/// are ignored; a missing one is 0 (unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(default)]
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
/// characters, upper case, the first at most `7` (128 bits) (§2).
pub fn valid_msg_id(s: &str) -> bool {
    s.len() == 26
        && s.as_bytes()[0] <= b'7'
        && s.bytes().all(|c| c.is_ascii_digit() || (c.is_ascii_uppercase() && !b"ILOU".contains(&c)))
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
    /// The success statuses this call accepts.
    expect: &'static [u16],
    /// The most the whole call may take, retries included.
    deadline: Duration,
}

/// A client for one relay key (the desktop's mailbox).
pub struct RelayClient {
    base_url: String,
    key: SigningKey,
    http: reqwest::Client,
    /// Attempts for retryable failures (at least 1).
    pub max_attempts: u32,
    /// The relay's `max_payload_bytes` (from [`Registration::limits`]),
    /// which sizes the cap on a collect answer. Values below the default
    /// (0 included) count as the default, values above 8 MiB as 8 MiB.
    pub max_payload_bytes: usize,
}

impl std::fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayClient").field("base_url", &self.base_url).finish_non_exhaustive()
    }
}

impl RelayClient {
    /// A client for `base_url` (`https://host[:port]`, an optional `/` and
    /// nothing else) signing as `key`.
    pub fn new(base_url: &str, key: SigningKey) -> Result<Self, RelayError> {
        let base_url = check_base_url(base_url, http_allowed())?;
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .https_only(!http_allowed())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| RelayError::Invalid)?;
        Ok(Self { base_url, key, http, max_attempts: 3, max_payload_bytes: DEFAULT_MAX_PAYLOAD })
    }

    /// **DEVELOPMENT ONLY** (`dev-relay`): a client for the dev stack's
    /// relay, `https://relay.vettid.test` and nothing else, resolved to its
    /// loopback front and trusting only the stack's TEST-ONLY root
    /// ([`crate::dev`]).
    #[cfg(feature = "dev-relay")]
    pub fn new_dev(base_url: &str, key: SigningKey, dev: &crate::dev::DevRelay) -> Result<Self, RelayError> {
        let base_url = check_base_url(base_url, false)?;
        if base_url != crate::dev::DEV_RELAY_URL {
            return Err(RelayError::Invalid);
        }
        let http = dev.builder()?.user_agent(USER_AGENT).redirect(reqwest::redirect::Policy::none()).build().map_err(|_| RelayError::Invalid)?;
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
                expect: &[200, 201],
                deadline: CALL_DEADLINE,
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
    /// [`DepositError::possibly_delivered`].
    pub async fn deposit(&self, mailbox_id: &str, token: &Token, payload: &[u8]) -> Result<String, DepositError> {
        if !auth::valid_mailbox_id(mailbox_id) {
            return Err(DepositError { error: RelayError::Invalid, possibly_delivered: false });
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
                expect: &[201],
                deadline: CALL_DEADLINE,
            })
            .await
            .map_err(|f| {
                let spent = matches!(&f.error, RelayError::Relay { status: 409, code, .. } if code == "token_used");
                DepositError { possibly_delivered: f.may_have_stored || spent, error: f.error }
            })?;
        // A 201 whose body is wrong was stored all the same.
        let stored = |error| DepositError { error, possibly_delivered: true };
        let w: Wire = serde_json::from_slice(&bytes).map_err(|_| stored(RelayError::Malformed))?;
        if !valid_msg_id(&w.msg_id) {
            return Err(stored(RelayError::Malformed));
        }
        Ok(w.msg_id)
    }

    /// `GET /v1/mailbox?wait=…&max=…` (§6.3): long-poll this mailbox.
    /// `wait` is capped at 25 s, and `max` at 100 and at what fits 64 MiB
    /// of the relay's largest messages. Re-issue at once after every
    /// answer, empty ones included.
    pub async fn collect(&self, wait_secs: u64, max: u32) -> Result<Vec<Message>, RelayError> {
        let wait = wait_secs.min(MAX_WAIT_SECS);
        let max = collect_max(max, self.max_payload_bytes);
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
                expect: &[200],
                deadline: Duration::from_secs(wait) + WAIT_MARGIN,
            })
            .await?;
        let w: Wire = serde_json::from_slice(&bytes).map_err(|_| RelayError::Malformed)?;
        if w.messages.len() > max as usize {
            return Err(RelayError::Malformed);
        }
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
            expect: &[204],
            deadline: CALL_DEADLINE,
        })
        .await
        .map(|_| ())
        .map_err(RelayError::from)
    }

    /// `GET /v1/claim/{claim_id}` (§6.9): unsigned, and **never retried**:
    /// if the answer is lost the claim is gone, and the owner makes a new
    /// one.
    pub async fn get_claim(&self, claim_id: &str) -> Result<Vec<u8>, RelayError> {
        if !valid_claim_id(claim_id) {
            return Err(RelayError::Invalid);
        }
        let url = format!("{}/v1/claim/{claim_id}", self.base_url);
        let resp = self.http.get(url).timeout(REQUEST_TIMEOUT).send().await.map_err(|e| RelayError::from_reqwest(&e))?;
        let (_, bytes) = read_response(resp, MAX_CLAIM_BODY, &[200]).await?;
        Ok(bytes)
    }

    /// Send `r`, retrying retryable failures (§7.2), each attempt signed
    /// afresh, within `r.deadline`: each attempt's timeout is cut to the
    /// time left, and a retry whose wait wouldn't leave any is not
    /// started. The failure records whether any attempt may have been
    /// stored, not only the last.
    async fn send(&self, r: Request<'_>) -> Result<(u16, Vec<u8>), Failure> {
        let attempts = self.max_attempts.max(1);
        let deadline = tokio::time::Instant::now() + r.deadline;
        let mut may_have_stored = false;
        let mut attempt = 0;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let error = match self.once(&r, r.timeout.min(left)).await {
                Ok(ok) => return Ok(ok),
                Err(e) => e,
            };
            may_have_stored |= error.may_have_stored();
            attempt += 1;
            let wait = match &error {
                RelayError::Relay { retry_after: Some(s), .. } if *s > MAX_RETRY_AFTER_SECS => None,
                e if e.retryable() && attempt < attempts => Some(retry_delay(attempt, e)),
                _ => None,
            };
            // A retry must start with time to spare (1 s) before the deadline.
            let wait = wait.filter(|d| tokio::time::Instant::now() + *d + Duration::from_secs(1) < deadline);
            match wait {
                Some(d) => tokio::time::sleep(d).await,
                None => return Err(Failure { error, may_have_stored }),
            }
        }
    }

    async fn once(&self, r: &Request<'_>, timeout: Duration) -> Result<(u16, Vec<u8>), RelayError> {
        let mut url = format!("{}{}", self.base_url, r.path);
        if let Some(q) = &r.query {
            url.push('?');
            url.push_str(q);
        }
        let body = r.body.clone().unwrap_or_default();
        let signed = SignedHeaders::new(&self.key, r.method.as_str(), &r.path, &body, chrono::Utc::now());
        let mut req = self.http.request(r.method.clone(), url).timeout(timeout);
        for (name, value) in signed.pairs() {
            req = req.header(name, value);
        }
        if let Some(token) = r.token {
            // Sensitive: kept out of reqwest's and http's Debug output.
            let mut value = reqwest::header::HeaderValue::from_str(&format!("VettID-Deposit {}", token.as_str()))
                .map_err(|_| RelayError::Invalid)?;
            value.set_sensitive(true);
            req = req.header(reqwest::header::AUTHORIZATION, value);
        }
        if r.body.is_some() {
            req = req.header(reqwest::header::CONTENT_TYPE, "application/json").body(body);
        }
        let resp = req.send().await.map_err(|e| RelayError::from_reqwest(&e))?;
        read_response(resp, r.limit, r.expect).await
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

/// Read a response: a success's body (an `expect`ed status, else
/// `Malformed`; up to `limit` bytes, else `TooLarge`; a body that breaks
/// off is `Malformed`, not retried), or the error body of §7.1 (up to
/// 4 KiB; a longer, cut-off or unparsable one gives the code
/// `http_<status>`).
async fn read_response(mut resp: reqwest::Response, limit: usize, expect: &[u16]) -> Result<(u16, Vec<u8>), RelayError> {
    let status = resp.status().as_u16();
    if status >= 400 {
        // An error body that breaks off is still that status, not a
        // transport failure (which would be retried and count as stored).
        let body = read_capped(&mut resp, MAX_ERROR_BODY).await.ok().flatten().unwrap_or_default();
        return Err(parse_error(status, &body));
    }
    if !expect.contains(&status) {
        return Err(RelayError::Malformed);
    }
    // The status is the relay's answer: a broken body after it is not a
    // transport failure to retry (a deposit was stored).
    let bytes = read_capped(&mut resp, limit).await.map_err(|_| RelayError::Malformed)?.ok_or(RelayError::TooLarge)?;
    Ok((status, bytes))
}

/// The wait before retry `attempt` (1-based): `retry_after` if the relay
/// gave one (plus up to 250 ms), else full jitter over 0.25 s × 2ⁿ⁻¹,
/// capped at 30 s (VM §8.6).
fn retry_delay(attempt: u32, last: &RelayError) -> Duration {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    if let RelayError::Relay { retry_after: Some(s), .. } = last {
        return Duration::from_secs(*s) + Duration::from_millis(rng.gen_range(0..250));
    }
    let cap_ms = (250u64 << attempt.saturating_sub(1).min(7)).min(30_000);
    Duration::from_millis(rng.gen_range(0..=cap_ms))
}

/// Whether a plain-HTTP relay is allowed: tests, and the dev stack only.
const fn http_allowed() -> bool {
    cfg!(test)
}

/// A relay base URL as an origin (`scheme://host[:port]`): `https`, or
/// `http` when `allow_http`; no user name or password (they'd show in
/// `Debug`), no path but `/` (requests are signed over `/v1/…`), no query
/// or fragment.
fn check_base_url(input: &str, allow_http: bool) -> Result<String, RelayError> {
    let u = reqwest::Url::parse(input).map_err(|_| RelayError::Invalid)?;
    let scheme_ok = u.scheme() == "https" || (allow_http && u.scheme() == "http");
    if !scheme_ok
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || !(u.path().is_empty() || u.path() == "/")
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(RelayError::Invalid);
    }
    Ok(u.origin().ascii_serialization())
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
                // Status 0: `body` is the whole raw response.
                let reply = if status == 0 {
                    body
                } else {
                    format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
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

    /// 5xx and 429 rate_limited are retried, each attempt signed (the
    /// signatures differ anyway, as the timestamps move on: fresh signing
    /// holds by construction in `once`).
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
        assert_eq!(err.error, RelayError::Relay { status: 429, code: "quota_exceeded".into(), retry_after: None, quota: Some("token".into()) });
        assert!(!err.error.retryable() && !err.possibly_delivered);
        assert_eq!(seen.lock().unwrap().len(), 1);

        // A wrongly typed retry_after doesn't hide the code.
        let (base, seen) = stub(vec![(429, r#"{"code":"quota_exceeded","retry_after":1.5,"quota":7}"#)]);
        let err = client(&base).collect(0, 1).await.unwrap_err();
        assert_eq!(err, RelayError::Relay { status: 429, code: "quota_exceeded".into(), retry_after: Some(2), quota: None });
        assert_eq!(seen.lock().unwrap().len(), 1);

        // A 429 without a readable code, or a code that isn't [a-z_], is
        // not retried and not passed on.
        let (base, seen) = stub(vec![(429, "busy")]);
        assert_eq!(client(&base).collect(0, 1).await.unwrap_err().code(), Some("http_429"));
        assert_eq!(seen.lock().unwrap().len(), 1);
        let (base, _) = stub(vec![(403, "{\"code\":\"x\\n[fake log line]\"}")]);
        assert_eq!(client(&base).collect(0, 1).await.unwrap_err().code(), Some("http_403"));

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
            assert_eq!(c.deposit(bad, &token, b"x").await.unwrap_err().error, RelayError::Invalid, "{bad}");
            assert_eq!(c.get_claim(bad).await.unwrap_err(), RelayError::Invalid, "{bad}");
        }
        assert_eq!(c.ack("01jxample0000000000000000a").await.unwrap_err(), RelayError::Invalid);
        assert_eq!(c.ack("01JXAMPLE000000000000000IL").await.unwrap_err(), RelayError::Invalid);
        assert_eq!(c.ack("81JXAMPE00000000000000000A").await.unwrap_err(), RelayError::Invalid, "over 128 bits");
        assert!(!c.deposit("../x", &token, b"x").await.unwrap_err().possibly_delivered);
        assert!(RelayClient::new("ftp://relay.example", sender()).is_err());
        assert!(RelayClient::new("https://relay.example/", sender()).is_ok());
    }

    /// The base URL rule as a release build applies it: https only, an
    /// origin and nothing more.
    #[test]
    fn base_urls_are_origins() {
        assert_eq!(check_base_url("https://relay.example/", false).unwrap(), "https://relay.example");
        assert_eq!(check_base_url("HTTPS://Relay.Example:8443", false).unwrap(), "https://relay.example:8443");
        for bad in [
            "http://relay.example",
            "https://user:pw@relay.example",
            "https://user@relay.example",
            "https://relay.example/prefix",
            "https://relay.example/?q",
            "https://relay.example/#f",
            "relay.example",
            "",
        ] {
            assert_eq!(check_base_url(bad, false), Err(RelayError::Invalid), "{bad}");
        }
        assert_eq!(check_base_url("http://127.0.0.1:8080", true).unwrap(), "http://127.0.0.1:8080");
        assert!(!format!("{:?}", RelayClient::new("https://relay.example", sender()).unwrap()).contains("pw"));
    }

    /// Only the protocol's success status is a success: a 3xx (redirects
    /// are off) or a 200 where 201 or 204 is due is Malformed; for a
    /// deposit that is unconfirmed.
    #[tokio::test]
    async fn unexpected_success_statuses_are_refused() {
        let (base, _) = stub(vec![(302, "")]);
        assert_eq!(client(&base).ack(MSG_ID).await.unwrap_err(), RelayError::Malformed);
        let (base, _) = stub(vec![(301, "moved")]);
        assert_eq!(client(&base).get_claim("gr2q7gf5lh6pzfdnurnkvputhp").await.unwrap_err(), RelayError::Malformed);
        let (base, _) = stub(vec![(200, r#"{"msg_id":"01JXAMPE00000000000000000A"}"#)]);
        let token = Token::from_received("v4.public.t".into());
        let err = client(&base).deposit("gr2q7gf5lh6pzfdnurnkvputhp", &token, b"x").await.unwrap_err();
        assert_eq!(err, DepositError { error: RelayError::Malformed, possibly_delivered: true });
    }

    /// A retry_after over 60 s ends the attempts at once instead of
    /// sleeping.
    #[tokio::test]
    async fn a_long_retry_after_is_not_waited_out() {
        let (base, seen) = stub(vec![(429, r#"{"code":"rate_limited","retry_after":1000000000000000}"#), (204, "")]);
        let c = client(&base);
        let err = tokio::time::timeout(Duration::from_secs(5), c.ack(MSG_ID)).await.expect("no long sleep").unwrap_err();
        assert_eq!(err.code(), Some("rate_limited"));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    /// An earlier attempt that may have been stored makes a deposit
    /// unconfirmed whatever the last attempt says.
    #[tokio::test]
    async fn retry_history_decides_possibly_delivered() {
        let (base, seen) = stub(vec![
            (503, r#"{"code":"internal","message":"x"}"#),
            (429, r#"{"code":"quota_exceeded","message":"x","quota":"token"}"#),
        ]);
        let token = Token::from_received("v4.public.t".into());
        let err = client(&base).deposit("gr2q7gf5lh6pzfdnurnkvputhp", &token, b"x").await.unwrap_err();
        assert_eq!(err.error.code(), Some("quota_exceeded"));
        assert!(err.possibly_delivered, "the 503 may have come after storing");
        assert_eq!(seen.lock().unwrap().len(), 2);
        assert!(err.to_string().contains("may have been delivered"));
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
        assert_eq!(err.error.code(), Some("token_used"));
        assert!(err.possibly_delivered && !err.error.retryable());
        assert_eq!(seen.lock().unwrap().len(), 2);

        // token_used alone (a first attempt) is unconfirmed too; a plain
        // refusal is a failure.
        let (base, _) = stub(vec![(409, r#"{"code":"token_used"}"#)]);
        assert!(client(&base).deposit("gr2q7gf5lh6pzfdnurnkvputhp", &token, b"x").await.unwrap_err().possibly_delivered);
        let (base, _) = stub(vec![(401, r#"{"code":"token_invalid"}"#)]);
        assert!(!client(&base).deposit("gr2q7gf5lh6pzfdnurnkvputhp", &token, b"x").await.unwrap_err().possibly_delivered);
    }

    /// Bodies over their cap are refused, not buffered: a claim over 1 MiB,
    /// a collect over what `max` messages can need, an error over 4 KiB.
    #[tokio::test]
    async fn oversized_answers_are_refused() {
        let big = "a".repeat(MAX_CLAIM_BODY + 1);
        let (base, _) = stub(vec![(200, big.as_str())]);
        assert_eq!(client(&base).get_claim("gr2q7gf5lh6pzfdnurnkvputhp").await.unwrap_err(), RelayError::TooLarge);

        // The same with no Content-Length (chunked): the cap holds while
        // reading.
        let chunk = "b".repeat(0x10000);
        let mut raw = String::from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
        for _ in 0..17 {
            raw.push_str(&format!("10000\r\n{chunk}\r\n"));
        }
        raw.push_str("0\r\n\r\n");
        let (base, _) = stub(vec![(0, raw.as_str())]);
        assert_eq!(client(&base).get_claim("gr2q7gf5lh6pzfdnurnkvputhp").await.unwrap_err(), RelayError::TooLarge);

        let body = format!(r#"{{"messages":[],"pad":"{}"}}"#, "x".repeat(collect_limit(1, 0)));
        let (base, _) = stub(vec![(200, body.as_str())]);
        assert_eq!(client(&base).collect(0, 1).await.unwrap_err(), RelayError::TooLarge);

        let long_err = format!(r#"{{"code":"bad_request","message":"{}"}}"#, "m".repeat(MAX_ERROR_BODY));
        let (base, _) = stub(vec![(400, long_err.as_str())]);
        assert_eq!(client(&base).collect(0, 1).await.unwrap_err().code(), Some("http_400"));
    }

    /// A full collect of the largest messages fits its cap, and no cap
    /// passes 64 MiB: a relay advertising big payloads gets a smaller max.
    #[test]
    fn collect_limit_fits_a_full_answer() {
        let b64 = DEFAULT_MAX_PAYLOAD.div_ceil(3) * 4;
        assert_eq!(collect_max(100, DEFAULT_MAX_PAYLOAD), 100);
        assert!(collect_limit(100, DEFAULT_MAX_PAYLOAD) >= 100 * (b64 + 300));
        assert!(collect_limit(100, DEFAULT_MAX_PAYLOAD) <= MAX_COLLECT_BODY);
        for payload in [DEFAULT_MAX_PAYLOAD, 1 << 20, MAX_PAYLOAD_CEILING, usize::MAX] {
            let m = collect_max(100, payload);
            assert!(m >= 1 && collect_limit(m, payload) <= MAX_COLLECT_BODY, "{payload}: {m}");
        }
        assert_eq!(collect_max(100, MAX_PAYLOAD_CEILING), 5);
        assert_eq!(collect_max(0, DEFAULT_MAX_PAYLOAD), 1);
        // A missing (0) or small limit sizes for the default, so a normal
        // message never wedges collect.
        assert_eq!(collect_limit(1, 0), collect_limit(1, DEFAULT_MAX_PAYLOAD));
        assert_eq!(collect_limit(1, 30), collect_limit(1, DEFAULT_MAX_PAYLOAD));
    }

    /// A registration whose limits leave members out (or leave limits out)
    /// still parses; missing members are 0.
    #[tokio::test]
    async fn partial_limits_parse() {
        let mailbox = auth::mailbox_id(&sender().verifying_key());
        for limits in [r#","limits":{"max_payload_bytes":1000}"#, ""] {
            let body = format!(r#"{{"mailbox_id":"{mailbox}"{limits}}}"#);
            let (base, _) = stub(vec![(200, body.as_str())]);
            let reg = client(&base).register().await.unwrap();
            assert!(!reg.created);
            assert_eq!(reg.limits.message_ttl_seconds, 0);
        }
    }

    /// A connection that never opens sent nothing: retryable, not
    /// possibly delivered. A request that can't be built is Invalid.
    #[tokio::test]
    async fn unreachable_and_unbuildable_requests_are_not_unconfirmed() {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut c = client(&format!("http://127.0.0.1:{port}"));
        c.max_attempts = 1;
        let token = Token::from_received("v4.public.t".into());
        let err = c.deposit("gr2q7gf5lh6pzfdnurnkvputhp", &token, b"x").await.unwrap_err();
        assert_eq!(err.error, RelayError::Connect);
        assert!(err.error.retryable() && !err.possibly_delivered);

        let (base, seen) = stub(vec![(201, "{}")]);
        let bad = Token::from_received("v4.public.a\nb".into());
        let err = client(&base).deposit("gr2q7gf5lh6pzfdnurnkvputhp", &bad, b"x").await.unwrap_err();
        assert_eq!(err, DepositError { error: RelayError::Invalid, possibly_delivered: false });
        assert!(seen.lock().unwrap().is_empty());
    }

    /// A 201 whose body breaks off is the relay's answer: not retried, and
    /// the deposit is unconfirmed.
    #[tokio::test]
    async fn a_broken_success_body_is_not_retried() {
        let raw = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"msg";
        let (base, seen) = stub(vec![(0, raw), (201, r#"{"msg_id":"01JXAMPE00000000000000000A"}"#)]);
        let token = Token::from_received("v4.public.t".into());
        let err = client(&base).deposit("gr2q7gf5lh6pzfdnurnkvputhp", &token, b"x").await.unwrap_err();
        assert_eq!(err, DepositError { error: RelayError::Malformed, possibly_delivered: true });
        assert_eq!(seen.lock().unwrap().len(), 1, "not retried");
    }

    /// A retry that wouldn't fit the call's 30 s isn't started.
    #[tokio::test]
    async fn retries_stay_within_the_deadline() {
        let (base, seen) = stub(vec![(429, r#"{"code":"rate_limited","retry_after":45}"#), (204, "")]);
        let c = client(&base);
        let started = std::time::Instant::now();
        let err = tokio::time::timeout(Duration::from_secs(5), c.ack(MSG_ID)).await.expect("no wait past the deadline").unwrap_err();
        assert_eq!(err.code(), Some("rate_limited"));
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// More messages than asked for is Malformed.
    #[tokio::test]
    async fn too_many_messages_are_refused() {
        let key = auth::encode_key(&sender().verifying_key());
        let one = format!(r#"{{"msg_id":"{MSG_ID}","deposited_at":"t","sender":"{key}","payload":""}}"#);
        let body = format!(r#"{{"messages":[{one},{one}]}}"#);
        let (base, _) = stub(vec![(200, body.as_str())]);
        assert_eq!(client(&base).collect(0, 1).await.unwrap_err(), RelayError::Malformed);
    }

    /// The retry delay: full jitter within 0.25 s × 2ⁿ, capped at 30 s; or
    /// retry_after.
    #[test]
    fn retry_delays_follow_section_8_6() {
        for attempt in 1..12 {
            let d = retry_delay(attempt, &RelayError::Transport);
            assert!(d <= Duration::from_millis((250u64 << (attempt - 1).min(7)).min(30_000)), "{attempt}: {d:?}");
        }
        assert!((0..50).all(|_| retry_delay(1, &RelayError::Transport) <= Duration::from_millis(250)), "starts at 0.25 s");
        let after = RelayError::Relay { status: 429, code: "rate_limited".into(), retry_after: Some(3), quota: None };
        let d = retry_delay(1, &after);
        assert!(d >= Duration::from_secs(3) && d < Duration::from_millis(3250));
    }
}
