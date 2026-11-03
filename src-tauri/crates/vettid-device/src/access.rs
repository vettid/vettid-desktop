//! Access sessions of a desktop (VAULT-MESSAGING §6.8, §10.3): the
//! time-limited authorization an owner app grants, without which the vault
//! lets a paired desktop do almost nothing. This module asks for one, ends
//! one, reads the desktop's own from `vault.status`, and follows the
//! vault's `device.session.granted` and `device.session.ended`.
//!
//! **Fail secure.** [`Access::active_at`] is true only for a session the
//! vault named (in a grant or in `vault.status`) whose `expires_at` is
//! still ahead. Nothing here guesses one into being:
//! - after a restart there is none until `vault.status` is read (the
//!   vault is the only source, §6.8 "A device's own session");
//! - ending one drops it here at once, before the vault answers;
//! - a session event that doesn't check out drops it too (only the vault
//!   can seal one, so something changed that this device can't read):
//!   read `vault.status` again;
//! - what the vault said is applied in the order the vault said it (its
//!   inner `ts`), not in the order it arrived: messages arrive in no order
//!   (§8.4), and a `vault.status` answer from before an end must not bring
//!   the ended session back.
//!
//! **The ordering rule** (§6.8 "Ending", 0.82.5): no
//! `device.session.request` is sent while this device's last
//! `device.session.end` is unanswered. The unanswered end is stored
//! ([`crate::store::PendingEnd`]), so the rule holds across a restart.
//! [`Access::settle`] sends it, and retries it twice under the same `id`
//! (§8.6); when no answer comes, it reads `vault.status`:
//! - `session: null`: the request may go;
//! - the session the end named: the end is sent again under a new `id`;
//! - no `session` member (an old vault: the member came with 0.41.0, the
//!   spec's "a vault before this change"): the request may go, the
//!   retries being spent;
//! - another session than the one the end named: that end can no longer
//!   change anything (the vault answers an end of a session that isn't
//!   current `{}` and changes nothing), so the request may go;
//! - a session, and the end named none: the request waits (until the end
//!   is answered or that session reads `null`).
//!
//! Missed events are recovered by reading `vault.status`, as §6.8 says:
//! they are not stored in the inbox.
//!
//! Not here yet: approvals (`approval.waiting`) and step-up types.

use chrono::{DateTime, TimeDelta, Utc};
use vettid_vms::envelope::{parse_ts, Inner, Status};
use vettid_vms::strict_json::{self, Builder, Object};

use crate::pairing::Clock;
use crate::session::{Session, SessionError, REQUEST_TIMEOUT};
use crate::store::{PendingEnd, Persist};
use crate::transport::Transport;

/// The shortest access session a device may ask for (§10.3).
pub const MIN_SECONDS: u32 = 60;
/// The longest (24 h, §10.3).
pub const MAX_SECONDS: u32 = 86_400;
/// How many times an end is sent under one `id`: once, and the two
/// application retries of §8.6.
pub const END_ATTEMPTS: u32 = 3;
/// The longest `session_id` this device sends or accepts (the vault's
/// bound on a string member).
pub const MAX_SESSION_ID: usize = 4096;

pub const TYPE_REQUEST: &str = "device.session.request";
pub const TYPE_END: &str = "device.session.end";
pub const TYPE_GRANTED: &str = "device.session.granted";
pub const TYPE_ENDED: &str = "device.session.ended";
pub const TYPE_STATUS: &str = "vault.status";

/// An access session the vault named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessSession {
    pub session_id: String,
    pub expires_at: DateTime<Utc>,
}

impl AccessSession {
    /// Whether it is still running at `t`.
    pub fn active_at(&self, t: DateTime<Utc>) -> bool {
        t < self.expires_at
    }
}

/// `vault.status`'s `session` member (§10.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusSession {
    /// This device's current session.
    Session(AccessSession),
    /// `null`: it has none.
    None,
    /// No `session` member: a vault before 0.41.0 (§6.8), for which the
    /// ordering rule falls back to the retries alone.
    Absent,
}

/// The answer to `device.session.request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestOutcome {
    /// The owner's apps are asked; the request lapses at `exp`.
    Requested { request_id: String, exp: DateTime<Utc> },
    /// Less than 10 minutes after the last accepted request: try again at
    /// `allowed_after` (0.40.0).
    TooSoon { allowed_after: DateTime<Utc> },
}

/// How an end came out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndOutcome {
    /// The vault answered it, or `vault.status` shows the session gone.
    Ended,
    /// No answer, and nothing shows the session gone (a vault without the
    /// `session` member): the person must not be told it ended. Requests
    /// may go again (the retries are spent).
    Unconfirmed,
}

/// How [`Access::settle`] left the ordering rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// No end was waiting.
    Clear,
    /// The end was answered `ok`.
    Answered,
    /// No answer, but `vault.status` reads `session: null`.
    StatusNull,
    /// No answer, and the end named a session that `vault.status` shows
    /// replaced: that end can't change anything any more.
    Moot,
    /// No answer, and the vault has no `session` member in `vault.status`
    /// (before 0.41.0): the retries are spent.
    OldVault,
}

/// What a session message from the vault said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessEvent {
    /// `device.session.granted`: this session replaces the current one.
    Granted(AccessSession),
    /// `device.session.ended{reason: "denied"}`: the request was refused.
    /// A current session runs on to its `expires_at` (0.77.0).
    Denied,
    /// `device.session.ended{reason: "ended"}`: an app ended the session.
    Ended,
    /// A late answer to this device's `device.session.request`.
    Requested(RequestOutcome),
    /// A late `ok` answer to this device's pending end: requests may go.
    EndAnswered,
    /// A late answer to `vault.status`.
    Status(StatusSession),
}

/// Why an access operation failed. Carries no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessError {
    /// The session engine failed (relay, store, refused, timed out).
    Session(SessionError),
    /// `seconds` outside 60..=86,400: not sent.
    BadSeconds,
    /// A `session_id` that is empty or too long: not sent.
    BadSessionId,
    /// What the vault sent doesn't check out (a body with a missing,
    /// unknown or mistyped member). The current session, if it was the
    /// subject, is dropped: read `vault.status`.
    Malformed,
    /// The vault answered with an error `code`.
    Vault(String),
    /// The ordering rule holds the request back: the last end is
    /// unanswered and `vault.status` still shows a session. Try again
    /// later.
    EndUnconfirmed,
}

impl std::fmt::Display for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session(e) => write!(f, "access: {e}"),
            Self::BadSeconds => f.write_str("access: a session is 60 seconds to 24 hours"),
            Self::BadSessionId => f.write_str("access: invalid session id"),
            Self::Malformed => f.write_str("access: the vault's message doesn't check out"),
            // The code is the vault's: printable ASCII only, bounded.
            Self::Vault(code) => write!(f, "access: the vault answered {}", printable(code)),
            Self::EndUnconfirmed => f.write_str("access: the last end isn't confirmed yet"),
        }
    }
}

impl std::error::Error for AccessError {}

impl From<SessionError> for AccessError {
    fn from(e: SessionError) -> Self {
        Self::Session(e)
    }
}

fn printable(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_graphic()).take(64).collect()
}

fn malformed<E>(_: E) -> AccessError {
    AccessError::Malformed
}

/// Refuse a member not in `names`.
fn only(o: &Object<'_>, names: &[&str]) -> Result<(), AccessError> {
    if o.names().all(|n| names.contains(&n)) {
        Ok(())
    } else {
        Err(AccessError::Malformed)
    }
}

fn ts(o: &Object<'_>, name: &str) -> Result<DateTime<Utc>, AccessError> {
    parse_ts(&o.string(name).map_err(malformed)?).ok_or(AccessError::Malformed)
}

/// Whether `id` may be sent as, or accepted as, a `session_id`.
pub fn valid_session_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_SESSION_ID
}

/// `{session_id, expires_at}`, exactly.
fn session_of(o: &Object<'_>) -> Result<AccessSession, AccessError> {
    only(o, &["session_id", "expires_at"])?;
    let session_id = o.string("session_id").map_err(malformed)?;
    if !valid_session_id(&session_id) {
        return Err(AccessError::Malformed);
    }
    Ok(AccessSession { session_id, expires_at: ts(o, "expires_at")? })
}

/// `vault.status`'s `session` member from its body. The rest of the body
/// is not this module's: only `session` is checked.
pub fn parse_status(body: &str) -> Result<StatusSession, AccessError> {
    let o = strict_json::parse_object(body.as_bytes()).map_err(malformed)?;
    match o.get("session") {
        None => Ok(StatusSession::Absent),
        Some("null") => Ok(StatusSession::None),
        Some(_) => Ok(StatusSession::Session(session_of(&o.object("session", 1).map_err(malformed)?)?)),
    }
}

/// A `device.session.request` answer.
pub fn parse_request_answer(answer: &Inner) -> Result<RequestOutcome, AccessError> {
    let o = strict_json::parse_object(answer.body.as_bytes()).map_err(malformed)?;
    match answer.response.as_ref().map(|r| &r.status) {
        Some(Status::Ok) => {
            only(&o, &["request_id", "exp"])?;
            let request_id = o.string("request_id").map_err(malformed)?;
            if request_id.is_empty() {
                return Err(AccessError::Malformed);
            }
            Ok(RequestOutcome::Requested { request_id, exp: ts(&o, "exp")? })
        }
        Some(Status::Error { code, .. }) if code == "too_soon" => {
            only(&o, &["allowed_after"])?;
            Ok(RequestOutcome::TooSoon { allowed_after: ts(&o, "allowed_after")? })
        }
        Some(Status::Error { code, .. }) => Err(AccessError::Vault(code.clone())),
        None => Err(AccessError::Malformed),
    }
}

/// A session event from the vault (not a response): `None` if `m` isn't
/// one.
pub fn parse_event(m: &Inner) -> Option<Result<AccessEvent, AccessError>> {
    if m.response.is_some() || ![TYPE_GRANTED, TYPE_ENDED].contains(&m.kind.as_str()) {
        return None;
    }
    Some((|| {
        let o = strict_json::parse_object(m.body.as_bytes()).map_err(malformed)?;
        if m.kind == TYPE_GRANTED {
            return Ok(AccessEvent::Granted(session_of(&o)?));
        }
        only(&o, &["reason"])?;
        match o.string("reason").map_err(malformed)?.as_str() {
            "denied" => Ok(AccessEvent::Denied),
            "ended" => Ok(AccessEvent::Ended),
            _ => Err(AccessError::Malformed),
        }
    })())
}

/// The body of an end.
fn end_body(session_id: Option<&str>) -> String {
    match session_id {
        Some(s) => Builder::new().string("session_id", s).finish(),
        None => "{}".into(),
    }
}

/// An `ok` answer's body must be `{}`.
fn empty_ok(answer: &Inner) -> Result<(), AccessError> {
    match answer.response.as_ref().map(|r| &r.status) {
        Some(Status::Ok) => {
            let o = strict_json::parse_object(answer.body.as_bytes()).map_err(malformed)?;
            only(&o, &[])
        }
        Some(Status::Error { code, .. }) => Err(AccessError::Vault(code.clone())),
        None => Err(AccessError::Malformed),
    }
}

/// The desktop's view of its access session. Held in memory beside the
/// [`Session`]; the unanswered end is in the session's stored state.
#[derive(Debug)]
pub struct Access {
    current: Option<AccessSession>,
    /// The vault's `ts` of the last thing applied to `current`.
    learned: Option<DateTime<Utc>>,
    /// How long each attempt waits for its answer.
    timeout: TimeDelta,
}

impl Default for Access {
    fn default() -> Self {
        Self::new()
    }
}

impl Access {
    /// No session known (as after a start: read `vault.status`).
    pub fn new() -> Self {
        Access { current: None, learned: None, timeout: REQUEST_TIMEOUT }
    }

    /// The same, waiting `timeout` for each answer.
    pub fn with_timeout(timeout: TimeDelta) -> Self {
        Access { timeout, ..Self::new() }
    }

    /// The session last learned from the vault, if any (perhaps expired).
    pub fn current(&self) -> Option<&AccessSession> {
        self.current.as_ref()
    }

    /// Whether this desktop has an access session at `t`.
    pub fn active_at(&self, t: DateTime<Utc>) -> bool {
        self.current.as_ref().is_some_and(|s| s.active_at(t))
    }

    /// Apply what the vault said at `at`: `Some` a session, `None` none.
    /// Older than what is already applied: ignored. A session that the
    /// unanswered end will end (the one it names, or any if it names none)
    /// doesn't become current.
    fn learn(&mut self, at: DateTime<Utc>, session: Option<AccessSession>, pending: Option<&PendingEnd>) {
        if self.learned.is_some_and(|l| at < l) {
            return;
        }
        self.learned = Some(at);
        self.current = match (session, pending) {
            (Some(s), Some(p)) if p.session_id.as_ref().is_none_or(|n| *n == s.session_id) => None,
            (s, _) => s,
        };
    }

    /// Drop the current session if `named` (or any, if `None`) is it.
    fn forget(&mut self, named: Option<&str>) {
        if named.is_none_or(|n| self.current.as_ref().is_some_and(|c| c.session_id == n)) {
            self.current = None;
        }
    }

    /// Ask `vault.status` and apply its `session`.
    pub async fn read_status<T: Transport, C: Clock>(&mut self, s: &mut Session<T, C>, store: &mut impl Persist) -> Result<StatusSession, AccessError> {
        let answer = s.request(store, TYPE_STATUS, "{}", self.timeout).await?;
        self.status_answer(s, &answer)
    }

    fn status_answer<T: Transport, C: Clock>(&mut self, s: &Session<T, C>, answer: &Inner) -> Result<StatusSession, AccessError> {
        if let Some(Status::Error { code, .. }) = answer.response.as_ref().map(|r| &r.status) {
            return Err(AccessError::Vault(code.clone()));
        }
        let status = match parse_status(&answer.body) {
            Ok(st) => st,
            Err(e) => {
                // Unreadable: nothing known.
                self.current = None;
                return Err(e);
            }
        };
        match &status {
            StatusSession::Session(x) => self.learn(answer.ts, Some(x.clone()), s.access_end()),
            StatusSession::None => self.learn(answer.ts, None, s.access_end()),
            // A vault before 0.41.0 says nothing: what a grant said stands.
            StatusSession::Absent => {}
        }
        Ok(status)
    }

    /// Ask for an access session of `seconds` (`None`: the vault's
    /// default, 1 h). Checked before anything is sent; then the ordering
    /// rule is settled ([`Access::settle`]) and the request sent.
    pub async fn request<T: Transport, C: Clock>(
        &mut self,
        s: &mut Session<T, C>,
        store: &mut impl Persist,
        seconds: Option<u32>,
    ) -> Result<RequestOutcome, AccessError> {
        if seconds.is_some_and(|n| !(MIN_SECONDS..=MAX_SECONDS).contains(&n)) {
            return Err(AccessError::BadSeconds);
        }
        self.settle(s, store).await?;
        let body = match seconds {
            Some(n) => Builder::new().uint("seconds", u64::from(n)).finish(),
            None => "{}".into(),
        };
        let answer = s.request(store, TYPE_REQUEST, &body, self.timeout).await?;
        parse_request_answer(&answer)
    }

    /// End this desktop's access session: the one named by `session_id`,
    /// or all of its access when `None` (the person's End access, §6.8:
    /// a desktop names a session only for an end it makes on its own).
    /// The session is dropped here at once; the end is stored, sent, and
    /// settled as the ordering rule says. While an end that names no
    /// session is unanswered, a new end is that one again (it already
    /// ends everything); otherwise a new end replaces the unanswered one.
    pub async fn end<T: Transport, C: Clock>(
        &mut self,
        s: &mut Session<T, C>,
        store: &mut impl Persist,
        session_id: Option<&str>,
    ) -> Result<EndOutcome, AccessError> {
        if session_id.is_some_and(|id| !valid_session_id(id)) {
            return Err(AccessError::BadSessionId);
        }
        self.forget(session_id);
        let reuse = s.access_end().is_some_and(|p| p.session_id.is_none());
        if !reuse {
            let id = s.new_id()?;
            s.set_access_end(store, Some(PendingEnd { id, session_id: session_id.map(str::to_string), attempts: 0 }))?;
        }
        match self.settle(s, store).await? {
            Settled::OldVault => Ok(EndOutcome::Unconfirmed),
            _ => Ok(EndOutcome::Ended),
        }
    }

    /// Settle the unanswered end, if there is one (see the module doc):
    /// `Ok` once a request may be sent. `EndUnconfirmed` while it may not;
    /// the end stays stored, and a later call carries on from where this
    /// one stopped.
    pub async fn settle<T: Transport, C: Clock>(&mut self, s: &mut Session<T, C>, store: &mut impl Persist) -> Result<Settled, AccessError> {
        let mut reissued = false;
        loop {
            let Some(p) = s.access_end().cloned() else { return Ok(Settled::Clear) };
            if p.attempts < END_ATTEMPTS {
                // Counted (and stored) before it is sent.
                s.set_access_end(store, Some(PendingEnd { attempts: p.attempts + 1, ..p.clone() }))?;
                let body = end_body(p.session_id.as_deref());
                match s.request_again(store, &p.id, TYPE_END, &body, self.timeout).await {
                    Ok(answer) => return self.end_answered(s, store, &p, &answer).map(|()| Settled::Answered),
                    Err(SessionError::TimedOut) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            // The retries are spent: vault.status decides.
            let status = self.read_status(s, store).await?;
            match (status, &p.session_id) {
                (StatusSession::None, _) => {
                    s.set_access_end(store, None)?;
                    return Ok(Settled::StatusNull);
                }
                (StatusSession::Absent, _) => {
                    s.set_access_end(store, None)?;
                    return Ok(Settled::OldVault);
                }
                (StatusSession::Session(cur), Some(named)) if cur.session_id == *named => {
                    if reissued {
                        return Err(AccessError::EndUnconfirmed);
                    }
                    // Sent again under a new id, naming the same session.
                    reissued = true;
                    let id = s.new_id()?;
                    s.set_access_end(store, Some(PendingEnd { id, session_id: Some(named.clone()), attempts: 0 }))?;
                }
                // Another session is current (read_status applied it): the
                // end of the one it replaced changes nothing any more.
                (StatusSession::Session(_), Some(_)) => {
                    s.set_access_end(store, None)?;
                    return Ok(Settled::Moot);
                }
                (StatusSession::Session(_), None) => return Err(AccessError::EndUnconfirmed),
            }
        }
    }

    /// The end `p` is answered: it is cleared (an error answer is an answer
    /// too), and an `ok` one confirms that what it named is gone.
    fn end_answered<T: Transport, C: Clock>(
        &mut self,
        s: &mut Session<T, C>,
        store: &mut impl Persist,
        p: &PendingEnd,
        answer: &Inner,
    ) -> Result<(), AccessError> {
        s.set_access_end(store, None)?;
        let ok = empty_ok(answer);
        if ok.is_ok() || ok == Err(AccessError::Malformed) {
            // Ended (or never current): from the vault's ts of the answer,
            // what it named isn't current. A malformed `ok` is still an ok.
            if self.learned.is_none_or(|l| answer.ts >= l) {
                self.learned = Some(answer.ts);
            }
            self.forget(p.session_id.as_deref());
        }
        ok
    }

    /// Take a message from [`Session::poll`]: a session event, or a late
    /// answer to this module's requests. `Ok(None)`: not one of them.
    pub fn observe<T: Transport, C: Clock>(
        &mut self,
        s: &mut Session<T, C>,
        store: &mut impl Persist,
        m: &Inner,
    ) -> Result<Option<AccessEvent>, AccessError> {
        if let Some(r) = &m.response {
            return match m.kind.as_str() {
                TYPE_END => match s.access_end().cloned() {
                    Some(p) if p.id == r.re => self.end_answered(s, store, &p, m).map(|()| Some(AccessEvent::EndAnswered)),
                    _ => Ok(None),
                },
                TYPE_REQUEST => parse_request_answer(m).map(|o| Some(AccessEvent::Requested(o))),
                TYPE_STATUS => self.status_answer(s, m).map(|st| Some(AccessEvent::Status(st))),
                _ => Ok(None),
            };
        }
        let Some(event) = parse_event(m) else { return Ok(None) };
        match &event {
            Ok(AccessEvent::Granted(g)) => self.learn(m.ts, Some(g.clone()), s.access_end()),
            Ok(AccessEvent::Ended) => self.learn(m.ts, None, s.access_end()),
            // A renewal denied: the current session runs on (0.77.0).
            Ok(_) => {}
            // Something changed that can't be read: nothing is assumed.
            Err(_) => self.current = None,
        }
        event.map(Some)
    }
}

#[cfg(test)]
mod tests;
