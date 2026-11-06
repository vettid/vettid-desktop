//! Access sessions of a desktop (VAULT-MESSAGING §6.8, §10.3): the
//! time-limited authorization an owner app grants, without which the vault
//! lets a paired desktop do almost nothing. This module asks for one, ends
//! one, reads the desktop's own from `vault.status`, and follows the
//! vault's `device.session.granted` and `device.session.ended`.
//!
//! **Fail secure.** [`Access::active_at`] is true only for a session the
//! vault named (in a grant or in `vault.status`) whose `expires_at` is
//! more than its margin ahead (see [`margin_for`]). Nothing here guesses
//! one into being:
//! - after a start there is none until `vault.status` has answered, or an
//!   end has been answered (the vault is the only source, §6.8 "A device's
//!   own session"): a grant that arrives first is recorded, not reported
//!   active (it may be older than an end this device doesn't know of);
//! - ending one drops it here at once, before the vault answers;
//! - a session event that doesn't check out drops it too (only the vault
//!   can seal one, so something changed that this device can't read):
//!   read `vault.status` again;
//! - what the vault said is applied in the order the vault said it (its
//!   inner `ts`), not in the order it arrived: messages arrive in no order
//!   (§8.4), and a `vault.status` answer from before an end must not bring
//!   the ended session back. The vault stamps a batch with one `ts`: at
//!   the same `ts`, the vault's `seq` (§8.4, per epoch and direction)
//!   decides, and without one on both, the later to arrive stands.
//!
//! **The ordering rule** (§6.8 "Ending", 0.82.5): no
//! `device.session.request` is sent while this device's last
//! `device.session.end` is unanswered. The unanswered end is stored
//! ([`crate::store::PendingEnd`]), so the rule holds across a restart.
//! [`Access::settle`] sends it, and retries it twice under the same `id`
//! (§8.6); when no answer comes, it reads `vault.status`:
//! - `session: null`: the request may go;
//! - the session the end named, or any session when it named none: the end
//!   is sent again under a new `id`, naming that session (the vault ends
//!   all of a device's access for an end of its current session);
//! - no `session` member (an old vault: the member came with 0.41.0, the
//!   spec's "a vault before this change"): the request may go, the
//!   retries being spent;
//! - another session than the one the end named: that end can no longer
//!   change anything (the vault answers an end of a session that isn't
//!   current `{}` and changes nothing), so the request may go;
//! - the same again after that resend: the request waits (until the end is
//!   answered or the session reads `null`).
//!
//! Missed events are recovered by reading `vault.status`, as §6.8 says:
//! they are not stored in the inbox.
//!
//! **The vault's lock and hold** (VAULT-LOCK-PLAN §3.1; VAULT-MESSAGING
//! §3.6.3, §3.6.5, §10.2 "Locks"). Beside the session, [`Access`] keeps
//! what the vault last said of itself ([`VaultState`]): `Unknown` at
//! start and whenever nothing below says otherwise; `Open` (with its
//! `unlock_id`, and `due` past the deadline with the hold off) or `Held`
//! from a `vault.status` answer; `Held` from `vault.held` or an
//! `owner_check_required` answer; `Locked` from a `vault.locking` naming
//! the current `unlock_id`. Only `Open` lets a session be active
//! ([`Access::active_at`]): while held the vault suspends desktops'
//! sessions (§3.6.3), and a locked vault answers nothing (§12.1).
//! - These statements are ordered by the vault's `ts` (and `seq`), as the
//!   session's are, in their own order: an older one never replaces a
//!   newer one (§8.4).
//! - A `vault.locking` naming another `unlock_id` never sets `Locked`
//!   (§10.2 "Locks"), but a newer one makes the state `Unknown` (the
//!   `unlock_id` held is out of date); one when no `unlock_id` is held (or
//!   one without the member) makes it `Unknown` too, never `Locked` (owner
//!   decision 1, 2026-11-05): either way the event says to read
//!   `vault.status` now
//!   ([`AccessEvent::ReadStatus`]). A status never sets `Open` with an
//!   `unlock_id` a lock notice has ended.
//! - `device.session.granted` and `.ended` never change it (§3.6.3).
//! - Its decay (`Open` to `Unknown` when a status goes unanswered, when
//!   the vault hasn't confirmed it for a while, or on resume) is the
//!   app's: see [`Access::vault_unconfirmed`].
//! - The desktop never sends `vault.lock` (owner decision, 2026-11-05):
//!   nothing here does.
//!
//! Not here yet: approvals (`approval.waiting`) and step-up types.

use chrono::{DateTime, TimeDelta, Utc};
use vettid_vms::envelope::{parse_ts, Inner, Status};
use vettid_vms::strict_json::{self, Builder, Object};

use crate::pairing::Clock;
use crate::session::{Session, SessionError, REQUEST_TIMEOUT};
use crate::store::{short_id, PendingEnd, Persist};
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
/// A session counts as ended up to this long before its `expires_at`: this
/// desktop's clock may be behind the vault's, and acting on a session the
/// vault has already ended is the unsafe side. A short session gets less
/// ([`margin_for`]).
pub const EXPIRY_MARGIN: TimeDelta = TimeDelta::seconds(60);

/// The margin of a session the vault named at `at` (its `ts`):
/// [`EXPIRY_MARGIN`], but at most a quarter of what was left of it then, so
/// that a short session (60 s is valid) is active for most of its life.
/// Recomputed whenever the vault names it again (a `vault.status` read).
pub fn margin_for(session: &AccessSession, at: DateTime<Utc>) -> TimeDelta {
    let left = (session.expires_at - at).max(TimeDelta::zero());
    EXPIRY_MARGIN.min(left / 4)
}

pub const TYPE_REQUEST: &str = "device.session.request";
pub const TYPE_END: &str = "device.session.end";
pub const TYPE_GRANTED: &str = "device.session.granted";
pub const TYPE_ENDED: &str = "device.session.ended";
pub const TYPE_STATUS: &str = "vault.status";
pub const TYPE_LOCKING: &str = "vault.locking";
pub const TYPE_HELD: &str = "vault.held";
/// The code the vault answers a request with while it is held (§3.6.3).
pub const OWNER_CHECK_REQUIRED: &str = "owner_check_required";
/// How long after its answer is no longer awaited a `vault.status` request
/// stays good (its `exp` is the wait plus this). The vault reads `exp` by
/// its own clock and accepts a `ts` up to 5 minutes ahead (§8.4): with
/// that much margin, a desktop whose clock is up to 5 minutes behind the
/// vault's still gets its answers, and a copy queued longer is dropped.
pub const STATUS_EXP_MARGIN: TimeDelta = vettid_vms::envelope::MAX_CLOCK_SKEW_FUTURE;
/// How many `unlock_id`s that lock notices ended are remembered.
const ENDED_KEEP: usize = 16;

/// Whether `id` is an `unlock_id`: exactly 32 lowercase hex characters
/// (§10.2 "Locks").
pub fn valid_unlock_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// What is waiting while the vault is held: the counts of `vault.held`
/// and of `vault.status`'s `owner_check.waiting` (§3.6.3). Counts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Waiting {
    pub messages: u64,
    pub requests: u64,
    pub calls: u64,
    pub other: u64,
}

/// Why the vault locked: `vault.locking`'s `reason` (§10.2). Another
/// value, or none, is a lock without a known reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    /// `"idle"`: the idle lock (§3.6.8).
    Idle,
    /// `"owner_check"`: ten failed owner checks (§3.6.4).
    OwnerCheck,
    /// `"recovery"`: a recovery request (§11.11.1).
    Recovery,
}

/// What this desktop knows of the vault's lock and hold (VAULT-LOCK-PLAN
/// §3.1). Only `Open` lets a session be live. `Debug` shows only the start
/// of an `unlock_id`.
#[derive(Clone, PartialEq, Eq, Default)]
pub enum VaultState {
    /// Nothing current says otherwise: at start, after a malformed
    /// statement or a lock notice this desktop can't place, and (the
    /// app's decay) after an unanswered status or a resume.
    #[default]
    Unknown,
    /// A `vault.status` answer: open, under `unlock_id` (none from a vault
    /// before release L). `due`: past the deadline with the hold off; the
    /// session continues (§3.6.3, §3.6.7).
    Open { unlock_id: Option<String>, due: bool },
    /// Held (§3.6.3): `deadline`, the counts and `idle_lock_at` when a
    /// statement gave them (none from an `owner_check_required` answer).
    Held { deadline: Option<DateTime<Utc>>, waiting: Option<Waiting>, idle_lock_at: Option<DateTime<Utc>> },
    /// A `vault.locking` naming the current `unlock_id`, sent at `since`.
    Locked { since: DateTime<Utc>, reason: Option<LockReason> },
}

/// What a `vault.status` body says of the vault ([`parse_vault_status`]).
/// `Debug` shows only the start of the `unlock_id`.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultStatus {
    /// `Open` or `Held`.
    pub state: VaultState,
    pub unlock_id: Option<String>,
}

/// A `vault.locking` body ([`parse_locking`]). `Debug` shows only the start
/// of the `unlock_id`.
#[derive(Clone, PartialEq, Eq)]
pub struct Locking {
    /// The unlock the lock ends (none from a vault before release L).
    pub unlock_id: Option<String>,
    pub reason: Option<LockReason>,
}

/// An optional id, as `Debug` shows it: only its start.
fn short_opt(id: &Option<String>) -> Option<String> {
    id.as_deref().map(short_id)
}

impl std::fmt::Debug for VaultState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("Unknown"),
            Self::Open { unlock_id, due } => f.debug_struct("Open").field("unlock_id", &short_opt(unlock_id)).field("due", due).finish(),
            Self::Held { deadline, waiting, idle_lock_at } => {
                f.debug_struct("Held").field("deadline", deadline).field("waiting", waiting).field("idle_lock_at", idle_lock_at).finish()
            }
            Self::Locked { since, reason } => f.debug_struct("Locked").field("since", since).field("reason", reason).finish(),
        }
    }
}

impl std::fmt::Debug for VaultStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultStatus").field("state", &self.state).field("unlock_id", &short_opt(&self.unlock_id)).finish()
    }
}

impl std::fmt::Debug for Locking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Locking").field("unlock_id", &short_opt(&self.unlock_id)).field("reason", &self.reason).finish()
    }
}

/// An access session the vault named. `Debug` shows only the start of
/// its id.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessSession {
    pub session_id: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for AccessSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessSession").field("session_id", &short_id(&self.session_id)).field("expires_at", &self.expires_at).finish()
    }
}

impl AccessSession {
    /// Whether it is still running at `t`, by this desktop's clock, ended
    /// `margin` before its `expires_at`.
    pub fn active_at(&self, t: DateTime<Utc>, margin: TimeDelta) -> bool {
        t + margin < self.expires_at
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

/// What [`Access::read_status`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusRead {
    /// `vault.status`'s `session`.
    pub session: StatusSession,
    /// An end of this device's is stored and unanswered (after a restart,
    /// it isn't sent again until [`Access::settle`], [`Access::request`] or
    /// [`Access::end`] runs): call [`Access::settle`].
    pub end_pending: bool,
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
    /// No answer, and the session it named was replaced by another, which
    /// `vault.status` shows current and which runs on (owner decision
    /// 2026-11-03): this desktop still has access, and says so.
    Replaced,
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
    /// `vault.locking` naming the current `unlock_id`, newer than what was
    /// applied: the vault is [`VaultState::Locked`].
    Locked,
    /// `vault.held` (applied only if newest by `ts`).
    Held,
    /// A `vault.locking` this desktop can't apply (another `unlock_id`,
    /// none held, none named, or older than what was applied): read
    /// `vault.status` now.
    ReadStatus,
}

/// Why an access operation failed. Carries no secret; `Debug` filters
/// the vault's code as `Display` does.
#[derive(Clone, PartialEq, Eq)]
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

impl std::fmt::Debug for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session(e) => f.debug_tuple("Session").field(e).finish(),
            Self::BadSeconds => f.write_str("BadSeconds"),
            Self::BadSessionId => f.write_str("BadSessionId"),
            Self::Malformed => f.write_str("Malformed"),
            Self::Vault(code) => f.debug_tuple("Vault").field(&printable(code)).finish(),
            Self::EndUnconfirmed => f.write_str("EndUnconfirmed"),
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

/// An optional timestamp member.
fn opt_ts(o: &Object<'_>, name: &str) -> Result<Option<DateTime<Utc>>, AccessError> {
    match o.get(name) {
        None => Ok(None),
        Some(_) => ts(o, name).map(Some),
    }
}

/// An optional `waiting` member of `o` (at nesting `level`): `{messages,
/// requests, calls, other}`, each required. Other members are ignored.
fn opt_waiting(o: &Object<'_>, level: usize) -> Result<Option<Waiting>, AccessError> {
    if o.get("waiting").is_none() {
        return Ok(None);
    }
    let w = o.object("waiting", level).map_err(malformed)?;
    let n = |name: &str| w.uint(name, 0, u64::MAX).map_err(malformed);
    Ok(Some(Waiting { messages: n("messages")?, requests: n("requests")?, calls: n("calls")?, other: n("other")? }))
}

/// An optional `unlock_id` member: absent is `None`; present, it must be
/// 32 lowercase hex characters ([`valid_unlock_id`]).
fn opt_unlock_id(o: &Object<'_>) -> Result<Option<String>, AccessError> {
    match o.get("unlock_id") {
        None => Ok(None),
        Some(_) => {
            let id = o.string("unlock_id").map_err(malformed)?;
            if valid_unlock_id(&id) {
                Ok(Some(id))
            } else {
                Err(AccessError::Malformed)
            }
        }
    }
}

/// What a `vault.status` body says of the vault's lock and hold (§10.2):
/// its `unlock_id` and `owner_check` (`state`, `hold`, `deadline`, and
/// `waiting` and `idle_lock_at` if present). Other members are ignored,
/// as in [`parse_status`], which this doesn't replace.
/// - `ok`: `Open`; `due` (with the hold off): `Open` with `due`; `held`
///   (with the hold on): `Held`. A `state` and `hold` that disagree don't
///   check out.
/// - A vault that answers is not locked (§12.1): without `owner_check` (a
///   vault before 0.13.0) it is `Open`, and without `unlock_id` (before
///   release L) `Open` with none.
/// - `Malformed` when either member is present and doesn't check out (an
///   `unlock_id` that isn't 32 lowercase hex characters included): the
///   state is then `Unknown`, never taken as absent.
pub fn parse_vault_status(body: &str) -> Result<VaultStatus, AccessError> {
    let o = strict_json::parse_object(body.as_bytes()).map_err(malformed)?;
    let unlock_id = opt_unlock_id(&o)?;
    if o.get("owner_check").is_none() {
        return Ok(VaultStatus { state: VaultState::Open { unlock_id: unlock_id.clone(), due: false }, unlock_id });
    }
    let oc = o.object("owner_check", 1).map_err(malformed)?;
    let deadline = ts(&oc, "deadline")?;
    let hold = oc.bool("hold").map_err(malformed)?;
    let waiting = opt_waiting(&oc, 2)?;
    let idle_lock_at = opt_ts(&oc, "idle_lock_at")?;
    let state = match (oc.string("state").map_err(malformed)?.as_str(), hold) {
        ("ok", _) => VaultState::Open { unlock_id: unlock_id.clone(), due: false },
        ("due", false) => VaultState::Open { unlock_id: unlock_id.clone(), due: true },
        ("held", true) => VaultState::Held { deadline: Some(deadline), waiting, idle_lock_at },
        _ => return Err(AccessError::Malformed),
    };
    Ok(VaultStatus { state, unlock_id })
}

/// A `vault.held` body (§3.6.3, §10.2): `{deadline, waiting?,
/// idle_lock_at?}` as [`VaultState::Held`]. Without `waiting` the counts
/// are not known. Other members are ignored.
pub fn parse_held(body: &str) -> Result<VaultState, AccessError> {
    let o = strict_json::parse_object(body.as_bytes()).map_err(malformed)?;
    Ok(VaultState::Held { deadline: Some(ts(&o, "deadline")?), waiting: opt_waiting(&o, 1)?, idle_lock_at: opt_ts(&o, "idle_lock_at")? })
}

/// A `vault.locking` body (§10.2): `{unlock_id?, reason?}`. A `reason`
/// this desktop doesn't know is a lock without a known reason. Other
/// members are ignored.
pub fn parse_locking(body: &str) -> Result<Locking, AccessError> {
    let o = strict_json::parse_object(body.as_bytes()).map_err(malformed)?;
    let reason = match o.opt_string("reason").map_err(malformed)?.as_deref() {
        Some("idle") => Some(LockReason::Idle),
        Some("owner_check") => Some(LockReason::OwnerCheck),
        Some("recovery") => Some(LockReason::Recovery),
        _ => None,
    };
    Ok(Locking { unlock_id: opt_unlock_id(&o)?, reason })
}

/// Whether `answer` is the vault's `owner_check_required` (§3.6.3).
fn hold_answer(answer: &Inner) -> bool {
    matches!(answer.response.as_ref().map(|r| &r.status), Some(Status::Error { code, .. }) if code == OWNER_CHECK_REQUIRED)
}

/// Whether what the vault said at `at` with `seq` is not older than what
/// was applied last at `learned` with `learned_seq`: at the same `ts`, the
/// lower `seq` is the older; without a `seq` on both, the later to arrive
/// stands.
fn not_older(learned: Option<DateTime<Utc>>, learned_seq: Option<u64>, at: DateTime<Utc>, seq: Option<u64>) -> bool {
    match learned {
        None => true,
        Some(l) if at != l => at > l,
        Some(_) => match (learned_seq, seq) {
            (Some(prev), Some(n)) => n >= prev,
            _ => true,
        },
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
///
/// **The app calls [`Access::read_status`] after opening the session**
/// (and whenever it may have missed events): until this `Access` has had
/// an answer to its own `vault.status` (or to an end), no session is
/// reported active. **Then, if it says `end_pending`, the app calls
/// [`Access::settle`]**: an end stored before a restart is sent again only
/// by `settle` (or `request`, `end`).
///
/// `Debug` shows only the start of each `unlock_id` (the current one and
/// those lock notices ended), as [`AccessSession`]'s does of its id.
pub struct Access {
    current: Option<AccessSession>,
    /// The current session's margin ([`margin_for`]), from when the vault
    /// last named it.
    margin: TimeDelta,
    /// The vault's `ts` of the last thing applied to `current`.
    learned: Option<DateTime<Utc>>,
    /// Its `seq`, if it had one: at the same `ts`, a lower `seq` is older.
    learned_seq: Option<u64>,
    /// An answer to a `vault.status` this `Access` sent, or to an end, has
    /// come: before it, a grant isn't reported active. (An answer collected
    /// by a poll may be to a request sent before a restart: it doesn't
    /// count.)
    baseline: bool,
    /// How long each attempt waits for its answer.
    timeout: TimeDelta,
    /// What the vault last said of its lock and hold.
    vault: VaultState,
    /// The vault's `ts` and `seq` of the last statement applied to
    /// `vault` (their own order, apart from the session's).
    vault_learned: Option<DateTime<Utc>>,
    vault_learned_seq: Option<u64>,
    /// The current `unlock_id`, from the newest status applied; dropped
    /// once a lock notice names it.
    unlock_id: Option<String>,
    /// `unlock_id`s that lock notices ended, newest last (at most
    /// [`ENDED_KEEP`]): a status naming one never sets `Open`.
    ended: Vec<String>,
    /// A lock or hold notice asked for `vault.status` to be read now
    /// ([`Access::take_status_wanted`]).
    status_wanted: bool,
}

impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Access")
            .field("current", &self.current)
            .field("margin", &self.margin)
            .field("learned", &self.learned)
            .field("learned_seq", &self.learned_seq)
            .field("baseline", &self.baseline)
            .field("timeout", &self.timeout)
            .field("vault", &self.vault)
            .field("vault_learned", &self.vault_learned)
            .field("vault_learned_seq", &self.vault_learned_seq)
            .field("unlock_id", &short_opt(&self.unlock_id))
            .field("ended", &self.ended.iter().map(|e| short_id(e)).collect::<Vec<_>>())
            .field("status_wanted", &self.status_wanted)
            .finish()
    }
}

impl Default for Access {
    fn default() -> Self {
        Self::new()
    }
}

impl Access {
    /// No session known (as after a start: read `vault.status`).
    pub fn new() -> Self {
        Access {
            current: None,
            margin: EXPIRY_MARGIN,
            learned: None,
            learned_seq: None,
            baseline: false,
            timeout: REQUEST_TIMEOUT,
            vault: VaultState::Unknown,
            vault_learned: None,
            vault_learned_seq: None,
            unlock_id: None,
            ended: Vec::new(),
            status_wanted: false,
        }
    }

    /// The same, waiting `timeout` for each answer.
    pub fn with_timeout(timeout: TimeDelta) -> Self {
        Access { timeout, ..Self::new() }
    }

    /// The session last learned from the vault, if any (perhaps expired).
    pub fn current(&self) -> Option<&AccessSession> {
        self.current.as_ref()
    }

    /// Whether this desktop has an access session at `t`: one the vault
    /// named, more than its margin ([`margin_for`]) from its end, and known
    /// since this `Access`'s own `vault.status` (or an end) answered; and
    /// the vault is [`VaultState::Open`] (`due` included). Held, locked or
    /// unknown, no session is live (VAULT-LOCK-PLAN §3.1).
    pub fn active_at(&self, t: DateTime<Utc>) -> bool {
        self.baseline && matches!(self.vault, VaultState::Open { .. }) && self.current.as_ref().is_some_and(|s| s.active_at(t, self.margin))
    }

    /// What the vault last said of its lock and hold.
    pub fn vault(&self) -> &VaultState {
        &self.vault
    }

    /// The current `unlock_id`, if a status named one and no lock notice
    /// has ended it since.
    pub fn unlock_id(&self) -> Option<&str> {
        self.unlock_id.as_deref()
    }

    /// The vault's word that it is open is no longer current (a status
    /// went unanswered, the vault hasn't confirmed it for a while, or the
    /// computer slept): `Open` becomes `Unknown` until a status answers.
    /// `Held` and `Locked` stay (neither is live). The `unlock_id` is kept,
    /// so a lock notice naming it still applies. The app calls it
    /// (VAULT-LOCK-PLAN §3.1).
    pub fn vault_unconfirmed(&mut self) {
        if matches!(self.vault, VaultState::Open { .. }) {
            self.vault = VaultState::Unknown;
        }
    }

    /// A `vault.status` went unanswered: `Open` and `Held` become
    /// `Unknown` (a held vault still answers `vault.status`, §3.6.3, so
    /// silence says it may no longer be held). `Locked` stays: the app
    /// decides whether it is still confirmed (VAULT-LOCK-PLAN §3.1; lead
    /// review L2).
    pub fn status_unanswered(&mut self) {
        if matches!(self.vault, VaultState::Open { .. } | VaultState::Held { .. }) {
            self.vault = VaultState::Unknown;
        }
    }

    /// Whether a lock or hold notice observed since the last call asked
    /// for `vault.status` to be read now ([`AccessEvent::ReadStatus`], or
    /// a notice that didn't check out); cleared by the call.
    pub fn take_status_wanted(&mut self) -> bool {
        std::mem::take(&mut self.status_wanted)
    }

    /// The vault's `ts` of the last statement applied to [`Access::vault`]
    /// (`None`: none yet). An `Unknown` from a statement that didn't check
    /// out, or from the app's decay, doesn't move it.
    pub fn vault_learned_at(&self) -> Option<DateTime<Utc>> {
        self.vault_learned
    }

    fn vault_not_older(&self, at: DateTime<Utc>, seq: Option<u64>) -> bool {
        not_older(self.vault_learned, self.vault_learned_seq, at, seq)
    }

    fn vault_mark(&mut self, at: DateTime<Utc>, seq: Option<u64>) {
        self.vault_learned = Some(at);
        self.vault_learned_seq = seq;
    }

    /// Apply a status's word on the vault, said at `at` with `seq`: older
    /// than what is applied, or naming an `unlock_id` a lock notice ended
    /// (a status from before that lock), it is ignored.
    fn learn_vault(&mut self, at: DateTime<Utc>, seq: Option<u64>, st: VaultStatus) {
        if !self.vault_not_older(at, seq) || st.unlock_id.as_ref().is_some_and(|id| self.ended.contains(id)) {
            return;
        }
        self.vault_mark(at, seq);
        self.unlock_id = st.unlock_id;
        self.vault = st.state;
    }

    /// The vault answered `owner_check_required` at `at`: it is held
    /// (§3.6.3). A hold already known keeps its deadline and counts.
    fn learn_held_answer(&mut self, answer: &Inner) {
        if !hold_answer(answer) || !self.vault_not_older(answer.ts, answer.seq) {
            return;
        }
        self.vault_mark(answer.ts, answer.seq);
        if !matches!(self.vault, VaultState::Held { .. }) {
            self.vault = VaultState::Held { deadline: None, waiting: None, idle_lock_at: None };
        }
    }

    /// Remember that a lock notice ended `id`.
    fn end_unlock(&mut self, id: &str) {
        if !self.ended.iter().any(|e| e == id) {
            self.ended.push(id.to_string());
            if self.ended.len() > ENDED_KEEP {
                self.ended.remove(0);
            }
        }
    }

    /// A `vault.locking` said at `at` with `seq` (§10.2 "Locks").
    fn learn_locking(&mut self, at: DateTime<Utc>, seq: Option<u64>, l: Locking) -> AccessEvent {
        let Some(named) = l.unlock_id else {
            // A notice without `unlock_id` (a vault before release L): the
            // §11.4 time rule needs an unlock result, which a desktop
            // doesn't have. As with none held (owner decision 1,
            // 2026-11-05): Unknown, never Locked, and read the status.
            self.unknown_from_notice(at, seq);
            return AccessEvent::ReadStatus;
        };
        let known = self.ended.contains(&named);
        self.end_unlock(&named);
        match self.unlock_id.as_deref() {
            Some(cur) if cur == named => {
                self.unlock_id = None;
                if self.vault_not_older(at, seq) {
                    self.vault_mark(at, seq);
                    self.vault = VaultState::Locked { since: at, reason: l.reason };
                    AccessEvent::Locked
                } else {
                    // Its unlock is over, but something newer was applied
                    // (the vault opened again and came back held): that
                    // stands, and the status says which unlock is current.
                    AccessEvent::ReadStatus
                }
            }
            // Another unlock's. R1's "MUST ignore" is about confirming a
            // lock: this notice confirms nothing, and Locked is never set
            // on it. But a newer notice of another unlock shows the
            // unlock_id held is out of date, so the vault's word that it is
            // open is no longer current: Unknown until the status, read
            // now, says (lead review M3). An older one changes nothing.
            Some(_) => {
                if self.vault_not_older(at, seq) {
                    self.vault_mark(at, seq);
                    self.vault = VaultState::Unknown;
                }
                AccessEvent::ReadStatus
            }
            // The lock already applied, again: nothing new.
            None if known => AccessEvent::ReadStatus,
            // None held (no status read yet, or a vault before release L):
            // owner decision 1 (2026-11-05): Unknown, never Locked.
            None => {
                self.unknown_from_notice(at, seq);
                AccessEvent::ReadStatus
            }
        }
    }

    /// A lock notice this desktop can't place (none held, or none named):
    /// Unknown in any case (owner decision 1, 2026-11-05), and, when the
    /// notice isn't older than what is applied, its order is marked, so a
    /// status from before it can't set Open again (lead review L1).
    fn unknown_from_notice(&mut self, at: DateTime<Utc>, seq: Option<u64>) {
        if self.vault_not_older(at, seq) {
            self.vault_mark(at, seq);
        }
        self.vault = VaultState::Unknown;
    }

    /// Apply what the vault said at `at` (its `ts`) with `seq`: `Some` a
    /// session, `None` none. Older than what is already applied: ignored.
    /// At the same `ts` (one batch of the vault's), the lower `seq` is the
    /// older; without a `seq` on both, the later to arrive stands. (`seq`
    /// counts per epoch: two messages of one millisecond across a rekey
    /// would compare wrongly; the vault starts a rekey only between
    /// batches.) A session that the
    /// unanswered end will end (the one it names, or any if it names none)
    /// doesn't become current.
    fn learn(&mut self, at: DateTime<Utc>, seq: Option<u64>, session: Option<AccessSession>, pending: Option<&PendingEnd>) {
        if !self.newer(at, seq) {
            return;
        }
        self.learned = Some(at);
        self.learned_seq = seq;
        let before = self.current.as_ref().map(|c| c.session_id.clone());
        self.current = match (session, pending) {
            (Some(s), Some(p)) if p.session_id.as_ref().is_none_or(|n| *n == s.session_id) => None,
            (s, _) => s,
        };
        if let Some(c) = &self.current {
            let new = margin_for(c, at);
            // The same session named again late in its life must not shrink
            // the margin (a desktop clock that is behind would then show it
            // past its end): keep the larger one. A different session gets
            // its own.
            self.margin = if before.as_deref() == Some(c.session_id.as_str()) { self.margin.max(new) } else { new };
        }
    }

    /// Whether what the vault said at `at` with `seq` is not older than what
    /// was applied last.
    fn newer(&self, at: DateTime<Utc>, seq: Option<u64>) -> bool {
        not_older(self.learned, self.learned_seq, at, seq)
    }

    /// Drop the current session if `named` (or any, if `None`) is it.
    fn forget(&mut self, named: Option<&str>) {
        if named.is_none_or(|n| self.current.as_ref().is_some_and(|c| c.session_id == n)) {
            self.current = None;
        }
    }

    /// Ask `vault.status` and apply its `session`. Its answer (to this
    /// request, sent now) is the baseline [`Access::active_at`] needs.
    pub async fn read_status<T: Transport, C: Clock>(&mut self, s: &mut Session<T, C>, store: &mut impl Persist) -> Result<StatusRead, AccessError> {
        // With an `exp` (VAULT-LOCK-PLAN §3.1, lead review): a locked vault
        // collects nothing (§12.1), so unanswered reads wait at the relay;
        // after an unlock the vault drops the stale ones instead of
        // answering them all.
        let answer = s.request_expiring(store, TYPE_STATUS, "{}", self.timeout, self.timeout + STATUS_EXP_MARGIN).await?;
        let session = self.status_answer(s, &answer)?;
        self.baseline = true;
        Ok(StatusRead { session, end_pending: s.access_end().is_some() })
    }

    fn status_answer<T: Transport, C: Clock>(&mut self, s: &Session<T, C>, answer: &Inner) -> Result<StatusSession, AccessError> {
        if let Some(Status::Error { code, .. }) = answer.response.as_ref().map(|r| &r.status) {
            self.learn_held_answer(answer);
            return Err(AccessError::Vault(code.clone()));
        }
        let status = match parse_status(&answer.body) {
            Ok(st) => st,
            Err(e) => {
                // Unreadable: nothing known.
                self.current = None;
                self.vault = VaultState::Unknown;
                return Err(e);
            }
        };
        match parse_vault_status(&answer.body) {
            Ok(v) => self.learn_vault(answer.ts, answer.seq, v),
            // An unlock_id or owner_check that doesn't check out: the
            // vault's state is not known (never "absent"). The session
            // part stands on its own.
            Err(_) => self.vault = VaultState::Unknown,
        }
        match &status {
            StatusSession::Session(x) => self.learn(answer.ts, answer.seq, Some(x.clone()), s.access_end()),
            StatusSession::None => self.learn(answer.ts, answer.seq, None, s.access_end()),
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
        self.request_answered(s, store, seconds).await.map(|(outcome, _)| outcome)
    }

    /// [`Access::request`], also returning the `ts` the vault put on its
    /// answer: a caller that waits for the grant needs it to tell a denial
    /// sent before this request (about an earlier one) from a denial of
    /// this one. The one path for a request: the checks, the ordering rule
    /// and the send are the same here and in [`Access::request`], which
    /// calls this.
    pub async fn request_answered<T: Transport, C: Clock>(
        &mut self,
        s: &mut Session<T, C>,
        store: &mut impl Persist,
        seconds: Option<u32>,
    ) -> Result<(RequestOutcome, DateTime<Utc>), AccessError> {
        if seconds.is_some_and(|n| !(MIN_SECONDS..=MAX_SECONDS).contains(&n)) {
            return Err(AccessError::BadSeconds);
        }
        self.settle(s, store).await?;
        let body = match seconds {
            Some(n) => Builder::new().uint("seconds", u64::from(n)).finish(),
            None => "{}".into(),
        };
        let answer = match s.request(store, TYPE_REQUEST, &body, self.timeout).await {
            Ok(a) => a,
            Err(e) => {
                // #107 (lead decision a): the wait ended. A request still
                // held in the outbox (the relay refused this computer's
                // clock, or couldn't be reached) is dropped and reported, so
                // no stale prompt reaches the phone once it gets through.
                let _ = s.withdraw_held(store, TYPE_REQUEST);
                return Err(e.into());
            }
        };
        // Refused while held (§3.6.3): the vault is held.
        self.learn_held_answer(&answer);
        Ok((parse_request_answer(&answer)?, answer.ts))
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
            Settled::Moot => Ok(EndOutcome::Replaced),
            Settled::Clear | Settled::Answered | Settled::StatusNull => Ok(EndOutcome::Ended),
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
            let status = self.read_status(s, store).await?.session;
            match (status, &p.session_id) {
                (StatusSession::None, _) => {
                    s.set_access_end(store, None)?;
                    return Ok(Settled::StatusNull);
                }
                (StatusSession::Absent, _) => {
                    s.set_access_end(store, None)?;
                    return Ok(Settled::OldVault);
                }
                // SPEC: §6.8 "Ending" (0.82.5) covers an unanswered end that
                // names the session vault.status shows, not one that names S1
                // while vault.status shows another, S2. Owner decision
                // 2026-11-03: a resend after a named end names only that same
                // session; a different current session releases the request
                // (the lead's next VAULT-MESSAGING erratum clarifies §6.8). So
                // S2 is left running: an end of S1 can't change anything any
                // more (the vault answers an end of a session that isn't
                // current `{}`). Test:
                // `spec_question_named_end_of_a_replaced_session_is_moot`.
                (StatusSession::Session(cur), Some(named)) if *named != cur.session_id => {
                    s.set_access_end(store, None)?;
                    return Ok(Settled::Moot);
                }
                // The session it named is still current, or it named none and
                // one is current (§6.8 "If it names a session", read as
                // vault.status's session): sent again under a new id, naming
                // that session. The vault ends all of the device's access for
                // an end of its current session (vault/access.go
                // hSessionEnd), and a named end, if delayed, can't end a later
                // session.
                (StatusSession::Session(cur), _) => {
                    if reissued {
                        return Err(AccessError::EndUnconfirmed);
                    }
                    reissued = true;
                    let id = s.new_id()?;
                    s.set_access_end(store, Some(PendingEnd { id, session_id: Some(cur.session_id), attempts: 0 }))?;
                }
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
        self.learn_held_answer(answer);
        let ok = empty_ok(answer);
        if ok.is_ok() || ok == Err(AccessError::Malformed) {
            // Ended (or never current): from the vault's ts of the answer,
            // what it named isn't current. A malformed `ok` is still an ok.
            self.baseline = true;
            self.forget(p.session_id.as_deref());
            if self.newer(answer.ts, answer.seq) {
                self.learned = Some(answer.ts);
                self.learned_seq = answer.seq;
            }
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
            // `owner_check_required` to any request: the vault is held
            // (§3.6.3).
            self.learn_held_answer(m);
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
        // The vault's lock and hold (§10.2). One that doesn't check out
        // leaves the state unknown (fail secure): read the status.
        match m.kind.as_str() {
            TYPE_LOCKING => {
                let r = match parse_locking(&m.body) {
                    Ok(l) => Ok(Some(self.learn_locking(m.ts, m.seq, l))),
                    Err(e) => {
                        self.vault = VaultState::Unknown;
                        Err(e)
                    }
                };
                if !matches!(r, Ok(Some(AccessEvent::Locked))) {
                    self.status_wanted = true;
                }
                return r;
            }
            TYPE_HELD => {
                return match parse_held(&m.body) {
                    Ok(held) => {
                        // The newest by ts (§3.6.3 "A device keeps the
                        // newest by ts").
                        if self.vault_not_older(m.ts, m.seq) {
                            self.vault_mark(m.ts, m.seq);
                            self.vault = held;
                        }
                        Ok(Some(AccessEvent::Held))
                    }
                    Err(e) => {
                        self.vault = VaultState::Unknown;
                        self.status_wanted = true;
                        Err(e)
                    }
                };
            }
            _ => {}
        }
        // Session events below never change the vault's state (§3.6.3).
        let Some(event) = parse_event(m) else { return Ok(None) };
        match &event {
            Ok(AccessEvent::Granted(g)) => self.learn(m.ts, m.seq, Some(g.clone()), s.access_end()),
            Ok(AccessEvent::Ended) => self.learn(m.ts, m.seq, None, s.access_end()),
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
