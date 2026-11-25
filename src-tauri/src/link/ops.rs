//! Vault operations over the link (DESKTOP-REWORK-PLAN Phase 5, 5.2): a
//! request of a type the vault answers for a desktop with an access
//! session (VAULT-MESSAGING §6.8, §10), its answer's body, and why one
//! fails, said plainly. Nothing is sent without a session live as the
//! screen shows it; nothing is claimed that the vault didn't answer.
//!
//! Answers can carry personal data (names, profiles): they are kept in
//! memory for the caller only, and never logged (logs carry types and
//! codes).

use chrono::{DateTime, TimeDelta, Utc};
use tokio::sync::Mutex;
use vettid_device::access::{VaultState, OWNER_CHECK_REQUIRED};
use vettid_device::pairing::Clock;
use vettid_device::session::SessionError;
use vettid_device::transport::Transport;
use vettid_vms::envelope::{Status, MAX_CLOCK_SKEW_FUTURE};
use zeroize::Zeroizing;

use super::shape::BadShape;
use super::{clock_notice, clock_offset, Link, Snapshot, NOT_SAVED_NOTICE, PAIRED_NO_ACCESS_NOTICE, REFUSED_NOTICE, VAULT_HELD_NOTICE, VAULT_LOCKED_NOTICE, VAULT_UNKNOWN_NOTICE};

/// How long an operation waits for its answer (chosen; not in the spec).
pub const OP_TIMEOUT: TimeDelta = TimeDelta::seconds(6);

/// The longest an operation holds the link, everything included (its
/// deposit, its collects), chosen under the 10 s a log-out waits for the
/// link to end the session at the vault. Past it the operation is
/// unconfirmed ([`OpError::Unconfirmed`]), never "not done".
pub const OP_HOLD_MAX: std::time::Duration = std::time::Duration::from_secs(8);

/// How long a change stays valid at the vault (`exp`, §8.5): one not
/// delivered by then is dropped, so "unconfirmed" means "within this",
/// plus [`KEPT_MARGIN`].
pub const CHANGE_TTL: TimeDelta = TimeDelta::minutes(2);

/// How long past its `exp`, by this computer's clock, a kept change is
/// still taken as able to arrive: the vault judges `exp` by its own clock,
/// which may be behind this one. The clock skew a receiver allows (§8.4:
/// a `ts` up to 5 minutes ahead, [`MAX_CLOCK_SKEW_FUTURE`]), as
/// `Session::arm` keeps a request's id for its answer until `exp` plus
/// the same, and as §8.6 has a device wait for a `vault.lock` until "its
/// own `exp` plus a margin". Only past it is a kept change forgotten
/// ([`OpError::UnconfirmedExpired`]).
pub const KEPT_MARGIN: TimeDelta = MAX_CLOCK_SKEW_FUTURE;
/// The same for a read: an answer this late is of no use.
pub const READ_TTL: TimeDelta = TimeDelta::seconds(30);

/// NEW TEXT (owner approval needed): a change sent, or stored to be sent,
/// but not answered in time: it may still be carried out within
/// [`CHANGE_TTL`].
pub const OP_UNCONFIRMED_NOTICE: &str = "Your vault hasn't confirmed this yet. It may still happen in the next few minutes: refresh then to see.";
/// NEW TEXT (owner approval needed): a kept change still unconfirmed, and
/// this desktop can't reach the vault now (not sent, no session):
/// [`OpError::UnconfirmedFor`].
pub const OP_UNCONFIRMED_UNREACHABLE_NOTICE: &str = "Your vault hasn't confirmed this yet, and this desktop can't reach it now. It may still happen in the next few minutes.";
/// NEW TEXT (owner approval needed): said after the lock's, the hold's or
/// the clock's own text, for a change still unconfirmed
/// ([`OpError::UnconfirmedFor`]).
pub const OP_UNCONFIRMED_AFTER_NOTICE: &str = "Your vault hasn't confirmed this yet; it may still happen in the next few minutes.";
/// NEW TEXT (owner approval needed): it couldn't be sent at all.
pub const OP_NOT_SENT_NOTICE: &str = "This desktop couldn't send this to your vault. Try again.";

/// NEW TEXT (owner approval needed): the vault refused the operation for
/// a desktop (`forbidden`): it is the phone's.
pub const OP_FORBIDDEN_NOTICE: &str = "This is done on your phone.";
/// NEW TEXT (owner approval needed): `not_found`.
pub const OP_NOT_FOUND_NOTICE: &str = "Your vault doesn't have this any more. Refresh to see what it has now.";
/// NEW TEXT (owner approval needed): any other error answer.
pub const OP_FAILED_NOTICE: &str = "Your vault couldn't do this. Try again.";
/// NEW TEXT (owner approval needed): a change left unconfirmed past its
/// `exp` ([`OpError::UnconfirmedExpired`]): it was done by then or never
/// will be, and only a fresh read tells which.
pub const OP_UNCONFIRMED_EXPIRED_NOTICE: &str = "Your vault didn't confirm this in time. Refresh to see whether it was done before you try again.";
/// NEW TEXT (owner approval needed): a change the vault answered `ok`, with
/// an answer this desktop couldn't read ([`OpError::AnswerUnreadable`]).
pub const OP_ANSWER_UNREADABLE_NOTICE: &str = "Your vault did this, but this desktop couldn't read its answer. Refresh to see it.";
/// NEW TEXT (owner approval needed): a new message held back while the one
/// before it is unconfirmed ([`OpError::EarlierUnconfirmed`]).
pub const OP_EARLIER_UNCONFIRMED_NOTICE: &str = "Your vault hasn't confirmed your previous message yet, so this one wasn't sent.";

/// Why a vault operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    /// No access session live as the screen shows it (or the vault said
    /// `session_required`): nothing was sent, or nothing done.
    NoSession,
    /// The vault is held (§3.6.3): nothing is done until the daily check.
    Held,
    /// The vault is locked.
    Locked,
    /// Whether the vault is open isn't known: nothing was sent.
    Unknown,
    /// Sent, or stored and sent later, with no answer in time: it may still
    /// be carried out (within its `exp`). Never "not done".
    Unconfirmed,
    /// The relay refused this computer's clock (`timestamp_stale`): the
    /// relay's date, if it gave one.
    Clock(Option<i64>),
    /// The device state couldn't be saved: nothing was sent.
    NotSaved,
    /// It couldn't be sealed or queued: nothing was sent.
    NotSent,
    /// The vault's mailbox refuses this device (§8.6).
    Refused,
    /// The vault answered with an error code (§10.1).
    Vault(String),
    /// An answer that isn't what the spec says.
    Malformed,
    /// The desktop's own call was wrong (an empty id): nothing was sent.
    BadArgument,
    /// A page asked for with `before` that the vault no longer holds
    /// (`not_found`, §10.5.2): the view starts again from the newest page.
    PageGone,
    /// A kept change ([`Link::op_kept_first`]) was retried first and is
    /// still unconfirmed, so this one wasn't sent.
    EarlierUnconfirmed,
    /// A retry of a kept change, or a change that may have gone, that got
    /// no answer for this reason (not sent, the clock, a lock, a hold): it
    /// stays unconfirmed and kept. Its code is `unconfirmed`; its notice
    /// names the reason.
    UnconfirmedFor(Box<OpError>),
    /// A kept change past its `exp`, forgotten now: it was carried out by
    /// then or never will be. The view reads again before a new request.
    UnconfirmedExpired,
    /// A change the vault answered `ok`, whose answer doesn't check out:
    /// it was done. The view reads again; nothing is retried.
    AnswerUnreadable,
}

impl OpError {
    /// What the person is told.
    pub fn notice(&self) -> String {
        match self {
            OpError::NoSession => PAIRED_NO_ACCESS_NOTICE.into(),
            OpError::Held => VAULT_HELD_NOTICE.into(),
            OpError::Locked => VAULT_LOCKED_NOTICE.into(),
            OpError::Unknown => VAULT_UNKNOWN_NOTICE.into(),
            OpError::Unconfirmed => OP_UNCONFIRMED_NOTICE.into(),
            OpError::Clock(d) => clock_notice(clock_offset(*d)),
            OpError::NotSaved => NOT_SAVED_NOTICE.into(),
            OpError::NotSent => OP_NOT_SENT_NOTICE.into(),
            OpError::EarlierUnconfirmed => OP_EARLIER_UNCONFIRMED_NOTICE.into(),
            // Never the cause's own "try again" or "couldn't send": it may
            // still happen.
            OpError::UnconfirmedFor(e) => match **e {
                OpError::Locked | OpError::Held | OpError::Clock(_) => format!("{} {}", e.notice(), OP_UNCONFIRMED_AFTER_NOTICE),
                _ => OP_UNCONFIRMED_UNREACHABLE_NOTICE.into(),
            },
            OpError::UnconfirmedExpired => OP_UNCONFIRMED_EXPIRED_NOTICE.into(),
            OpError::AnswerUnreadable => OP_ANSWER_UNREADABLE_NOTICE.into(),
            OpError::Refused => REFUSED_NOTICE.into(),
            OpError::Vault(c) if c == "forbidden" => OP_FORBIDDEN_NOTICE.into(),
            OpError::Vault(c) if c == "not_found" => OP_NOT_FOUND_NOTICE.into(),
            // A notice, for completeness; the view starts again from the
            // newest page without showing it.
            OpError::PageGone => OP_NOT_FOUND_NOTICE.into(),
            OpError::Vault(_) | OpError::Malformed | OpError::BadArgument => OP_FAILED_NOTICE.into(),
        }
    }

    /// Whether it says "unconfirmed": a change that may still be carried
    /// out, kept under its id.
    pub fn is_unconfirmed(&self) -> bool {
        matches!(self, OpError::Unconfirmed | OpError::UnconfirmedFor(_))
    }

    /// A stable code for the frontend (it never matches on the text).
    pub fn code(&self) -> &'static str {
        match self {
            OpError::NoSession => "no_session",
            OpError::Held => "held",
            OpError::Locked => "locked",
            OpError::Unknown => "unknown",
            OpError::Unconfirmed | OpError::UnconfirmedFor(_) => "unconfirmed",
            OpError::UnconfirmedExpired => "unconfirmed_expired",
            OpError::AnswerUnreadable => "answer_unreadable",
            OpError::Clock(_) => "clock",
            OpError::NotSaved => "not_saved",
            OpError::NotSent => "not_sent",
            OpError::Refused => "refused",
            OpError::Vault(c) if c == "forbidden" => "forbidden",
            OpError::Vault(c) if c == "not_found" => "not_found",
            OpError::Vault(c) if c == "connection_unavailable" => "connection_unavailable",
            OpError::Vault(_) => "vault_error",
            OpError::Malformed => "malformed",
            OpError::BadArgument => "bad_argument",
            OpError::PageGone => "page_gone",
            OpError::EarlierUnconfirmed => "earlier_unconfirmed",
        }
    }
}

impl<T: Transport, C: Clock> Link<T, C> {
    /// Why no operation can be sent now, if one can't: no session live
    /// as the screen shows it, and what the vault's state says of that.
    fn not_open_for_an_op(&self) -> Option<OpError> {
        if self.refused() {
            return Some(OpError::Refused);
        }
        if self.views_live(Utc::now()) {
            return None;
        }
        Some(match self.access.vault() {
            VaultState::Held { .. } => OpError::Held,
            VaultState::Locked { .. } => OpError::Locked,
            VaultState::Unknown => OpError::Unknown,
            VaultState::Open { .. } => OpError::NoSession,
        })
    }

    /// Send `kind` with `body` (a JSON object) and wait up to
    /// [`OP_TIMEOUT`] for its answer: its body, checked by `shape`. Only
    /// while a session is live as the link knows it (the caller checks
    /// what the screen shows). A sleep is looked for first.
    ///
    /// - A change (`change`) carries an `exp` of [`CHANGE_TTL`], a read
    ///   one of [`READ_TTL`]. Each call is a new request: a change is
    ///   retried under its id only when asked to ([`Link::op_retry`],
    ///   [`Link::op_kept_first`]), never because the same body came again.
    /// - Once the request is stored, any failure is
    ///   [`OpError::Unconfirmed`], and a change is kept to be retried under
    ///   its id: it goes with the next exchange. A `message.send` is never
    ///   stored (its body is plaintext, `vettid_device::session::memory_only`):
    ///   it is unconfirmed and kept once the relay may have taken it; one the
    ///   relay certainly didn't take is [`OpError::NotSent`]. A change that
    ///   may have gone stays unconfirmed when the same exchange showed a lock
    ///   or a hold ([`OpError::UnconfirmedFor`]); a read is said as the lock
    ///   or the hold.
    /// - A change answered `ok` with a body that doesn't check out was
    ///   done: [`OpError::AnswerUnreadable`], never "try again".
    /// - `owner_check_required` is learned as the hold (§3.6.3);
    ///   `session_required` takes the session as unconfirmed.
    /// - A read answered while the batch it came in also showed a lock,
    ///   a hold or an end is dropped: the state's error instead. A change
    ///   the vault confirmed is reported done.
    /// - One change is kept at a time: another change left unconfirmed
    ///   takes its place (the first still goes with the next exchange, but
    ///   its answer is no longer looked for). [`Link::op_kept_first`]
    ///   retries the kept one first.
    pub async fn op(&mut self, kind: &str, body: &serde_json::Value, shape: impl Fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>, change: bool) -> Result<serde_json::Value, OpError> {
        self.op_as(kind, body, shape, change, None).await
    }

    /// [`Link::op`]; with `retry`, that kept change again, under its id and
    /// first `exp` (even past it: the vault dedupes or drops it), with its
    /// own body (`body` is then unused), never a new request.
    ///
    /// - A retry that gets no answer from the vault, for any reason (not
    ///   sent, the clock, a lock or a hold before or during it), stays
    ///   unconfirmed and kept ([`OpError::UnconfirmedFor`]): the first try
    ///   may have gone.
    /// - A retry the vault answers with an error is settled, not done
    ///   ([`OpError::Vault`]): the answer may be the vault's cached one
    ///   (§8.2), from when it was first sent, so it says nothing of the
    ///   session or the hold now (a `session_required` doesn't end the
    ///   screen's session).
    async fn op_as(&mut self, kind: &str, body: &serde_json::Value, shape: impl Fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>, change: bool, retry: Option<Pending>) -> Result<serde_json::Value, OpError> {
        self.check_gap(Utc::now());
        let is_retry = retry.is_some();
        if let Some(e) = self.not_open_for_an_op() {
            return Err(still_unconfirmed(is_retry, e));
        }
        let now = Utc::now();
        // SECURITY: a change's body can carry message plaintext: this copy
        // and the kept one are wiped.
        let body = match &retry {
            Some(p) => p.body.clone().ok_or(OpError::UnconfirmedExpired)?,
            None => Zeroizing::new(body.to_string()),
        };
        let (id, exp, retries) = match &retry {
            Some(p) => (Some(p.id.clone()), p.exp, p.retries + 1),
            None => (None, now + if change { CHANGE_TTL } else { READ_TTL }, 0),
        };
        let connection_id = match &retry {
            Some(p) => p.connection_id.clone(),
            None => named(&body),
        };
        let pending = |id: String| Pending { kind: kind.to_string(), body: Some(body.clone()), id, exp, retries, connection_id: connection_id.clone() };
        if change {
            self.sending = Some(pending(id.clone().unwrap_or_default()));
        }
        let r = self.session.request_at(&mut self.store, id.as_deref(), kind, &body, OP_TIMEOUT, exp).await;
        self.sending = None;
        let stored = self.session.last_request_id().map(str::to_string);
        // A sleep during the wait: found before the answer counts.
        self.check_gap(Utc::now());
        self.drain_held();
        let out = match r {
            Ok(m) => {
                self.reachable = true;
                self.vault_answered();
                if change {
                    self.unconfirmed = None;
                }
                let e = self.access.observe(&mut self.session, &mut self.store, &m);
                self.noted(&e);
                match m.response.as_ref().map(|r| &r.status) {
                    Some(Status::Ok) => match serde_json::from_str::<serde_json::Value>(&m.body).ok().map(|v| shape(&v)) {
                        Some(Ok(v)) => Ok(v),
                        _ => {
                            log::warn!("link: {} answered with a body that doesn't check out ({} bytes)", kind, m.body.len());
                            // A change answered ok was done: never "try again".
                            Err(if change { OpError::AnswerUnreadable } else { OpError::Malformed })
                        }
                    },
                    Some(Status::Error { code, .. }) => {
                        log::info!("link: {} answered {}", kind, code);
                        Err(match code.as_str() {
                            // Settled, not done; maybe the cached answer.
                            c if is_retry => {
                                if c == OWNER_CHECK_REQUIRED {
                                    // A status read tells whether the hold is on now.
                                    self.read_now = true;
                                }
                                OpError::Vault(c.to_string())
                            }
                            OWNER_CHECK_REQUIRED => {
                                // Read the status now, for the hold's
                                // deadline and counts; nothing queued is
                                // shown.
                                self.read_now = true;
                                self.inbound.clear_changed();
                                OpError::Held
                            }
                            "session_required" => {
                                self.confirmed = None;
                                self.read_now = true;
                                self.inbound.clear_changed();
                                OpError::NoSession
                            }
                            c => OpError::Vault(c.to_string()),
                        })
                    }
                    None => Err(if change { OpError::AnswerUnreadable } else { OpError::Malformed }),
                }
            }
            Err(SessionError::Refused) => Err(OpError::Refused),
            Err(e) => {
                log::info!("link: {}: {}", kind, e);
                // The relay refused this computer's clock: said so, stored
                // or not (a stored change is kept, and goes once the clock
                // is right, within its exp).
                if let Some(d) = e.clock_skew() {
                    if let (true, Some(id)) = (change, stored) {
                        self.keep(pending(id));
                    }
                    return Err(still_unconfirmed(is_retry, OpError::Clock(d)));
                }
                match stored {
                    // Stored: it goes with the next exchange (until exp).
                    Some(id) => {
                        if matches!(e, SessionError::Relay(_) | SessionError::TimedOut) {
                            self.reachable = false;
                        }
                        if change {
                            self.keep(pending(id));
                        }
                        Err(OpError::Unconfirmed)
                    }
                    None => Err(still_unconfirmed(
                        is_retry,
                        match &e {
                            SessionError::Store(_) => OpError::NotSaved,
                            _ => OpError::NotSent,
                        },
                    )),
                }
            }
        };
        // What the same exchange showed of the vault or the session.
        let out = match out {
            // A change that may have gone stays unconfirmed, said with the
            // lock or the hold; a read's is said as the lock or the hold.
            Err(OpError::Unconfirmed) => Err(match self.not_open_for_an_op().filter(|e| *e != OpError::NoSession) {
                Some(e) if change => OpError::UnconfirmedFor(Box::new(e)),
                Some(e) => e,
                None => OpError::Unconfirmed,
            }),
            // A read isn't handed on once the session isn't live.
            Ok(_) if !change && !self.views_live(Utc::now()) => Err(self.not_open_for_an_op().unwrap_or(OpError::NoSession)),
            o => o,
        };
        self.note_refused().await;
        out
    }

    /// Keep `p` as the unconfirmed change, and note that this call kept it
    /// (its answer carries its id, [`Ran::pending`]).
    fn keep(&mut self, p: Pending) {
        self.kept_now = Some(p.id.clone());
        self.unconfirmed = Some(p);
    }

    /// Retry the kept change of `kind` whose request id is `pending_id`
    /// (and whose body names `connection_id`, if given), under that id and
    /// its first `exp`, with its own body. Nothing is sent when:
    /// - it isn't the kept one (settled, forgotten, or never kept here):
    ///   [`OpError::UnconfirmedExpired`], since only a read tells what
    ///   became of it;
    /// - its `exp` plus [`KEPT_MARGIN`] has passed: forgotten, and the same;
    /// - it was retried [`MAX_RETRIES`] times already (§8.6): it stays
    ///   kept and unconfirmed until then.
    pub async fn op_retry(&mut self, kind: &str, pending_id: &str, connection_id: Option<&str>, shape: impl Fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>) -> Result<serde_json::Value, OpError> {
        let now = Utc::now();
        self.forget_spent(now);
        let Some(p) = self.unconfirmed.clone().filter(|p| p.kind == kind && p.id == pending_id && connection_id.is_none_or(|c| p.connection_id.as_deref() == Some(c))) else {
            return Err(OpError::UnconfirmedExpired);
        };
        if now >= p.exp + KEPT_MARGIN {
            self.unconfirmed = None;
            return Err(OpError::UnconfirmedExpired);
        }
        if p.retries >= MAX_RETRIES {
            self.kept_now = Some(p.id);
            return Err(OpError::Unconfirmed);
        }
        let r = self.op_as(kind, &serde_json::Value::Null, shape, true, Some(p.clone())).await;
        if self.unconfirmed.as_ref().is_some_and(|q| q.id == p.id) {
            self.kept_now = Some(p.id);
        }
        r
    }

    /// The kept change's body goes once its `exp` plus [`KEPT_MARGIN`] has
    /// passed: it can't arrive any more, and a retry would be a new
    /// request. Its id, kind and `exp` stay, for the one answer that says
    /// so ([`OpError::UnconfirmedExpired`]). Run on every link tick (a
    /// refresh, a collect, an operation), so message plaintext isn't held
    /// past that time, also after the session ended, a lock or a hold.
    pub(super) fn forget_spent(&mut self, now: DateTime<Utc>) {
        if let Some(p) = self.unconfirmed.as_mut().filter(|p| now >= p.exp + KEPT_MARGIN) {
            p.body = None;
        }
    }
}

/// A failure that isn't the vault's answer: for a retry (`retry`) the kept
/// change may have gone, so it stays unconfirmed, said with its cause. A
/// refused device is said as such.
fn still_unconfirmed(retry: bool, e: OpError) -> OpError {
    match e {
        OpError::Refused => e,
        e if retry => OpError::UnconfirmedFor(Box::new(e)),
        e => e,
    }
}

/// The `connection_id` member of a change's body, if it has one (only the
/// id is read; a message's text is skipped).
fn named(body: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Named {
        connection_id: String,
    }
    serde_json::from_str::<Named>(body).map(|n| n.connection_id).ok()
}

/// How many times a change is retried under its id (§8.6: "Application
/// retries reuse the inner `id`, at most twice").
pub const MAX_RETRIES: u32 = 2;

/// A change sent and not confirmed: retried under its id, with its first
/// `exp`, at most [`MAX_RETRIES`] times. Its body is dropped once its `exp`
/// plus [`KEPT_MARGIN`] has passed ([`Link::forget_spent`]). `Debug`
/// leaves the body out (message plaintext).
#[derive(Clone)]
pub struct Pending {
    kind: String,
    body: Option<Zeroizing<String>>,
    id: String,
    exp: DateTime<Utc>,
    /// The retries under `id` so far.
    retries: u32,
    /// The body's `connection_id`, kept apart so it outlives the body.
    connection_id: Option<String>,
}

impl Pending {
    /// Until when it may still arrive, by this computer's clock: `exp`
    /// plus [`KEPT_MARGIN`].
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.exp + KEPT_MARGIN
    }
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("kind", &self.kind)
            .field("body_len", &self.body.as_ref().map(|b| b.len()))
            .field("id", &self.id)
            .field("exp", &self.exp)
            .field("retries", &self.retries)
            .finish_non_exhaustive()
    }
}

/// What became of a kept change retried before a new one
/// ([`Link::op_kept_first`]): its request id (the `pending_id` the view
/// matches its message by), its connection, until when it could arrive,
/// and its answer, or [`OpError::Unconfirmed`] while it is still not
/// confirmed. No body. `Debug` leaves the answer's body out.
#[derive(Clone, PartialEq, Eq)]
pub struct Earlier {
    pub id: String,
    pub connection_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub result: Result<serde_json::Value, OpError>,
}

impl std::fmt::Debug for Earlier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Earlier").field("id", &self.id).field("error", &self.result.as_ref().err()).finish_non_exhaustive()
    }
}

impl<T: Transport, C: Clock> Link<T, C> {
    /// A new change, sent after the kept change of the same `kind`, if
    /// there is one (whatever its body: the same text twice is two
    /// messages): that one is retried first, under its id and first `exp`,
    /// so that it is never dropped unseen, and what became of it is kept in
    /// `earlier` for the caller.
    /// - While it stays unconfirmed, or nothing could be sent, this change
    ///   isn't sent: [`OpError::EarlierUnconfirmed`], or the error that
    ///   would have stopped this one too.
    /// - Retried [`MAX_RETRIES`] times already and still within its `exp`
    ///   and [`KEPT_MARGIN`], it isn't retried, and this one waits
    ///   ([`OpError::EarlierUnconfirmed`]).
    /// - Past its `exp` but within the margin it is still retried under its
    ///   id (the vault dedupes or drops it).
    /// - Past both it is forgotten, reported
    ///   [`OpError::UnconfirmedExpired`] (only a read tells whether it
    ///   happened), and this one goes.
    pub async fn op_kept_first(&mut self, kind: &str, body: &serde_json::Value, shape: impl Fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>) -> Result<serde_json::Value, OpError> {
        self.earlier = None;
        let now = Utc::now();
        self.forget_spent(now);
        if let Some(p) = self.unconfirmed.clone().filter(|p| p.kind == kind) {
            let told = |result| Earlier { id: p.id.clone(), connection_id: p.connection_id.clone(), expires_at: p.expires_at(), result };
            // Unconfirmed until its answer is in (a cut-off leaves it so).
            self.earlier = Some(told(Err(OpError::Unconfirmed)));
            if now >= p.expires_at() {
                self.unconfirmed = None;
                self.earlier = Some(told(Err(OpError::UnconfirmedExpired)));
            } else if p.retries >= MAX_RETRIES {
                return Err(OpError::EarlierUnconfirmed);
            } else {
                let r = self.op_as(kind, body, &shape, true, Some(p.clone())).await;
                // Its id goes in `earlier`, not as this one's.
                self.kept_now = None;
                match r {
                    Err(e) if self.unconfirmed.as_ref().is_some_and(|q| q.id == p.id) => {
                        return Err(match e {
                            OpError::Unconfirmed => OpError::EarlierUnconfirmed,
                            // Not sent for a reason that stops this one too.
                            OpError::UnconfirmedFor(e) => *e,
                            e => e,
                        });
                    }
                    r => self.earlier = Some(told(r)),
                }
            }
        }
        self.op_as(kind, body, &shape, true, None).await
    }
}

impl<T: Transport, C: Clock> Link<T, C> {
    /// An operation's wait was cut off (its bound, or a reset): a change
    /// that was stored is kept as unconfirmed, to be retried under its id.
    /// What the operation is told:
    /// - cut off while the kept change before it was retried
    ///   ([`Link::op_kept_first`]): [`OpError::EarlierUnconfirmed`], since
    ///   it wasn't sent itself;
    /// - cut off before anything of it was stored or deposited (in
    ///   `request_once`'s flush, say): [`OpError::NotSent`], or for a retry
    ///   [`OpError::UnconfirmedFor`] (the kept change stays);
    /// - otherwise [`OpError::Unconfirmed`].
    fn cut_off(&mut self) -> OpError {
        let sending = self.sending.take();
        let retry = sending.as_ref().is_some_and(|p| !p.id.is_empty());
        let earlier_retry = retry && sending.as_ref().is_some_and(|p| self.earlier.as_ref().is_some_and(|e| e.id == p.id));
        let stored = self.session.last_request_id().map(str::to_string);
        let reached = sending.is_some() && stored.is_some();
        if let (Some(mut p), Some(id)) = (sending.clone(), stored) {
            p.id = id;
            if earlier_retry {
                self.unconfirmed = Some(p);
            } else {
                self.keep(p);
            }
        } else if let Some(p) = sending.as_ref().filter(|_| retry && !earlier_retry) {
            // Not tried this time: still kept as it was.
            if self.unconfirmed.as_ref().is_some_and(|q| q.id == p.id) {
                self.kept_now = Some(p.id.clone());
            }
        }
        match (earlier_retry, sending.is_some(), reached, retry) {
            (true, ..) => OpError::EarlierUnconfirmed,
            (false, true, false, true) => OpError::UnconfirmedFor(Box::new(OpError::NotSent)),
            (false, true, false, false) => OpError::NotSent,
            _ => OpError::Unconfirmed,
        }
    }
}

/// An operation as a command runs it: only while the screen shows a live
/// session (`screen_live`) and no End session, lock or log-out has started
/// (`overtaken`); with the link held for at most [`OP_HOLD_MAX`], and let
/// go at once when a reset starts (`stop` completes: the reset gets the
/// link without waiting); then what
/// the link learned is published (`publish`, under the link's lock, so it
/// is ordered with every other holder's), unless a reset came first. Then
/// a read's answer isn't handed on; a change the vault confirmed is still
/// reported done.
#[allow(clippy::too_many_arguments)]
pub async fn link_op_with<T: Transport, C: Clock>(
    link: &Mutex<Option<Link<T, C>>>,
    screen_live: impl Fn() -> bool,
    overtaken: impl Fn() -> bool,
    publish: impl Fn(Snapshot),
    stop: impl std::future::Future<Output = ()>,
    kind: &str,
    body: serde_json::Value,
    shape: impl Fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>,
    change: bool,
) -> Result<serde_json::Value, OpError> {
    let how = if change { How::Change } else { How::Read };
    link_run_with(link, screen_live, overtaken, publish, stop, kind, body, shape, how).await.result
}

/// How [`link_run_with`] sends: a read or a change ([`Link::op`]), a new
/// change after the kept one ([`Link::op_kept_first`]), or a retry of the
/// kept change by its request id ([`Link::op_retry`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum How {
    Read,
    Change,
    KeptFirst,
    Retry { pending_id: String, connection_id: String },
}

/// What [`link_run_with`] answers. `Debug` leaves the answer's body out
/// (it can be a page of messages).
pub struct Ran {
    pub result: Result<serde_json::Value, OpError>,
    /// With [`How::KeptFirst`]: what became of the kept change retried
    /// first, if there was one.
    pub earlier: Option<Earlier>,
    /// When this change is kept (unconfirmed, or a clock refusal of one
    /// stored): its request id, an opaque token the view matches its
    /// message by, and until when it may arrive ([`Pending::expires_at`]).
    pub pending: Option<(String, DateTime<Utc>)>,
}

impl std::fmt::Debug for Ran {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ran").field("error", &self.result.as_ref().err()).field("earlier", &self.earlier).field("pending", &self.pending).finish_non_exhaustive()
    }
}

/// [`link_op_with`], with the [`Ran`] details.
#[allow(clippy::too_many_arguments)]
pub async fn link_run_with<T: Transport, C: Clock>(
    link: &Mutex<Option<Link<T, C>>>,
    screen_live: impl Fn() -> bool,
    overtaken: impl Fn() -> bool,
    publish: impl Fn(Snapshot),
    stop: impl std::future::Future<Output = ()>,
    kind: &str,
    body: serde_json::Value,
    shape: impl Fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>,
    how: How,
) -> Ran {
    let change = how != How::Read;
    let none = || Ran { result: Err(OpError::NoSession), earlier: None, pending: None };
    if overtaken() || !screen_live() {
        return none();
    }
    let mut slot = link.lock().await;
    let Some(l) = slot.as_mut() else { return none() };
    if overtaken() {
        return none();
    }
    l.earlier = None;
    l.kept_now = None;
    let r = {
        let run = async {
            match &how {
                How::KeptFirst => l.op_kept_first(kind, &body, shape).await,
                How::Retry { pending_id, connection_id } => l.op_retry(kind, pending_id, Some(connection_id), shape).await,
                How::Read | How::Change => l.op(kind, &body, shape, change).await,
            }
        };
        tokio::select! {
            r = tokio::time::timeout(OP_HOLD_MAX, run) => r.map_err(|_| "held the link too long"),
            () = stop => Err("stopped for a reset"),
        }
    };
    let r = match r {
        Ok(r) => r,
        Err(why) => {
            log::info!("link: {} {}; it may still be carried out", kind, why);
            Err(l.cut_off())
        }
    };
    let earlier = l.earlier.take();
    let pending = l.kept_now.take().and_then(|id| l.unconfirmed.as_ref().filter(|p| p.id == id).map(|p| (p.id.clone(), p.expires_at())));
    if overtaken() {
        let result = match r {
            Ok(v) if change => Ok(v),
            Ok(_) => Err(OpError::NoSession),
            e => e,
        };
        return Ran { result, earlier, pending };
    }
    publish(l.snapshot(Utc::now()));
    Ran { result: r, earlier, pending }
}

#[cfg(test)]
mod tests;
