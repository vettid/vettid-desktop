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
use vettid_vms::envelope::Status;
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
/// delivered by then is dropped, so "unconfirmed" means "within this".
pub const CHANGE_TTL: TimeDelta = TimeDelta::minutes(2);
/// The same for a read: an answer this late is of no use.
pub const READ_TTL: TimeDelta = TimeDelta::seconds(30);

/// NEW TEXT (owner approval needed): a change sent, or stored to be sent,
/// but not answered in time: it may still be carried out within
/// [`CHANGE_TTL`].
pub const OP_UNCONFIRMED_NOTICE: &str = "Your vault hasn't confirmed this yet. It may still happen in the next two minutes: refresh then to see.";
/// NEW TEXT (owner approval needed): it couldn't be sent at all.
pub const OP_NOT_SENT_NOTICE: &str = "This desktop couldn't send this to your vault. Try again.";

/// NEW TEXT (owner approval needed): the vault refused the operation for
/// a desktop (`forbidden`): it is the phone's.
pub const OP_FORBIDDEN_NOTICE: &str = "This is done on your phone.";
/// NEW TEXT (owner approval needed): `not_found`.
pub const OP_NOT_FOUND_NOTICE: &str = "Your vault doesn't have this any more. Refresh to see what it has now.";
/// NEW TEXT (owner approval needed): any other error answer.
pub const OP_FAILED_NOTICE: &str = "Your vault couldn't do this. Try again.";

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
            OpError::NotSent | OpError::EarlierUnconfirmed => OP_NOT_SENT_NOTICE.into(),
            OpError::Refused => REFUSED_NOTICE.into(),
            OpError::Vault(c) if c == "forbidden" => OP_FORBIDDEN_NOTICE.into(),
            OpError::Vault(c) if c == "not_found" => OP_NOT_FOUND_NOTICE.into(),
            // The view starts again from the newest page without saying so.
            OpError::PageGone => OP_NOT_FOUND_NOTICE.into(),
            OpError::Vault(_) | OpError::Malformed | OpError::BadArgument => OP_FAILED_NOTICE.into(),
        }
    }

    /// A stable code for the frontend (it never matches on the text).
    pub fn code(&self) -> &'static str {
        match self {
            OpError::NoSession => "no_session",
            OpError::Held => "held",
            OpError::Locked => "locked",
            OpError::Unknown => "unknown",
            OpError::Unconfirmed => "unconfirmed",
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
    ///   one of [`READ_TTL`]. A change not confirmed is remembered, and the
    ///   same change asked again is retried under its id (§8.6), so the
    ///   vault answers it from its cache instead of acting twice.
    /// - Once the request is stored, any failure is
    ///   [`OpError::Unconfirmed`]: it goes with the next exchange.
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
        self.check_gap(Utc::now());
        if let Some(e) = self.not_open_for_an_op() {
            return Err(e);
        }
        // SECURITY: a change's body can carry message plaintext: this copy
        // and the kept one are wiped.
        let body = Zeroizing::new(body.to_string());
        let now = Utc::now();
        // The same change asked again while its first try can still arrive:
        // its id and its exp.
        let again = match &self.unconfirmed {
            Some(p) if change && p.kind == kind && *p.body == *body && now < p.exp => Some((p.id.clone(), p.exp)),
            _ => None,
        };
        let exp = again.as_ref().map_or_else(|| now + if change { CHANGE_TTL } else { READ_TTL }, |(_, e)| *e);
        if change {
            self.sending = Some(Pending { kind: kind.to_string(), body: body.clone(), id: again.as_ref().map(|(i, _)| i.clone()).unwrap_or_default(), exp });
        }
        let r = self.session.request_at(&mut self.store, again.as_ref().map(|(i, _)| i.as_str()), kind, &body, OP_TIMEOUT, exp).await;
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
                            Err(OpError::Malformed)
                        }
                    },
                    Some(Status::Error { code, .. }) => {
                        log::info!("link: {} answered {}", kind, code);
                        Err(match code.as_str() {
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
                    None => Err(OpError::Malformed),
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
                        self.unconfirmed = Some(Pending { kind: kind.to_string(), body: body.clone(), id, exp });
                    }
                    return Err(OpError::Clock(d));
                }
                match stored {
                    // Stored: it goes with the next exchange (until exp).
                    Some(id) => {
                        if matches!(e, SessionError::Relay(_) | SessionError::TimedOut) {
                            self.reachable = false;
                        }
                        if change {
                            self.unconfirmed = Some(Pending { kind: kind.to_string(), body: body.clone(), id, exp });
                        }
                        Err(OpError::Unconfirmed)
                    }
                    None => Err(match &e {
                        SessionError::Store(_) => OpError::NotSaved,
                        _ => OpError::NotSent,
                    }),
                }
            }
        };
        // What the same exchange showed of the vault or the session.
        let out = match out {
            // Said as the lock or the hold, not as a failure of its own.
            Err(OpError::Unconfirmed) => Err(self.not_open_for_an_op().filter(|e| *e != OpError::NoSession).unwrap_or(OpError::Unconfirmed)),
            // A read isn't handed on once the session isn't live.
            Ok(_) if !change && !self.views_live(Utc::now()) => Err(self.not_open_for_an_op().unwrap_or(OpError::NoSession)),
            o => o,
        };
        self.note_refused().await;
        out
    }
}

/// A change sent and not confirmed: retried under its id, with its first
/// `exp`, until then. `Debug` leaves the body out (message plaintext).
#[derive(Clone)]
pub struct Pending {
    kind: String,
    body: Zeroizing<String>,
    id: String,
    exp: DateTime<Utc>,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending").field("kind", &self.kind).field("body_len", &self.body.len()).field("id", &self.id).field("exp", &self.exp).finish()
    }
}

/// What became of a kept change retried before a new one
/// ([`Link::op_kept_first`]): its body (so the caller can tell which it
/// was) and its answer, or [`OpError::Unconfirmed`] while it is still not
/// confirmed. `Debug` leaves the body and the answer's body out.
#[derive(Clone, PartialEq, Eq)]
pub struct Earlier {
    pub body: Zeroizing<String>,
    pub result: Result<serde_json::Value, OpError>,
}

impl std::fmt::Debug for Earlier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Earlier").field("body_len", &self.body.len()).field("error", &self.result.as_ref().err()).finish()
    }
}

impl<T: Transport, C: Clock> Link<T, C> {
    /// A change as [`Link::op`] sends it, except that a kept change of the
    /// same `kind` with another body (a send left unconfirmed, then another
    /// message) is retried first, under its id and with its first `exp`, so
    /// that it is never dropped unseen; what became of it is kept in
    /// `earlier` for the caller. While it stays unconfirmed, or nothing
    /// could be sent, this change isn't sent:
    /// [`OpError::EarlierUnconfirmed`], or the error that would have
    /// stopped this one too. A kept change past its `exp` isn't retried (it
    /// would be a new request): it is reported unconfirmed, and only a read
    /// tells whether it happened.
    pub async fn op_kept_first(&mut self, kind: &str, body: &serde_json::Value, shape: impl Fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>) -> Result<serde_json::Value, OpError> {
        self.earlier = None;
        let this = Zeroizing::new(body.to_string());
        let kept = self.unconfirmed.clone().filter(|p| p.kind == kind && *p.body != *this);
        if let Some(p) = kept {
            // Unconfirmed until its answer is in (a cut-off leaves it so).
            self.earlier = Some(Earlier { body: p.body.clone(), result: Err(OpError::Unconfirmed) });
            if Utc::now() >= p.exp {
                self.unconfirmed = None;
            } else {
                let again: serde_json::Value = serde_json::from_str(&p.body).map_err(|_| OpError::Malformed)?;
                let r = self.op(kind, &again, &shape, true).await;
                if self.unconfirmed.as_ref().is_some_and(|q| q.id == p.id) {
                    return Err(match r {
                        Err(OpError::Unconfirmed) | Ok(_) => OpError::EarlierUnconfirmed,
                        Err(e) => e,
                    });
                }
                self.earlier = Some(Earlier { body: p.body, result: r });
            }
        }
        self.op(kind, body, &shape, true).await
    }
}

impl<T: Transport, C: Clock> Link<T, C> {
    /// An operation's wait was cut off (its bound, or a reset): a change
    /// that was stored is kept as unconfirmed, to be retried under its id.
    /// What the operation of `body` is told: unconfirmed, unless it was cut
    /// off while the kept change before it was retried
    /// ([`Link::op_kept_first`]), so that it wasn't sent itself.
    fn cut_off(&mut self, body: &serde_json::Value) -> OpError {
        let sending = self.sending.take();
        let this = Zeroizing::new(body.to_string());
        let earlier_only = sending.as_ref().is_some_and(|p| *p.body != *this && self.earlier.as_ref().is_some_and(|e| e.body == p.body));
        if let (Some(mut p), Some(id)) = (sending, self.session.last_request_id()) {
            p.id = id.to_string();
            self.unconfirmed = Some(p);
        }
        if earlier_only {
            OpError::EarlierUnconfirmed
        } else {
            OpError::Unconfirmed
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
    link_run_with(link, screen_live, overtaken, publish, stop, kind, body, shape, how).await.0
}

/// How [`link_run_with`] sends: a read or a change ([`Link::op`]), or a
/// change after the kept one ([`Link::op_kept_first`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    Read,
    Change,
    KeptFirst,
}

/// [`link_op_with`]; with [`How::KeptFirst`], also what became of the kept
/// change retried first ([`Earlier`]), if there was one.
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
) -> (Result<serde_json::Value, OpError>, Option<Earlier>) {
    let change = how != How::Read;
    if overtaken() || !screen_live() {
        return (Err(OpError::NoSession), None);
    }
    let mut slot = link.lock().await;
    let Some(l) = slot.as_mut() else { return (Err(OpError::NoSession), None) };
    if overtaken() {
        return (Err(OpError::NoSession), None);
    }
    l.earlier = None;
    let r = {
        let run = async {
            match how {
                How::KeptFirst => l.op_kept_first(kind, &body, shape).await,
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
            Err(l.cut_off(&body))
        }
    };
    let earlier = l.earlier.take();
    if overtaken() {
        let r = match r {
            Ok(v) if change => Ok(v),
            Ok(_) => Err(OpError::NoSession),
            e => e,
        };
        return (r, earlier);
    }
    publish(l.snapshot(Utc::now()));
    (r, earlier)
}

#[cfg(test)]
mod tests;
