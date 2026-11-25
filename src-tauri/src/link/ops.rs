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
            OpError::Refused => REFUSED_NOTICE.into(),
            OpError::Vault(c) if c == "forbidden" => OP_FORBIDDEN_NOTICE.into(),
            OpError::Vault(c) if c == "not_found" => OP_NOT_FOUND_NOTICE.into(),
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
            OpError::Vault(_) => "vault_error",
            OpError::Malformed => "malformed",
            OpError::BadArgument => "bad_argument",
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
    pub async fn op(&mut self, kind: &str, body: &serde_json::Value, shape: fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>, change: bool) -> Result<serde_json::Value, OpError> {
        self.check_gap(Utc::now());
        if let Some(e) = self.not_open_for_an_op() {
            return Err(e);
        }
        let body = body.to_string();
        let now = Utc::now();
        // The same change asked again while its first try can still arrive:
        // its id and its exp.
        let again = match &self.unconfirmed {
            Some(p) if change && p.kind == kind && p.body == body && now < p.exp => Some((p.id.clone(), p.exp)),
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
/// `exp`, until then.
#[derive(Debug, Clone)]
pub struct Pending {
    kind: String,
    body: String,
    id: String,
    exp: DateTime<Utc>,
}

impl<T: Transport, C: Clock> Link<T, C> {
    /// An operation's wait was cut off (its bound, or a reset): a change
    /// that was stored is kept as unconfirmed, to be retried under its id.
    fn cut_off(&mut self) {
        if let (Some(mut p), Some(id)) = (self.sending.take(), self.session.last_request_id()) {
            p.id = id.to_string();
            self.unconfirmed = Some(p);
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
    shape: fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>,
    change: bool,
) -> Result<serde_json::Value, OpError> {
    if overtaken() || !screen_live() {
        return Err(OpError::NoSession);
    }
    let mut slot = link.lock().await;
    let Some(l) = slot.as_mut() else { return Err(OpError::NoSession) };
    if overtaken() {
        return Err(OpError::NoSession);
    }
    let r = tokio::select! {
        r = tokio::time::timeout(OP_HOLD_MAX, l.op(kind, &body, shape, change)) => match r {
            Ok(r) => r,
            Err(_) => {
                log::info!("link: {} held the link too long; it may still be carried out", kind);
                l.cut_off();
                Err(OpError::Unconfirmed)
            }
        },
        () = stop => {
            log::info!("link: {} stopped for a reset; it may still be carried out", kind);
            l.cut_off();
            Err(OpError::Unconfirmed)
        }
    };
    if overtaken() {
        return match r {
            Ok(v) if change => Ok(v),
            Ok(_) => Err(OpError::NoSession),
            e => e,
        };
    }
    publish(l.snapshot(Utc::now()));
    r
}

#[cfg(test)]
mod tests;
