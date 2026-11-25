//! Vault operations over the link (DESKTOP-REWORK-PLAN Phase 5, 5.2): a
//! request of a type the vault answers for a desktop with an access
//! session (VAULT-MESSAGING §6.8, §10), its answer's body, and why one
//! fails, said plainly. Nothing is sent without a session live as the
//! screen shows it; nothing is claimed that the vault didn't answer.
//!
//! Answers can carry personal data (names, profiles): they are kept in
//! memory for the caller only, and never logged (logs carry types and
//! codes).

use chrono::{TimeDelta, Utc};
use vettid_device::access::{VaultState, OWNER_CHECK_REQUIRED};
use vettid_device::pairing::Clock;
use vettid_device::session::SessionError;
use vettid_device::transport::Transport;
use vettid_vms::envelope::Status;

use super::{
    clock_notice, clock_offset, Link, NOT_SAVED_NOTICE, PAIRED_NO_ACCESS_NOTICE, REFUSED_NOTICE, UNREACHABLE_NOTICE, VAULT_HELD_NOTICE, VAULT_LOCKED_NOTICE,
    VAULT_UNKNOWN_NOTICE,
};

/// How long a vault operation waits for its answer while it holds the
/// link (chosen; not in the spec): under the 10 s a log-out waits for the
/// link to end the session at the vault. An answer later than this is
/// unconfirmed ([`OpError::Unconfirmed`]), never "not done".
pub const OP_TIMEOUT: TimeDelta = TimeDelta::seconds(8);

/// NEW TEXT (owner approval needed): sent, or stored to be sent, but not
/// answered in time: it may still be carried out.
pub const OP_UNCONFIRMED_NOTICE: &str = "Your vault hasn't confirmed this yet. It may still happen: refresh in a moment to see.";
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
    /// Not sent: the relay couldn't be reached and nothing is stored to
    /// go later.
    Unreachable,
    /// Sent, or stored and sent later, with no answer in time: it may still
    /// be carried out. Never "not done".
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
    /// An answer that isn't a JSON object.
    Malformed,
}

impl OpError {
    /// What the person is told.
    pub fn notice(&self) -> String {
        match self {
            OpError::NoSession => PAIRED_NO_ACCESS_NOTICE.into(),
            OpError::Held => VAULT_HELD_NOTICE.into(),
            OpError::Locked => VAULT_LOCKED_NOTICE.into(),
            OpError::Unknown => VAULT_UNKNOWN_NOTICE.into(),
            OpError::Unreachable => UNREACHABLE_NOTICE.into(),
            OpError::Unconfirmed => OP_UNCONFIRMED_NOTICE.into(),
            OpError::Clock(d) => clock_notice(clock_offset(*d)),
            OpError::NotSaved => NOT_SAVED_NOTICE.into(),
            OpError::NotSent => OP_NOT_SENT_NOTICE.into(),
            OpError::Refused => REFUSED_NOTICE.into(),
            OpError::Vault(c) if c == "forbidden" => OP_FORBIDDEN_NOTICE.into(),
            OpError::Vault(c) if c == "not_found" => OP_NOT_FOUND_NOTICE.into(),
            OpError::Vault(_) | OpError::Malformed => OP_FAILED_NOTICE.into(),
        }
    }

    /// A stable code for the frontend (it never matches on the text).
    pub fn code(&self) -> &'static str {
        match self {
            OpError::NoSession => "no_session",
            OpError::Held => "held",
            OpError::Locked => "locked",
            OpError::Unknown => "unknown",
            OpError::Unreachable => "unreachable",
            OpError::Unconfirmed => "unconfirmed",
            OpError::Clock(_) => "clock",
            OpError::NotSaved => "not_saved",
            OpError::NotSent => "not_sent",
            OpError::Refused => "refused",
            OpError::Vault(c) if c == "forbidden" => "forbidden",
            OpError::Vault(c) if c == "not_found" => "not_found",
            OpError::Vault(_) => "vault_error",
            OpError::Malformed => "malformed",
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
    /// [`OP_TIMEOUT`] for its answer: its body, parsed. Only while a session
    /// is live as the link knows it (the caller also checks what the screen
    /// shows). A sleep is looked for first. An `owner_check_required`
    /// answer is learned as the hold (§3.6.3); a `session_required` one
    /// takes the session as unconfirmed, so the screen isn't live until a
    /// status read says otherwise. A request not answered in time is
    /// [`OpError::Unconfirmed`]: it stays stored and is sent with the next
    /// exchange, so it may still be carried out.
    pub async fn op(&mut self, kind: &str, body: &serde_json::Value) -> Result<serde_json::Value, OpError> {
        self.check_gap(Utc::now());
        if let Some(e) = self.not_open_for_an_op() {
            return Err(e);
        }
        let body = body.to_string();
        let r = self.session.request(&mut self.store, kind, &body, OP_TIMEOUT).await;
        // A sleep during the wait: found before the answer counts.
        self.check_gap(Utc::now());
        self.drain_held();
        let out = match r {
            Ok(m) => {
                self.reachable = true;
                self.vault_answered();
                let e = self.access.observe(&mut self.session, &mut self.store, &m);
                self.noted(&e);
                match m.response.as_ref().map(|r| &r.status) {
                    Some(Status::Ok) => match serde_json::from_str::<serde_json::Value>(&m.body) {
                        Ok(v @ serde_json::Value::Object(_)) => Ok(v),
                        _ => {
                            log::warn!("link: {} answered with a body that isn't an object ({} bytes)", kind, m.body.len());
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
                self.reachable = false;
                Err(match &e {
                    _ if e.clock_skew().is_some() => OpError::Clock(e.clock_skew().flatten()),
                    SessionError::Store(_) => OpError::NotSaved,
                    SessionError::Seal(_) | SessionError::NotQueueable => OpError::NotSent,
                    // Stored in the outbox: it goes with the next exchange.
                    _ => OpError::Unconfirmed,
                })
            }
        };
        // Learned during the wait (a lock, a hold): said as that, not as a
        // failure of the operation.
        let out = match out {
            Err(OpError::Unconfirmed | OpError::Unreachable) => Err(self.not_open_for_an_op().filter(|e| *e != OpError::NoSession).unwrap_or(OpError::Unconfirmed)),
            o => o,
        };
        self.note_refused().await;
        out
    }
}

#[cfg(test)]
mod tests;
