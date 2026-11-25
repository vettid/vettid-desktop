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

use super::{Link, PAIRED_NO_ACCESS_NOTICE, REFUSED_NOTICE, UNREACHABLE_NOTICE, VAULT_HELD_NOTICE, VAULT_LOCKED_NOTICE, VAULT_UNKNOWN_NOTICE};

/// How long a vault operation waits for its answer (§8.1).
pub const OP_TIMEOUT: TimeDelta = TimeDelta::seconds(30);

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
    /// No answer from the relay or the vault: it may or may not have been
    /// carried out.
    Unreachable,
    /// The vault's mailbox refuses this device (§8.6).
    Refused,
    /// The vault answered with an error code (§10.1).
    Vault(String),
    /// An answer that isn't a JSON object.
    Malformed,
}

impl OpError {
    /// What the person is told.
    pub fn notice(&self) -> &'static str {
        match self {
            OpError::NoSession => PAIRED_NO_ACCESS_NOTICE,
            OpError::Held => VAULT_HELD_NOTICE,
            OpError::Locked => VAULT_LOCKED_NOTICE,
            OpError::Unknown => VAULT_UNKNOWN_NOTICE,
            OpError::Unreachable => UNREACHABLE_NOTICE,
            OpError::Refused => REFUSED_NOTICE,
            OpError::Vault(c) if c == "forbidden" => OP_FORBIDDEN_NOTICE,
            OpError::Vault(c) if c == "not_found" => OP_NOT_FOUND_NOTICE,
            OpError::Vault(_) | OpError::Malformed => OP_FAILED_NOTICE,
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

    /// Send `kind` with `body` (a JSON object) and wait for its answer:
    /// its body, parsed. Only while a session is live as the screen shows
    /// it. An `owner_check_required` answer is learned as the hold
    /// (§3.6.3), and a `session_required` one says the session is gone.
    pub async fn op(&mut self, kind: &str, body: &serde_json::Value) -> Result<serde_json::Value, OpError> {
        if let Some(e) = self.not_open_for_an_op() {
            return Err(e);
        }
        let body = body.to_string();
        let r = self.session.request(&mut self.store, kind, &body, OP_TIMEOUT).await;
        self.drain_held();
        let out = match r {
            Ok(m) => {
                self.reachable = true;
                self.vault_answered();
                // The answer teaches the access logic too: a hold.
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
                            OWNER_CHECK_REQUIRED => OpError::Held,
                            "session_required" => OpError::NoSession,
                            c => OpError::Vault(c.to_string()),
                        })
                    }
                    None => Err(OpError::Malformed),
                }
            }
            Err(SessionError::Refused) => Err(OpError::Refused),
            Err(e) => {
                log::info!("link: {}: {}", kind, e);
                Err(OpError::Unreachable)
            }
        };
        self.note_refused().await;
        out
    }
}

#[cfg(test)]
mod tests;
