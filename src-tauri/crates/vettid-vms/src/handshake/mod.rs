//! The session handshake (VAULT-MESSAGING §6.1–§6.3): the three messages
//! `hs.init`, `hs.resp` and `hs.fin`, the key schedule and SAS, and the
//! epoch they establish, as the vault's `vms/handshake` builds them.
//!
//! This client is the **initiator** of a pairing (`desktop`, and the other
//! purposes that pair or connect: `app`, `agent`, `connection`). The
//! responder side, which the desktop needs when its vault rekeys (§6.5),
//! comes with the device engine, as do rekeys, reconnects, rotation
//! chains and key retention.
//!
//! Errors carry no key material, plaintext or input.

mod epoch;
mod initiator;
mod messages;
mod schedule;

pub use epoch::{Epoch, EpochState, Policy, Role, POLICY_VAULT_TO_DEVICE};
pub use initiator::{Initiator, InitiatorConfig, Outcome};
pub use messages::{valid_ctx, valid_relay_url, valid_token, Fin, Init, Principal, RelayAddr, Resp};
pub use schedule::{check_sas_commit, sas, sas_commit, sign_fin, sign_resp, th, th1, verify_fin, verify_resp, Schedule};

use crate::envelope::EnvelopeError;
use crate::suite::{SuiteError, SUITE_1, SUITE_2};

/// The inner `type` of each handshake message (§10).
pub const TYPE_INIT: &str = "hs.init";
pub const TYPE_RESP: &str = "hs.resp";
pub const TYPE_FIN: &str = "hs.fin";

/// The size of the SAS nonces `n_I` and `n_R` (§6.2).
pub const SAS_NONCE_SIZE: usize = 32;
/// The size of an epoch id.
pub const EPOCH_ID_SIZE: usize = 16;

/// Field limits. The spec leaves these open (except `ctx`); they bound
/// what a parser keeps, as the vault's do.
pub const MAX_CTX_LEN: usize = 128;
pub const MAX_TOKEN_LEN: usize = 4096;
pub const MAX_URL_LEN: usize = 256;
pub const MAX_PROFILE_LEN: usize = 16 * 1024;
/// The longest `suites` offer (§6.2).
pub const MAX_OFFER: usize = 8;

/// The `hs.init` purpose (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    App,
    Desktop,
    Agent,
    Connection,
    Rekey,
    Reconnect,
}

impl Purpose {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Desktop => "desktop",
            Self::Agent => "agent",
            Self::Connection => "connection",
            Self::Rekey => "rekey",
            Self::Reconnect => "reconnect",
        }
    }

    /// A wire name, or `None`.
    pub fn parse(s: &str) -> Option<Self> {
        [Self::App, Self::Desktop, Self::Agent, Self::Connection, Self::Rekey, Self::Reconnect].into_iter().find(|p| p.as_str() == s)
    }

    /// Whether it pairs an owner device or agent (§6.7).
    pub fn is_pairing(self) -> bool {
        matches!(self, Self::App | Self::Desktop | Self::Agent)
    }

    /// Whether the handshake has a SAS, and so `sas_commit` and
    /// `sas_nonce` (§6.2, 0.10.3): every purpose but rekey and reconnect.
    pub fn has_sas(self) -> bool {
        self.is_pairing() || self == Self::Connection
    }

    /// Whether `token` and `reconnect_token` are required (`Some(true)`),
    /// optional (`None`) or forbidden (`Some(false)`), in `hs.init` and
    /// `hs.resp` (§6.2's table).
    fn token_rules(self) -> (Option<bool>, Option<bool>) {
        match self {
            Self::App | Self::Desktop | Self::Agent | Self::Connection => (Some(true), Some(false)),
            Self::Reconnect => (Some(true), Some(true)),
            Self::Rekey => (None, None),
        }
    }
}

/// Why a handshake step failed. Carries no key material or input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// A malformed message body, or one that breaks §6.2's rules.
    Body,
    /// The inner `type` isn't the expected message.
    Type,
    /// The envelope or inner plaintext was refused.
    Envelope(EnvelopeError),
    /// A suite operation failed, or the suite choice was refused.
    Suite(SuiteError),
    /// The `hs.resp` `sender_kid` isn't all zero.
    SenderKid,
    /// The relay collect `sender` isn't the responder's relay key.
    Sender,
    /// `sig_R` didn't verify: the handshake is aborted.
    SigResp,
    /// `sig_I` didn't verify. A responder drops the `hs.fin` and keeps the
    /// handshake pending (§6.3), unlike a commitment mismatch.
    SigFin,
    /// The epoch isn't active yet: a pairing's epoch activates at the
    /// owner's approval (§6.7).
    Inactive,
    /// The handshake was aborted, or finished.
    Done,
    /// The configuration is incomplete or not supported here.
    Config,
    /// The epoch's keys are retired.
    EpochRetired,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Body => f.write_str("handshake: malformed message body"),
            Self::Type => f.write_str("handshake: unexpected message type"),
            Self::Envelope(e) => write!(f, "handshake: {e}"),
            Self::Suite(e) => write!(f, "handshake: {e}"),
            Self::SenderKid => f.write_str("handshake: sender kid does not match"),
            Self::Sender => f.write_str("handshake: relay sender does not match"),
            Self::SigResp => f.write_str("handshake: sig_R verification failed"),
            Self::SigFin => f.write_str("handshake: sig_I verification failed"),
            Self::Inactive => f.write_str("handshake: epoch not active yet"),
            Self::Done => f.write_str("handshake: handshake aborted or completed"),
            Self::Config => f.write_str("handshake: invalid configuration"),
            Self::EpochRetired => f.write_str("handshake: epoch key retired"),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<EnvelopeError> for HandshakeError {
    fn from(e: EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

impl From<SuiteError> for HandshakeError {
    fn from(e: SuiteError) -> Self {
        Self::Suite(e)
    }
}

/// A `suites` offer (§6.2): 1–8 strictly ascending integers in [2, 255].
/// Suite 1 (or 0) anywhere refuses the whole offer; unknown suites above 2
/// are allowed and not chosen.
pub fn validate_offer(suites: &[u64]) -> Result<(), HandshakeError> {
    if suites.is_empty() || suites.len() > MAX_OFFER {
        return Err(HandshakeError::Body);
    }
    for (i, s) in suites.iter().enumerate() {
        if *s == u64::from(SUITE_1) {
            return Err(HandshakeError::Suite(SuiteError::Suite1));
        }
        if !(2..=255).contains(s) || (i > 0 && *s <= suites[i - 1]) {
            return Err(HandshakeError::Body);
        }
    }
    Ok(())
}

/// The responder's choice: offered, supported (only suite 2), and not
/// below the pinned suite (§4.1, §13.4).
pub fn check_chosen(chosen: u64, offered: &[u64], pinned: u8) -> Result<(), HandshakeError> {
    if chosen == u64::from(SUITE_1) {
        return Err(HandshakeError::Suite(SuiteError::Suite1));
    }
    if chosen != u64::from(SUITE_2) || chosen < u64::from(pinned) || !offered.contains(&chosen) {
        return Err(HandshakeError::Suite(SuiteError::UnsupportedSuite));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes() {
        for p in ["app", "desktop", "agent", "connection", "rekey", "reconnect"] {
            assert_eq!(Purpose::parse(p).unwrap().as_str(), p);
        }
        assert_eq!(Purpose::parse("Desktop"), None);
        assert!(Purpose::Desktop.has_sas() && Purpose::Connection.has_sas());
        assert!(!Purpose::Rekey.has_sas() && !Purpose::Reconnect.has_sas());
        assert!(Purpose::Agent.is_pairing() && !Purpose::Connection.is_pairing());
    }

    #[test]
    fn offers_and_choices() {
        assert!(validate_offer(&[2]).is_ok());
        assert!(validate_offer(&[2, 3, 255]).is_ok());
        assert_eq!(validate_offer(&[1, 2]), Err(HandshakeError::Suite(SuiteError::Suite1)));
        for bad in [&[][..], &[0], &[2, 2], &[3, 2], &[256], &[2, 3, 4, 5, 6, 7, 8, 9, 10]] {
            assert_eq!(validate_offer(bad), Err(HandshakeError::Body), "{bad:?}");
        }
        assert!(check_chosen(2, &[2], 0).is_ok());
        assert!(check_chosen(2, &[2, 3], 2).is_ok());
        assert!(check_chosen(1, &[2], 0).is_err());
        assert!(check_chosen(3, &[2, 3], 0).is_err(), "unsupported");
        assert!(check_chosen(2, &[3], 0).is_err(), "not offered");
        assert!(check_chosen(2, &[2], 3).is_err(), "below the pin");
    }
}
