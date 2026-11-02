use serde::Serialize;
use std::fmt;
use std::path::PathBuf;

use crate::crypto::CryptoError;
use crate::nats::client::{NatsClient, NatsError};

#[derive(Debug, Clone)]
pub enum RegistrationError {
    InviteResolutionFailed(String),
    NatsConnectionFailed(String),
    NatsOperationFailed(String),
    CryptoFailed(String),
    Denied(String),
    Timeout,
    Internal(String),
    /// The saved pairing can't be opened on this machine (see
    /// `CredentialError::Unreadable`). Displays the plain notice.
    PairingUnreadable,
    /// The pairing can't be saved: the system keyring can't be reached
    /// and a weaker key is not allowed (see
    /// `CredentialError::KeyringUnavailable`). Displays the plain notice.
    KeyringUnavailable,
    /// The pairing's folder or file could be opened by another account
    /// (see `CredentialError::NotPrivate`). Displays the plain notice.
    NotPrivate,
    /// The folder that holds the pairing folder lets another account
    /// change what is in it (see `CredentialError::ParentNotPrivate`).
    /// Displays the plain notice.
    ParentNotPrivate,
    /// `%LOCALAPPDATA%` is a link (see `CredentialError::ParentIsLink`).
    /// Displays the plain notice.
    ParentIsLink,
    /// This computer has no machine id to bind the pairing to (see
    /// `CredentialError::NoMachineId`). Displays the plain notice.
    NoMachineId,
    /// The pairing is saved, but the new session couldn't be recorded on
    /// this computer (#33). Displays the plain notice.
    SessionNotRecorded,
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InviteResolutionFailed(msg) => write!(f, "invite resolution failed: {}", msg),
            Self::NatsConnectionFailed(msg) => write!(f, "NATS connection failed: {}", msg),
            Self::NatsOperationFailed(msg) => write!(f, "NATS operation failed: {}", msg),
            Self::CryptoFailed(msg) => write!(f, "cryptographic operation failed: {}", msg),
            Self::Denied(reason) => write!(f, "connection denied: {}", reason),
            Self::Timeout => write!(f, "timed out waiting for approval"),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
            Self::PairingUnreadable => {
                f.write_str(crate::credential::store::UNREADABLE_NOTICE)
            }
            Self::KeyringUnavailable => {
                f.write_str(crate::credential::store::KEYRING_UNAVAILABLE_NOTICE)
            }
            Self::NotPrivate => f.write_str(crate::credential::store::NOT_PRIVATE_NOTICE),
            Self::ParentNotPrivate => f.write_str(crate::credential::store::PARENT_NOT_PRIVATE_NOTICE),
            Self::ParentIsLink => f.write_str(crate::credential::store::PARENT_IS_LINK_NOTICE),
            Self::NoMachineId => f.write_str(crate::credential::store::NO_MACHINE_ID_NOTICE),
            Self::SessionNotRecorded => {
                f.write_str(crate::credential::store::SESSION_NOT_RECORDED_NOTICE)
            }
        }
    }
}

impl std::error::Error for RegistrationError {}

impl From<NatsError> for RegistrationError {
    fn from(err: NatsError) -> Self {
        match err {
            NatsError::ConnectionFailed(msg) => Self::NatsConnectionFailed(msg),
            other => Self::NatsOperationFailed(other.to_string()),
        }
    }
}

impl From<CryptoError> for RegistrationError {
    fn from(err: CryptoError) -> Self {
        Self::CryptoFailed(err.to_string())
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum RegistrationState {
    Idle,
    ResolvingInvite,
    ConnectingNats,
    AwaitingAuthorization,
    KeyExchange,
    Approved,
    Denied(String),
    Failed(String),
}

pub struct RegistrationFlow {
    state: RegistrationState,
    #[allow(dead_code)]
    config_dir: PathBuf,
    #[allow(dead_code)]
    nats_client: NatsClient,
}

impl RegistrationFlow {
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            state: RegistrationState::Idle,
            config_dir,
            nats_client: NatsClient::new(),
        }
    }

    pub fn state(&self) -> &RegistrationState {
        &self.state
    }

    /// Execute the device pairing flow.
    ///
    /// Per `vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md`, pairing is a two-stage flow:
    /// stage 1 resolves an 8-char invite code via the pre-provisioned guest NATS
    /// account reading `invite.<code>` from JetStream; stage 2 presents a
    /// session-authorization QR that the user scans in their phone app, and only
    /// after that approval does key exchange occur.
    ///
    /// The previous single-stage HTTP-broker implementation (`https://vett.id/...`)
    /// has been removed — that domain was never registered and the flow never worked.
    pub async fn run(&mut self, _invite_code: &str, _passphrase: &str) -> Result<(), RegistrationError> {
        Err(RegistrationError::Internal(
            "device pairing not yet implemented — see vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md".to_string(),
        ))
    }
}
