//! A session's epochs (§6.5), as the vault's `Keyring`: the current epoch,
//! and the receive keys of previous ones, kept 16 days (the relay TTL
//! plus a margin) so a late message of an old epoch still opens. When a
//! new epoch activates, the previous one's send key and `rk` are deleted
//! at once, so a rekey is possible only from the current epoch.

use chrono::{DateTime, TimeDelta, Utc};

use super::epoch::{Epoch, EpochState};
use super::HandshakeError;
use crate::envelope::{Envelope, EnvelopeError, Inner};

/// How long a previous epoch's receive key is kept (§6.5).
pub const RECEIVE_KEY_RETENTION: TimeDelta = TimeDelta::days(16);

/// The current epoch and the retired ones. `Debug` prints no key.
pub struct Keyring {
    current: Epoch,
    /// Each retired epoch (receive key only) and when it is deleted.
    retired: Vec<(Epoch, DateTime<Utc>)>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring").field("current", &self.current).field("retired", &self.retired.len()).finish()
    }
}

/// A keyring's stored form (secret: its keys wipe themselves, and `Debug`
/// prints nothing).
#[derive(Clone)]
pub struct KeyringState {
    pub current: EpochState,
    /// Each retired epoch, without its send key and `rk`, and when it is
    /// deleted.
    pub retired: Vec<(EpochState, DateTime<Utc>)>,
}

impl std::fmt::Debug for KeyringState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyringState(..)")
    }
}

impl Keyring {
    /// A keyring holding only `current`.
    pub fn new(current: Epoch) -> Self {
        Keyring { current, retired: Vec::new() }
    }

    /// The current epoch.
    pub fn current(&self) -> &Epoch {
        &self.current
    }

    /// The current epoch, to seal in.
    pub fn current_mut(&mut self) -> &mut Epoch {
        &mut self.current
    }

    /// Make `e` the current epoch. The previous one's send key and `rk`
    /// are deleted now; its receive key is kept for
    /// [`RECEIVE_KEY_RETENTION`].
    pub fn activate(&mut self, e: Epoch, now: DateTime<Utc>) {
        let mut old = std::mem::replace(&mut self.current, e);
        old.retire_send();
        self.retired.push((old, now + RECEIVE_KEY_RETENTION));
        self.prune(now);
    }

    /// Delete the retired receive keys past their retention.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        self.retired.retain(|(_, until)| now <= *until);
    }

    /// Open a session-mode envelope in the one epoch whose receive kid it
    /// names (§4.4: no other epoch is tried), and say whether that is the
    /// current epoch. Every candidate is compared in constant time.
    pub fn open(&mut self, env: &Envelope, now: DateTime<Utc>) -> Result<(Inner, bool), HandshakeError> {
        let kid = env.recipient_kid();
        let mut found: Option<usize> = None;
        let current = kid.ct_eq(&self.current.recv_kid());
        for (i, (e, until)) in self.retired.iter().enumerate() {
            if kid.ct_eq(&e.recv_kid()) & (now <= *until) && found.is_none() {
                found = Some(i);
            }
        }
        if current {
            return Ok((self.current.open(env)?, true));
        }
        match found {
            Some(i) => Ok((self.retired[i].0.open(env)?, false)),
            None => Err(EnvelopeError::Kid.into()),
        }
    }

    /// The stored form.
    pub fn snapshot(&self) -> KeyringState {
        KeyringState { current: self.current.snapshot(), retired: self.retired.iter().map(|(e, until)| (e.snapshot(), *until)).collect() }
    }

    /// A keyring from its stored form. A retired epoch that still holds a
    /// send key or `rk` is refused.
    pub fn restore(s: KeyringState) -> Result<Self, HandshakeError> {
        if s.retired.iter().any(|(e, _)| e.send.is_some() || e.rk.is_some()) {
            return Err(HandshakeError::Config);
        }
        Ok(Keyring { current: Epoch::restore(s.current), retired: s.retired.into_iter().map(|(e, until)| (Epoch::restore(e), until)).collect() })
    }
}
