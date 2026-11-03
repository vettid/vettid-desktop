//! A session's epochs (§6.5), as the vault's `Keyring`: the current epoch,
//! and the receive keys of previous ones, kept 16 days (the relay TTL
//! plus a margin) so a late message of an old epoch still opens. When a
//! new epoch activates, the previous one's send key and `rk` are deleted
//! at once, so a rekey is possible only from the current epoch.

use chrono::{DateTime, TimeDelta, Utc};

use super::epoch::{Epoch, EpochState};
use super::HandshakeError;
use crate::envelope::{Envelope, EnvelopeError, Inner, MAX_CLOCK_SKEW_FUTURE};

/// How long a previous epoch's receive key is kept (§6.5).
pub const RECEIVE_KEY_RETENTION: TimeDelta = TimeDelta::days(16);

/// The most retired epochs kept. The vault rekeys on every unlock and
/// every 7 days (§6.5), so this allows 16 rekeys a day for the whole
/// retention; past it, the oldest receive key goes early, and a stored
/// keyring with more is refused.
pub const MAX_RETIRED: usize = 256;

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

    /// Make `e`, which must be active (an established rekey), the current
    /// epoch: an inactive one (a pairing the owner hasn't approved) is
    /// refused, and nothing changes. The previous one's send key and `rk`
    /// are deleted now; its receive key is kept for
    /// [`RECEIVE_KEY_RETENTION`] (at most [`MAX_RETIRED`] of them).
    pub fn activate(&mut self, e: Epoch, now: DateTime<Utc>) -> Result<(), HandshakeError> {
        if !e.is_active() {
            return Err(HandshakeError::Inactive);
        }
        let mut old = std::mem::replace(&mut self.current, e);
        old.retire_send();
        self.retired.push((old, now + RECEIVE_KEY_RETENTION));
        self.prune(now);
        if self.retired.len() > MAX_RETIRED {
            let excess = self.retired.len() - MAX_RETIRED;
            self.retired.drain(..excess);
        }
        Ok(())
    }

    /// Delete the retired receive keys past their retention.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        self.retired.retain(|(_, until)| now <= *until);
    }

    /// Open a session-mode envelope in the one epoch whose receive kid it
    /// names (§4.4: no other epoch is tried), and say whether that is the
    /// current epoch. Every candidate is compared in constant time.
    /// Retired keys past their retention are deleted first.
    pub fn open(&mut self, env: &Envelope, now: DateTime<Utc>) -> Result<(Inner, bool), HandshakeError> {
        self.prune(now);
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

    /// A keyring from its stored form, at `now`; retired keys past their
    /// retention are deleted. A retired epoch that still holds a send key
    /// or `rk`, or whose deletion is further ahead than the retention (plus
    /// the clock skew), or more than [`MAX_RETIRED`] of them, is refused.
    pub fn restore(s: KeyringState, now: DateTime<Utc>) -> Result<Self, HandshakeError> {
        let latest = now + RECEIVE_KEY_RETENTION + MAX_CLOCK_SKEW_FUTURE;
        if s.retired.iter().any(|(e, until)| e.send.is_some() || e.rk.is_some() || *until > latest) {
            return Err(HandshakeError::Config);
        }
        let mut ring = Keyring { current: Epoch::restore(s.current), retired: s.retired.into_iter().map(|(e, until)| (Epoch::restore(e), until)).collect() };
        ring.prune(now);
        if ring.retired.len() > MAX_RETIRED {
            return Err(HandshakeError::Config);
        }
        Ok(ring)
    }
}
