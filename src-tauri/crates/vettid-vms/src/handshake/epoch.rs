//! An epoch (§6.3, §6.5): a send and a receive direction, each with its
//! key and kids, the per-direction `seq`, and the rekey secret `rk`.
//! Rekey, retention of previous epochs and persistence come with the
//! device engine.

use chrono::{DateTime, TimeDelta, Utc};
use zeroize::Zeroizing;

use super::schedule::Schedule;
use super::{HandshakeError, EPOCH_ID_SIZE};
use crate::envelope::{open_session, seal_session_with, Envelope, Inner, Mode};
use crate::suite::aead::fresh_nonce;
use crate::suite::kid::Kid;
use crate::suite::{KEY_SIZE, XNONCE_SIZE};

/// This side's role in the handshake that made the epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// What bounds an epoch (§6.5): due for rekey after `max_age`, or after
/// `max_messages` sent or received (0: no message bound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub max_age: TimeDelta,
    pub max_messages: u64,
}

/// Vault ↔ device: 7 days (and every unlock, which the vault starts).
pub const POLICY_VAULT_TO_DEVICE: Policy = Policy { max_age: TimeDelta::days(7), max_messages: 0 };

struct Direction {
    key: Zeroizing<[u8; KEY_SIZE]>,
    /// The header's `recipient_kid`.
    recipient_kid: Kid,
    /// The header's `sender_kid`.
    sender_kid: Kid,
}

/// One epoch. `Debug` shows the role, suite and counts only.
pub struct Epoch {
    id: [u8; EPOCH_ID_SIZE],
    role: Role,
    suite: u8,
    policy: Policy,
    created: DateTime<Utc>,
    send: Option<Direction>,
    recv: Direction,
    // Read by rekeys, which come with the device engine.
    #[allow(dead_code)]
    rk: Option<Zeroizing<[u8; KEY_SIZE]>>,
    last_seq: u64,
    sent: u64,
    received: u64,
}

impl std::fmt::Debug for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Epoch")
            .field("role", &self.role)
            .field("suite", &self.suite)
            .field("sent", &self.sent)
            .field("received", &self.received)
            .finish_non_exhaustive()
    }
}

impl Epoch {
    /// From a schedule: direction i2r uses `k_i2r` with `recipient_kid =
    /// kid_i2r` and `sender_kid = kid_r2i`; r2i mirrors it (§6.3).
    pub(crate) fn new(s: &Schedule, role: Role, suite: u8, policy: Policy, now: DateTime<Utc>) -> Self {
        let i2r = || Direction { key: s.k_i2r.clone(), recipient_kid: s.kid_i2r, sender_kid: s.kid_r2i };
        let r2i = || Direction { key: s.k_r2i.clone(), recipient_kid: s.kid_r2i, sender_kid: s.kid_i2r };
        let (send, recv) = match role {
            Role::Initiator => (i2r(), r2i()),
            Role::Responder => (r2i(), i2r()),
        };
        Epoch {
            id: s.epoch_id,
            role,
            suite,
            policy,
            created: now,
            send: Some(send),
            recv,
            rk: Some(s.rk.clone()),
            last_seq: 0,
            sent: 0,
            received: 0,
        }
    }

    /// The epoch id.
    pub fn id(&self) -> [u8; EPOCH_ID_SIZE] {
        self.id
    }

    /// This side's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The negotiated suite.
    pub fn suite(&self) -> u8 {
        self.suite
    }

    /// The `recipient_kid` that messages to this side carry.
    pub fn recv_kid(&self) -> Kid {
        self.recv.recipient_kid
    }

    /// The activation time.
    pub fn created(&self) -> DateTime<Utc> {
        self.created
    }

    /// Messages sent and received.
    pub fn counts(&self) -> (u64, u64) {
        (self.sent, self.received)
    }

    /// Restart the epoch's age and counts at activation: a new device's
    /// first epoch counts from the owner's approval, not from `hs.fin`
    /// (§6.5).
    pub fn mark_activated(&mut self, now: DateTime<Utc>) {
        self.created = now;
        self.sent = 0;
        self.received = 0;
    }

    /// Whether the policy limit is reached (§6.5).
    pub fn needs_rekey(&self, now: DateTime<Utc>) -> bool {
        let p = self.policy;
        (p.max_age > TimeDelta::zero() && now - self.created >= p.max_age)
            || (p.max_messages > 0 && (self.sent >= p.max_messages || self.received >= p.max_messages))
    }

    /// Whether the send key is still held.
    pub fn can_send(&self) -> bool {
        self.send.is_some()
    }

    /// `rk`, the `K_s` of the next rekey (§6.2).
    #[allow(dead_code)]
    pub(crate) fn rk(&self) -> Result<&[u8; KEY_SIZE], HandshakeError> {
        self.rk.as_deref().ok_or(HandshakeError::EpochRetired)
    }

    /// Seal an inner plaintext in session mode with a fresh nonce,
    /// assigning its `seq`: per epoch and direction, from 1 (§5.3). The
    /// same `id` may be sealed again for a retransmission; each call is a
    /// new envelope.
    pub fn seal(&mut self, inner: &mut Inner) -> Result<Vec<u8>, HandshakeError> {
        self.seal_with(inner, &fresh_nonce()?)
    }

    /// [`Epoch::seal`] with the nonce given: the nonce must be fresh
    /// randomness (only the known-answer tests pass a fixed one).
    pub(super) fn seal_with(&mut self, inner: &mut Inner, nonce: &[u8; XNONCE_SIZE]) -> Result<Vec<u8>, HandshakeError> {
        let send = self.send.as_ref().ok_or(HandshakeError::EpochRetired)?;
        inner.seq = Some(self.last_seq + 1);
        let sealed = inner
            .encode(Mode::Session)
            .map(Zeroizing::new)
            .and_then(|padded| seal_session_with(&send.key, send.sender_kid, send.recipient_kid, nonce, &padded));
        match sealed {
            Ok(env) => {
                self.last_seq += 1;
                self.sent += 1;
                Ok(env)
            }
            Err(e) => {
                inner.seq = None;
                Err(e.into())
            }
        }
    }

    /// Open a session-mode envelope addressed to this epoch: its
    /// `recipient_kid` and `sender_kid` must be this epoch's receive kids
    /// (constant time), the AEAD must verify, and the inner plaintext must
    /// parse strictly.
    pub fn open(&mut self, env: &Envelope) -> Result<Inner, HandshakeError> {
        if env.mode() != Mode::Session {
            return Err(crate::envelope::EnvelopeError::WrongMode.into());
        }
        let r = &self.recv;
        if !env.recipient_kid().ct_eq(&r.recipient_kid) || !env.sender_kid().ct_eq(&r.sender_kid) {
            return Err(crate::envelope::EnvelopeError::Kid.into());
        }
        let padded = open_session(env, &r.key)?;
        let inner = Inner::decode(&padded, Mode::Session)?;
        self.received += 1;
        Ok(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::schedule::Schedule;

    fn pair() -> (Epoch, Epoch) {
        let s = Schedule::derive(&[1; 32], &[2; 32], [3; 32], [4; 32]);
        let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
        (Epoch::new(&s, Role::Initiator, 2, POLICY_VAULT_TO_DEVICE, now), Epoch::new(&s, Role::Responder, 2, POLICY_VAULT_TO_DEVICE, now))
    }

    fn ping(id: &str) -> Inner {
        let mut i = Inner::parse(
            r#"{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","body":{}}"#.as_bytes(),
            Mode::Sealed,
        )
        .unwrap();
        i.id = id.into();
        i
    }

    #[test]
    fn both_directions_and_seq() {
        let (mut i, mut r) = pair();
        assert_eq!(i.id(), r.id());
        for n in 1..=3 {
            let mut m = ping("01JB2Z6V9K3M4N5P6Q7R8S9T0V");
            let env = Envelope::parse(&i.seal(&mut m).unwrap()).unwrap();
            assert_eq!(m.seq, Some(n));
            assert_eq!(env.recipient_kid(), r.recv_kid());
            assert_eq!(r.open(&env).unwrap().seq, Some(n));
        }
        let mut back = ping("01JB2Z6V9K3M4N5P6Q7R8S9T0W");
        let env = Envelope::parse(&r.seal(&mut back).unwrap()).unwrap();
        assert_eq!(back.seq, Some(1), "each direction counts from 1");
        assert_eq!(i.open(&env).unwrap().id, "01JB2Z6V9K3M4N5P6Q7R8S9T0W");
        assert_eq!((i.counts(), r.counts()), ((3, 1), (1, 3)));
        // A message to the other direction is refused by kid.
        let mut own = ping("01JB2Z6V9K3M4N5P6Q7R8S9T0X");
        let mine = Envelope::parse(&i.seal(&mut own).unwrap()).unwrap();
        assert!(i.open(&mine).is_err());
        assert!(!format!("{i:?}").contains("key"));
    }

    #[test]
    fn rekey_policy() {
        let (mut i, _) = pair();
        let t = i.created();
        assert!(!i.needs_rekey(t + TimeDelta::days(7) - TimeDelta::seconds(1)));
        assert!(i.needs_rekey(t + TimeDelta::days(7)));
        i.mark_activated(t + TimeDelta::days(1));
        assert!(!i.needs_rekey(t + TimeDelta::days(7)));
        assert!(i.rk().is_ok() && i.can_send());
    }
}
