//! What a paired (or pairing) device keeps, and how it is stored.
//!
//! [`DeviceState`] holds the device's keys (as seeds), its vault's record
//! and token, and the session epoch. It is secret through and through:
//! its serialized form is too, and only a [`Persist`] implementation that
//! protects it may hold it. This crate has none for release builds: a
//! real key store (Windows DPAPI or Credential Manager, the platform
//! keyring) comes with the app's storage work; until then a release build
//! has nothing to persist with, and so can't pair. The plain-file store
//! (`dev_store`) is for development builds only.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::VerifyingKey;
use vettid_vms::envelope::{format_ts, parse_ts};
use vettid_vms::handshake::{EpochState, Policy, RelayAddr, Role};
use vettid_vms::strict_json::{self, Builder, Object};
use vettid_vms::suite::kem::PublicKey;
use vettid_vms::suite::kid::Kid;
use vettid_vms::suite::EK_SIZE;
use zeroize::Zeroizing;

/// A stored direction: key, `recipient_kid`, `sender_kid`.
type Direction = (Zeroizing<[u8; 32]>, Kid, Kid);

/// The stored format's version.
pub const STATE_VERSION: u64 = 1;

/// A store's failure. Carries no stored content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// Reading or writing failed.
    Io,
    /// What was read isn't a device state this build understands.
    Corrupt,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Io => "device store: read or write failed",
            Self::Corrupt => "device store: unreadable state",
        })
    }
}

impl std::error::Error for StoreError {}

/// Where the serialized [`DeviceState`] lives. The bytes are secret: an
/// implementation must protect them at rest (encrypt them, or keep them
/// in the platform's key store) and must make `save` atomic.
pub trait Persist {
    /// Replace the stored state with `data`, durably, before returning.
    fn save(&mut self, data: &[u8]) -> Result<(), StoreError>;
    /// The stored state, if any.
    fn load(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError>;
    /// Remove the stored state.
    fn clear(&mut self) -> Result<(), StoreError>;
}

/// Where the pairing stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The handshake is done; the owner hasn't approved yet.
    Pending,
    /// `device.paired` arrived and checked out.
    Paired,
}

/// One deposit to the vault waiting in the outbox: an envelope already
/// sealed, deposited on the vault token held when it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    /// What it is (the inner `type`), for diagnosis and replacement.
    pub kind: String,
    /// The sealed envelope (ciphertext).
    pub payload: Vec<u8>,
    pub created: DateTime<Utc>,
    /// Its inner `exp`, if any: after it, it is dropped unsent.
    pub exp: Option<DateTime<Utc>>,
}

/// What this device knows of its vault.
#[derive(Debug, Clone)]
pub struct VaultRecord {
    pub ik: VerifyingKey,
    pub kem: PublicKey,
    pub relay: RelayAddr,
}

/// Everything the device keeps. Secret; `Debug` prints the phase only. A
/// clone is as secret (its keys wipe themselves too).
#[derive(Clone)]
pub struct DeviceState {
    pub ik_seed: Zeroizing<[u8; 32]>,
    pub kem_seed: Zeroizing<[u8; 32]>,
    pub relay_seed: Zeroizing<[u8; 32]>,
    /// This device's relay base URL (its mailbox is there).
    pub relay_url: String,
    pub vault: VaultRecord,
    /// The token this device deposits to its vault with: the request
    /// token of `hs.resp` while pending, then the standing token of
    /// `device.paired`.
    pub vault_token: Zeroizing<String>,
    pub vault_token_exp: DateTime<Utc>,
    /// When the standing token this device minted for the vault expires.
    pub issued_exp: DateTime<Utc>,
    pub phase: Phase,
    /// The end of the pairing window (10 minutes after `hs.init`, §6.7).
    pub pairing_deadline: DateTime<Utc>,
    pub device_id: Option<String>,
    pub vault_id: Option<String>,
    pub epoch: EpochState,
    /// Relay `msg_id`s handled, and when (§8.2, kept 16 days).
    pub seen: BTreeMap<String, DateTime<Utc>>,
    /// Inner `id`s handled from the vault, and until when they are kept
    /// (§8.2).
    pub seen_inner: BTreeMap<String, DateTime<Utc>>,
    /// Deposits to the vault not yet accepted by the relay, in order.
    pub outbox: Vec<OutboxEntry>,
    /// Requests sent and waiting for their response, and until when
    /// (stored, so a restart doesn't drop the answers).
    pub asked: BTreeMap<String, DateTime<Utc>>,
    /// The vault's mailbox refused this device (`token_revoked`): it has
    /// been unlinked; nothing more is sent.
    pub refused: bool,
}

impl std::fmt::Debug for DeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceState").field("phase", &self.phase).finish_non_exhaustive()
    }
}

fn role_name(r: Role) -> &'static str {
    match r {
        Role::Initiator => "initiator",
        Role::Responder => "responder",
    }
}

fn direction(key: &[u8; 32], recipient: Kid, sender: Kid) -> Zeroizing<String> {
    Zeroizing::new(
        Builder::new()
            .base64("key", key)
            .string("recipient_kid", &hex::encode(recipient.0))
            .string("sender_kid", &hex::encode(sender.0))
            .finish(),
    )
}

impl DeviceState {
    /// Room enough for the stored form, so its builders never reallocate
    /// (a reallocation would leave an unwiped copy of the secrets).
    fn capacity(&self) -> usize {
        let outbox: usize = self.outbox.iter().map(|o| o.payload.len() * 4 / 3 + o.kind.len() + 96).sum();
        16 * 1024 + self.vault_token.len() + outbox + (self.seen.len() + self.seen_inner.len()) * 64
    }

    /// The stored form: strict JSON, secret (wiped when dropped).
    pub fn to_json(&self) -> Zeroizing<String> {
        let e = &self.epoch;
        let mut eb = Builder::with_capacity(2048)
            .base64("id", &e.id)
            .string("role", role_name(e.role))
            .uint("suite", u64::from(e.suite))
            .uint("max_age_secs", e.policy.max_age.num_seconds().max(0) as u64)
            .uint("max_messages", e.policy.max_messages)
            .string("created", &format_ts(e.created))
            .bool("active", e.active);
        if let Some((k, r, s)) = &e.send {
            eb = eb.raw("send", &direction(k, *r, *s));
        }
        eb = eb.raw("recv", &direction(&e.recv.0, e.recv.1, e.recv.2));
        if let Some(rk) = &e.rk {
            eb = eb.base64("rk", &rk[..]);
        }
        let epoch = Zeroizing::new(eb.uint("last_seq", e.last_seq).uint("sent", e.sent).uint("received", e.received).finish());
        let relay = Builder::new()
            .string("url", &self.vault.relay.url)
            .string("mailbox", &self.vault.relay.mailbox)
            .base64("pk", self.vault.relay.pk.as_bytes())
            .finish();
        let vault = Builder::new().base64("ik", self.vault.ik.as_bytes()).base64("kem", self.vault.kem.as_bytes()).raw("relay", &relay).finish();
        let times = |m: &BTreeMap<String, DateTime<Utc>>| {
            m.iter().fold(Builder::with_capacity(m.len() * 64 + 16), |b, (k, t)| b.string(k, &format_ts(*t))).finish()
        };
        let outbox: Vec<String> = self
            .outbox
            .iter()
            .map(|o| {
                let b = Builder::new().string("kind", &o.kind).base64("payload", &o.payload).string("created", &format_ts(o.created));
                match o.exp {
                    Some(e) => b.string("exp", &format_ts(e)).finish(),
                    None => b.finish(),
                }
            })
            .collect();
        let mut b = Builder::with_capacity(self.capacity())
            .uint("v", STATE_VERSION)
            .base64("ik_seed", &self.ik_seed[..])
            .base64("kem_seed", &self.kem_seed[..])
            .base64("relay_seed", &self.relay_seed[..])
            .string("relay_url", &self.relay_url)
            .raw("vault", &vault)
            .string("vault_token", &self.vault_token)
            .string("vault_token_exp", &format_ts(self.vault_token_exp))
            .string("issued_exp", &format_ts(self.issued_exp))
            .string("phase", match self.phase {
                Phase::Pending => "pending",
                Phase::Paired => "paired",
            })
            .string("pairing_deadline", &format_ts(self.pairing_deadline));
        if let Some(d) = &self.device_id {
            b = b.string("device_id", d);
        }
        if let Some(v) = &self.vault_id {
            b = b.string("vault_id", v);
        }
        Zeroizing::new(
            b.raw("epoch", &epoch)
                .raw("seen", &times(&self.seen))
                .raw("seen_inner", &times(&self.seen_inner))
                .raw("outbox", &format!("[{}]", outbox.join(",")))
                .raw("asked", &times(&self.asked))
                .bool("refused", self.refused)
                .finish(),
        )
    }

    /// Read the stored form back.
    pub fn from_json(data: &[u8]) -> Result<Self, StoreError> {
        let c = |_| StoreError::Corrupt;
        let o = strict_json::parse_object(data).map_err(c)?;
        o.uint("v", STATE_VERSION, STATE_VERSION).map_err(c)?;
        let seed = |o: &Object<'_>, n: &str| -> Result<Zeroizing<[u8; 32]>, StoreError> {
            let b = Zeroizing::new(o.base64(n, Some(32)).map_err(c)?);
            Ok(Zeroizing::new(b[..].try_into().expect("checked length")))
        };
        let ts = |o: &Object<'_>, n: &str| parse_ts(&o.string(n).map_err(c)?).ok_or(StoreError::Corrupt);
        // A map of id to time; absent (a state stored before F2) is empty.
        let times = |o: &Object<'_>, n: &str| -> Result<BTreeMap<String, DateTime<Utc>>, StoreError> {
            if !o.has(n) {
                return Ok(BTreeMap::new());
            }
            let m = o.object(n, 1).map_err(c)?;
            m.names()
                .map(|k| {
                    let t = strict_json::as_string(m.get(k).expect("a name of m")).map_err(c)?;
                    Ok((k.to_string(), parse_ts(&t).ok_or(StoreError::Corrupt)?))
                })
                .collect()
        };
        let vk = |o: &Object<'_>, n: &str| -> Result<VerifyingKey, StoreError> {
            let b: [u8; 32] = o.base64(n, Some(32)).map_err(c)?.try_into().map_err(|_| StoreError::Corrupt)?;
            VerifyingKey::from_bytes(&b).map_err(|_| StoreError::Corrupt)
        };
        let v = o.object("vault", 1).map_err(c)?;
        let r = v.object("relay", 2).map_err(c)?;
        let relay = RelayAddr { url: r.string("url").map_err(c)?, mailbox: r.string("mailbox").map_err(c)?, pk: vk(&r, "pk")? };
        relay.validate().map_err(|_| StoreError::Corrupt)?;
        let vault = VaultRecord {
            ik: vk(&v, "ik")?,
            kem: PublicKey::parse(&v.base64("kem", Some(EK_SIZE)).map_err(c)?).map_err(|_| StoreError::Corrupt)?,
            relay,
        };
        let e = o.object("epoch", 1).map_err(c)?;
        let dir = |name: &str| -> Result<Option<Direction>, StoreError> {
            if !e.has(name) {
                return Ok(None);
            }
            let d = e.object(name, 2).map_err(c)?;
            let kid = |n: &str| Kid::parse_hex(&d.string(n).map_err(c)?).ok_or(StoreError::Corrupt);
            Ok(Some((seed(&d, "key")?, kid("recipient_kid")?, kid("sender_kid")?)))
        };
        let epoch = EpochState {
            id: e.base64("id", Some(16)).map_err(c)?.try_into().map_err(|_| StoreError::Corrupt)?,
            role: match e.string("role").map_err(c)?.as_str() {
                "initiator" => Role::Initiator,
                "responder" => Role::Responder,
                _ => return Err(StoreError::Corrupt),
            },
            suite: e.uint("suite", 2, 255).map_err(c)? as u8,
            policy: Policy {
                max_age: TimeDelta::seconds(e.uint("max_age_secs", 0, i64::MAX as u64).map_err(c)? as i64),
                max_messages: e.uint("max_messages", 0, strict_json::MAX_SAFE_INTEGER).map_err(c)?,
            },
            created: ts(&e, "created")?,
            active: e.bool("active").map_err(c)?,
            send: dir("send")?,
            recv: dir("recv")?.ok_or(StoreError::Corrupt)?,
            rk: if e.has("rk") { Some(seed(&e, "rk")?) } else { None },
            last_seq: e.uint("last_seq", 0, strict_json::MAX_SAFE_INTEGER).map_err(c)?,
            sent: e.uint("sent", 0, strict_json::MAX_SAFE_INTEGER).map_err(c)?,
            received: e.uint("received", 0, strict_json::MAX_SAFE_INTEGER).map_err(c)?,
        };
        Ok(DeviceState {
            ik_seed: seed(&o, "ik_seed")?,
            kem_seed: seed(&o, "kem_seed")?,
            relay_seed: seed(&o, "relay_seed")?,
            relay_url: o.string("relay_url").map_err(c)?,
            vault,
            vault_token: Zeroizing::new(o.string("vault_token").map_err(c)?),
            vault_token_exp: ts(&o, "vault_token_exp")?,
            issued_exp: ts(&o, "issued_exp")?,
            phase: match o.string("phase").map_err(c)?.as_str() {
                "pending" => Phase::Pending,
                "paired" => Phase::Paired,
                _ => return Err(StoreError::Corrupt),
            },
            pairing_deadline: ts(&o, "pairing_deadline")?,
            device_id: o.opt_string("device_id").map_err(c)?,
            vault_id: o.opt_string("vault_id").map_err(c)?,
            epoch,
            seen: times(&o, "seen")?,
            seen_inner: times(&o, "seen_inner")?,
            outbox: match o.get("outbox") {
                None => Vec::new(),
                Some(_) => o
                    .array("outbox")
                    .map_err(c)?
                    .into_iter()
                    .map(|raw| {
                        let e = strict_json::parse_object(raw.as_bytes()).map_err(c)?;
                        let exp = match e.opt_string("exp").map_err(c)? {
                            Some(x) => Some(parse_ts(&x).ok_or(StoreError::Corrupt)?),
                            None => None,
                        };
                        Ok(OutboxEntry { kind: e.string("kind").map_err(c)?, payload: e.base64("payload", None).map_err(c)?, created: ts(&e, "created")?, exp })
                    })
                    .collect::<Result<Vec<_>, StoreError>>()?,
            },
            asked: times(&o, "asked")?,
            refused: if o.has("refused") { o.bool("refused").map_err(c)? } else { false },
        })
    }

    /// Save to `store`.
    pub fn save(&self, store: &mut impl Persist) -> Result<(), StoreError> {
        store.save(self.to_json().as_bytes())
    }

    /// The paired device, if there is one. A stored state that is still
    /// pending (an app that stopped mid-pairing) is **not** a pairing: it
    /// is removed, keys included, and `None` returned. Use this, not
    /// [`DeviceState::load`], to decide whether the desktop is paired.
    pub fn load_paired(store: &mut impl Persist) -> Result<Option<Self>, StoreError> {
        match Self::load(store)? {
            Some(s) if s.phase == Phase::Paired => Ok(Some(s)),
            Some(_) => {
                store.clear()?;
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Load from `store`, if anything is stored, **pending or paired**: see
    /// [`DeviceState::load_paired`].
    pub fn load(store: &mut impl Persist) -> Result<Option<Self>, StoreError> {
        match store.load()? {
            Some(data) => Ok(Some(Self::from_json(&data)?)),
            None => Ok(None),
        }
    }
}

/// An in-memory store, for tests.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemStore {
    pub data: Option<Zeroizing<Vec<u8>>>,
    pub saves: usize,
}

#[cfg(test)]
impl Persist for MemStore {
    fn save(&mut self, data: &[u8]) -> Result<(), StoreError> {
        self.data = Some(Zeroizing::new(data.to_vec()));
        self.saves += 1;
        Ok(())
    }
    fn load(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        Ok(self.data.clone())
    }
    fn clear(&mut self) -> Result<(), StoreError> {
        self.data = None;
        Ok(())
    }
}
