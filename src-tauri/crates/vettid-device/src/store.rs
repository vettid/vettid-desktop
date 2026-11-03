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
use vettid_vms::envelope::{format_ts, parse_ts, Inner, Mode};
use vettid_vms::handshake::{EpochState, Policy, RelayAddr, ResponderState, Role};
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
    /// For an `hs.resp`: the inner id of the `hs.init` it answers, recorded
    /// as handled only once the relay has taken it.
    pub re: Option<String>,
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
    /// Previous epochs (receive key only) and when each is deleted (§6.5:
    /// 16 days).
    pub retired: Vec<(EpochState, DateTime<Utc>)>,
    /// Rekeys answered and waiting for `hs.fin` (§6.5), each with the inner
    /// id of the `hs.init` it answers.
    pub awaiting: Vec<(ResponderState, String)>,
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
    /// The `type` of each waiting request (its response must have it).
    pub asked_kinds: BTreeMap<String, String>,
    /// The vault's mailbox refused this device (`token_revoked`), or the
    /// vault said it was unlinked: nothing more is sent.
    pub refused: bool,
    /// The vault's `device.unlinked` arrived, with its `reason` (empty if
    /// none): the device was removed, and the app erases its state.
    pub unlinked: Option<String>,
    /// Events that change this device's state (`device.unlinked`,
    /// `identity.rotate`), stored before their ack and kept until the app
    /// has handled them, in order.
    pub inbox: Vec<Inner>,
    /// This device's last `device.session.end` while it waits for its
    /// answer (§6.8 "Ending"): no `device.session.request` goes out until
    /// it is settled, also after a restart (see `access`).
    pub access_end: Option<PendingEnd>,
}

/// A `device.session.end` sent and not yet answered (§6.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEnd {
    /// Its inner `id` (a retry reuses it, §8.6).
    pub id: String,
    /// The session it names, if any.
    pub session_id: Option<String>,
    /// How many times it was sent under this `id`.
    pub attempts: u32,
}

/// The most attempts a stored [`PendingEnd`] may record.
const MAX_STORED_ATTEMPTS: u64 = 255;

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
        Builder::with_capacity(160)
            .base64("key", key)
            .string("recipient_kid", &hex::encode(recipient.0))
            .string("sender_kid", &hex::encode(sender.0))
            .finish(),
    )
}

/// The room one stored epoch takes, at most.
const EPOCH_JSON: usize = 1024;

/// An epoch's stored form (secret).
fn epoch_json(e: &EpochState) -> Zeroizing<String> {
    let mut eb = Builder::with_capacity(EPOCH_JSON)
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
    Zeroizing::new(eb.uint("last_seq", e.last_seq).uint("sent", e.sent).uint("received", e.received).finish())
}

fn corrupt<E>(_: E) -> StoreError {
    StoreError::Corrupt
}

fn key32(o: &Object<'_>, n: &str) -> Result<Zeroizing<[u8; 32]>, StoreError> {
    let b = Zeroizing::new(o.base64(n, Some(32)).map_err(corrupt)?);
    Ok(Zeroizing::new(b[..].try_into().expect("checked length")))
}

fn time(o: &Object<'_>, n: &str) -> Result<DateTime<Utc>, StoreError> {
    parse_ts(&o.string(n).map_err(corrupt)?).ok_or(StoreError::Corrupt)
}

fn verifying(o: &Object<'_>, n: &str) -> Result<VerifyingKey, StoreError> {
    let b: [u8; 32] = o.base64(n, Some(32)).map_err(corrupt)?.try_into().map_err(corrupt)?;
    VerifyingKey::from_bytes(&b).map_err(corrupt)
}

/// An epoch from its stored form, at nesting `level`.
fn parse_epoch(e: &Object<'_>, level: usize) -> Result<EpochState, StoreError> {
    let c = corrupt;
    let dir = |name: &str| -> Result<Option<Direction>, StoreError> {
        if !e.has(name) {
            return Ok(None);
        }
        let d = e.object(name, level + 1).map_err(c)?;
        let kid = |n: &str| Kid::parse_hex(&d.string(n).map_err(c)?).ok_or(StoreError::Corrupt);
        Ok(Some((key32(&d, "key")?, kid("recipient_kid")?, kid("sender_kid")?)))
    };
    Ok(EpochState {
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
        created: time(e, "created")?,
        active: e.bool("active").map_err(c)?,
        send: dir("send")?,
        recv: dir("recv")?.ok_or(StoreError::Corrupt)?,
        rk: if e.has("rk") { Some(key32(e, "rk")?) } else { None },
        last_seq: e.uint("last_seq", 0, strict_json::MAX_SAFE_INTEGER).map_err(c)?,
        sent: e.uint("sent", 0, strict_json::MAX_SAFE_INTEGER).map_err(c)?,
        received: e.uint("received", 0, strict_json::MAX_SAFE_INTEGER).map_err(c)?,
    })
}

/// The elements of the array `n` (absent: none), each parsed by `f`.
fn list<T>(o: &Object<'_>, n: &str, f: impl Fn(&Object<'_>) -> Result<T, StoreError>) -> Result<Vec<T>, StoreError> {
    if o.get(n).is_none() {
        return Ok(Vec::new());
    }
    o.array(n)
        .map_err(corrupt)?
        .into_iter()
        .map(|raw| {
            let e = strict_json::parse_object(raw.as_bytes()).map_err(corrupt)?;
            f(&e)
        })
        .collect()
}

impl DeviceState {
    /// Room enough for the stored form, so its builders never reallocate
    /// (a reallocation would leave an unwiped copy of the secrets).
    fn capacity(&self) -> usize {
        let outbox: usize = self.outbox.iter().map(|o| o.payload.len() * 4 / 3 + o.kind.len() + 96).sum();
        let kinds: usize = self.asked_kinds.iter().map(|(k, v)| k.len() + v.len() + 8).sum();
        let epochs = (1 + self.retired.len() + self.awaiting.len()) * (EPOCH_JSON + 256);
        // Stored as a JSON string: escaping at most doubles compact JSON
        // (it holds no raw control characters; U+2028 is 3 bytes, 6 escaped).
        let inbox: usize = self.inbox.iter().map(|i| (i.body.len() + i.id.len() + i.kind.len() + 512) * 2 + 32).sum();
        let unlinked = self.unlinked.as_ref().map_or(0, |r| r.len() * 6 + 32);
        let end = self.access_end.as_ref().map_or(0, |p| (p.id.len() + p.session_id.as_ref().map_or(0, String::len)) * 6 + 96);
        16 * 1024
            + self.vault_token.len()
            + outbox
            + kinds
            + epochs
            + inbox
            + unlinked
            + end
            + (self.seen.len() + self.seen_inner.len() + self.asked.len()) * 64
    }

    /// The stored form: strict JSON, secret (wiped when dropped).
    pub fn to_json(&self) -> Zeroizing<String> {
        let epoch = epoch_json(&self.epoch);
        // Each list's parts, kept (and wiped) until the list is built.
        let retired_parts: Vec<Zeroizing<String>> = self
            .retired
            .iter()
            .map(|(e, until)| Zeroizing::new(Builder::with_capacity(EPOCH_JSON + 96).raw("epoch", &epoch_json(e)).string("until", &format_ts(*until)).finish()))
            .collect();
        let awaiting_parts: Vec<Zeroizing<String>> = self
            .awaiting
            .iter()
            .map(|(r, init)| {
                Zeroizing::new(
                    Builder::with_capacity(EPOCH_JSON + 256 + init.len())
                        .raw("pending", &epoch_json(&r.pending))
                        .base64("th", &r.th)
                        .base64("verify_ik", r.verify_ik.as_bytes())
                        .base64("sender", r.sender.as_bytes())
                        .string("since", &format_ts(r.since))
                        .string("init", init)
                        .finish(),
                )
            })
            .collect();
        let join = |parts: &[Zeroizing<String>]| {
            let mut out = Zeroizing::new(String::with_capacity(parts.iter().map(|p| p.len() + 1).sum::<usize>() + 2));
            out.push('[');
            for (i, p) in parts.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(p);
            }
            out.push(']');
            out
        };
        // Each inbox event as a JSON string, so its body's nesting doesn't
        // add to the state's (the parser's depth limit would refuse it).
        let inbox_parts: Vec<Zeroizing<String>> = self
            .inbox
            .iter()
            .filter_map(|i| {
                // The session inboxes only events that marshal.
                let m = i.marshal(Mode::Session);
                debug_assert!(m.is_ok(), "an inbox event marshals");
                let m = Zeroizing::new(m.ok()?);
                Some(Zeroizing::new(Builder::with_capacity(m.len() * 2 + 16).string("inner", &m).finish()))
            })
            .collect();
        let (retired, awaiting, inbox) = (join(&retired_parts), join(&awaiting_parts), join(&inbox_parts));
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
                let mut b = Builder::new().string("kind", &o.kind).base64("payload", &o.payload).string("created", &format_ts(o.created));
                if let Some(e) = o.exp {
                    b = b.string("exp", &format_ts(e));
                }
                if let Some(re) = &o.re {
                    b = b.string("re", re);
                }
                b.finish()
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
        if let Some(r) = &self.unlinked {
            b = b.string("unlinked", r);
        }
        if let Some(p) = &self.access_end {
            let mut e = Builder::new().string("id", &p.id);
            if let Some(s) = &p.session_id {
                e = e.string("session_id", s);
            }
            b = b.raw("access_end", &e.uint("attempts", u64::from(p.attempts)).finish());
        }
        let capacity = self.capacity();
        let out = Zeroizing::new(
            b.raw("epoch", &epoch)
                .raw("retired", &retired)
                .raw("awaiting", &awaiting)
                .raw("seen", &times(&self.seen))
                .raw("seen_inner", &times(&self.seen_inner))
                .raw("outbox", &format!("[{}]", outbox.join(",")))
                .raw("asked", &times(&self.asked))
                .raw(
                    "asked_kinds",
                    &self.asked_kinds.iter().fold(Builder::with_capacity(self.asked_kinds.len() * 64 + 16), |b, (k, v)| b.string(k, v)).finish(),
                )
                .bool("refused", self.refused)
                .raw("inbox", &inbox)
                .finish(),
        );
        // The builder never outgrew its capacity, so it left no unwiped
        // copy behind.
        debug_assert!(out.len() <= capacity, "state of {} bytes, capacity {capacity}", out.len());
        out
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
        let epoch = parse_epoch(&o.object("epoch", 1).map_err(c)?, 1)?;
        // Absent (a state stored before F3) is none.
        let retired = list(&o, "retired", |r| Ok((parse_epoch(&r.object("epoch", 1).map_err(c)?, 1)?, time(r, "until")?)))?;
        let awaiting = list(&o, "awaiting", |r| {
            let state = ResponderState {
                pending: parse_epoch(&r.object("pending", 1).map_err(c)?, 1)?,
                th: *key32(r, "th")?,
                verify_ik: verifying(r, "verify_ik")?,
                sender: verifying(r, "sender")?,
                since: time(r, "since")?,
            };
            Ok((state, r.string("init").map_err(c)?))
        })?;
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
            retired,
            awaiting,
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
                        let re = e.opt_string("re").map_err(c)?;
                        Ok(OutboxEntry { kind: e.string("kind").map_err(c)?, payload: e.base64("payload", None).map_err(c)?, created: ts(&e, "created")?, exp, re })
                    })
                    .collect::<Result<Vec<_>, StoreError>>()?,
            },
            asked: times(&o, "asked")?,
            asked_kinds: if o.has("asked_kinds") {
                let m = o.object("asked_kinds", 1).map_err(c)?;
                m.names()
                    .map(|k| Ok((k.to_string(), strict_json::as_string(m.get(k).expect("a name of m")).map_err(c)?)))
                    .collect::<Result<BTreeMap<_, _>, StoreError>>()?
            } else {
                BTreeMap::new()
            },
            // An unlinked device is refused, whatever was stored.
            refused: o.has("unlinked") || if o.has("refused") { o.bool("refused").map_err(c)? } else { false },
            unlinked: o.opt_string("unlinked").map_err(c)?,
            // An inbox entry this build can't read is dropped, rather than
            // lose the keys with a state refused as corrupt.
            inbox: o
                .array("inbox")
                .unwrap_or_default()
                .into_iter()
                .filter_map(|raw| {
                    let e = strict_json::parse_object(raw.as_bytes()).ok()?;
                    let inner = Zeroizing::new(e.string("inner").ok()?);
                    Inner::parse(inner.as_bytes(), Mode::Session).ok()
                })
                .collect(),
            // Absent (a state stored before access sessions) is none. One
            // that doesn't read is corrupt, not dropped: dropping it would
            // lift the ordering rule it enforces.
            access_end: if o.has("access_end") {
                let e = o.object("access_end", 1).map_err(c)?;
                if e.names().any(|n| !["id", "session_id", "attempts"].contains(&n)) {
                    return Err(StoreError::Corrupt);
                }
                let id = e.string("id").map_err(c)?;
                let session_id = e.opt_string("session_id").map_err(c)?;
                if id.is_empty() || session_id.as_ref().is_some_and(String::is_empty) {
                    return Err(StoreError::Corrupt);
                }
                Some(PendingEnd { id, session_id, attempts: e.uint("attempts", 0, MAX_STORED_ATTEMPTS).map_err(c)? as u32 })
            } else {
                None
            },
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
