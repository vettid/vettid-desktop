//! Pairing a desktop with its vault (VAULT-MESSAGING §6.7), as the vault's
//! Go device client does it (`client.startPairing`, `awaitHandshake`,
//! `awaitPaired`):
//!
//! 1. Read the code the member's phone shows (QR or pasted), which must be
//!    a desktop pairing code (`t` = `d`) that hasn't expired.
//! 2. Make fresh keys (identity, KEM, relay) and register this device's
//!    mailbox on the code's relay.
//! 3. Fetch the claim (single use) and open the bundle (§6.4).
//! 4. Mint the vault's standing token ([`crate::token`]) and send
//!    `hs.init` (purpose `desktop`) on the bundle's open token.
//! 5. Collect `hs.resp` from the vault's relay key, check the request
//!    token it carries, store the pending pairing, send `hs.fin` on that
//!    token, and show the SAS: the member compares it on their phone.
//! 6. Wait, under the handshake's still-inactive epoch, for the owner's
//!    answer until 10 minutes after `hs.init`: `device.paired` (check its
//!    standing token, activate the epoch, store, then ack) or
//!    `device.pair.rejected` (forget the pairing).
//!
//! **Fail secure.** The desktop is paired only once a `device.paired`
//! from the vault's relay key, under the handshake's keys, with a valid
//! standing token for this device, has been stored. Anything else (no
//! answer, a malformed answer, a deposit that may not have arrived) is
//! "not paired", and the pairing state is removed when the window ends.

use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use vettid_relay::auth::decode_key;
use vettid_relay::client::{Message, RelayError};
use vettid_relay::token::Token;
use vettid_vms::envelope::{Envelope, Mode};
use vettid_vms::handshake::{Epoch, HandshakeError, Initiator, InitiatorConfig, Purpose, RelayAddr, POLICY_VAULT_TO_DEVICE};
use vettid_vms::invite::{open_bundle, InviteError, Kind, Qr};
use vettid_vms::strict_json::{self, Builder};
use vettid_vms::suite::kem::PrivateKey;
use zeroize::Zeroizing;

use crate::display::{shown_name, CONFIRM_ON_PHONE};
use crate::store::{DeviceState, Persist, Phase, StoreError, VaultRecord};
use crate::token::{check_from_vault, mint_for_vault};
use crate::transport::Transport;

/// How long a pairing waits after `hs.init` (§6.7).
pub const PAIRING_WINDOW: TimeDelta = TimeDelta::minutes(10);
/// The long-poll wait per collect, and the batch size.
const COLLECT_WAIT_SECS: u64 = 25;
const COLLECT_MAX: u32 = 32;
/// The longest device name sent in `hs.init`'s profile.
pub const MAX_DEVICE_NAME: usize = 64;

const DEVICE_PAIRED: &str = "device.paired";
const DEVICE_PAIR_REJECTED: &str = "device.pair.rejected";

/// The time, so tests can move it.
pub trait Clock {
    fn now(&self) -> DateTime<Utc>;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Why a pairing failed. None of these means "paired".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairError {
    /// The code couldn't be read, or its bundle was refused.
    Code(InviteError),
    /// The code isn't a desktop pairing code.
    NotForDesktop,
    /// The code has expired.
    Expired,
    /// A relay call failed.
    Relay(RelayError),
    /// A deposit failed and certainly wasn't delivered.
    NotSent(RelayError),
    /// The handshake failed.
    Handshake(HandshakeError),
    /// A token from the vault isn't valid for this device.
    Token,
    /// The device state couldn't be stored.
    Store(StoreError),
    /// Fresh keys couldn't be made.
    Keys,
    /// The owner rejected the pairing on their phone.
    Rejected,
    /// The pairing window ended without an answer.
    TimedOut,
}

impl std::fmt::Display for PairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code(e) => write!(f, "pairing: {e}"),
            Self::NotForDesktop => f.write_str("pairing: not a desktop pairing code"),
            Self::Expired => f.write_str("pairing: the code has expired"),
            Self::Relay(e) | Self::NotSent(e) => write!(f, "pairing: {e}"),
            Self::Handshake(e) => write!(f, "pairing: {e}"),
            Self::Token => f.write_str("pairing: the vault's token is not valid for this device"),
            Self::Store(e) => write!(f, "pairing: {e}"),
            Self::Keys => f.write_str("pairing: keys could not be made"),
            Self::Rejected => f.write_str(crate::display::REJECTED_ON_PHONE),
            Self::TimedOut => f.write_str(crate::display::NOT_CONFIRMED),
        }
    }
}

impl std::error::Error for PairError {}

impl From<RelayError> for PairError {
    fn from(e: RelayError) -> Self {
        Self::Relay(e)
    }
}

impl From<StoreError> for PairError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// What `device.paired` told this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paired {
    pub device_id: String,
    pub vault_id: Option<String>,
}

/// A pairing whose handshake is done, waiting for the owner. `Debug`
/// prints nothing secret.
pub struct Pairing<T: Transport, C: Clock> {
    transport: T,
    clock: C,
    state: DeviceState,
    epoch: Epoch,
    sas: String,
    inviter: Option<String>,
}

impl<T: Transport, C: Clock> std::fmt::Debug for Pairing<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pairing").field("phase", &self.state.phase).finish_non_exhaustive()
    }
}

fn seed() -> Result<Zeroizing<[u8; 32]>, PairError> {
    let mut s = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.try_fill_bytes(&mut s[..]).map_err(|_| PairError::Keys)?;
    Ok(s)
}

/// Deposit, treating "maybe delivered" as sent (the receiver dedupes) and
/// "certainly not delivered" as a failure.
async fn deposit(t: &impl Transport, to: &RelayAddr, token: &Token, payload: &[u8]) -> Result<(), PairError> {
    match t.deposit(&to.url, &to.mailbox, token, payload).await {
        Ok(_) => Ok(()),
        Err(e) if e.possibly_delivered => Ok(()),
        Err(e) => Err(PairError::NotSent(e.error)),
    }
}

/// Start pairing from `code`: steps 1–5 above. `device_name` is this
/// desktop's name, sent to the vault (the member sees it on their phone).
/// `make_transport` gets this device's new relay key.
pub async fn start<T: Transport, C: Clock>(
    code: &str,
    device_name: &str,
    make_transport: impl FnOnce(SigningKey) -> T,
    store: &mut impl Persist,
    clock: C,
) -> Result<Pairing<T, C>, PairError> {
    let now = clock.now();
    let qr = Qr::parse_any(code).map_err(PairError::Code)?;
    if qr.kind != Kind::Desktop {
        return Err(PairError::NotForDesktop);
    }
    if qr.expired(now) {
        return Err(PairError::Expired);
    }
    let (ik_seed, kem_seed, relay_seed) = (seed()?, seed()?, seed()?);
    let ik = SigningKey::from_bytes(&ik_seed);
    let kem = PrivateKey::from_seed(&kem_seed).map_err(|_| PairError::Keys)?;
    let relay_key = SigningKey::from_bytes(&relay_seed);
    let own_pk = relay_key.verifying_key();
    let transport = make_transport(relay_key.clone());
    let own_url = qr.relay.clone();
    let registration = transport.register(&own_url).await?;
    let blob = transport.get_claim(&qr.relay, &qr.claim_id).await?;
    let bundle = open_bundle(&blob, &qr, Kind::Desktop, now).map_err(PairError::Code)?;
    let vault = VaultRecord { ik: bundle.vault.ik, kem: bundle.vault.kem.clone(), relay: bundle.vault.relay.clone() };

    let (standing, issued_exp) =
        mint_for_vault(&relay_key, &own_url, &vault.relay.pk, now, registration.limits.max_token_lifetime_seconds).map_err(|_| PairError::Token)?;
    let name = shown_name(device_name).unwrap_or_else(|| "Desktop".into());
    let name: String = name.chars().take(MAX_DEVICE_NAME).collect();
    let mut initiator = Initiator::new(InitiatorConfig {
        purpose: Purpose::Desktop,
        ctx: bundle.invite_id.clone(),
        identity: ik.clone(),
        static_kem: kem.public().clone(),
        relay: RelayAddr { url: own_url.clone(), mailbox: registration.mailbox_id.clone(), pk: own_pk },
        token: Some(standing.into_string()),
        suites: vec![],
        profile: Some(Builder::new().string("name", &name).finish()),
        anonymous_sender: false,
        responder_ik: vault.ik,
        responder_ek: vault.kem.clone(),
        responder_relay_key: vault.relay.pk,
        pinned_suite: 0,
        policy: POLICY_VAULT_TO_DEVICE,
        id: None,
        fin_id: None,
        now,
    })
    .map_err(PairError::Handshake)?;
    let deadline = now + PAIRING_WINDOW;
    deposit(&transport, &vault.relay, &Token::from_received(bundle.token.clone()), initiator.envelope()).await?;

    // Step 5: hs.resp. Anything that isn't it is acked and dropped.
    loop {
        if clock.now() >= deadline {
            return Err(PairError::TimedOut);
        }
        for m in transport.collect(&own_url, COLLECT_WAIT_SECS, COLLECT_MAX).await? {
            let out = match resp_candidate(&m, &initiator) {
                Some(sender) => match initiator.handle_resp(&m.payload, &sender, clock.now()) {
                    Ok(out) => out,
                    Err(e) => {
                        transport.ack(&own_url, &m.msg_id).await?;
                        if initiator.is_done() {
                            // It decrypted and failed: the handshake is over.
                            return Err(PairError::Handshake(e));
                        }
                        continue;
                    }
                },
                None => {
                    transport.ack(&own_url, &m.msg_id).await?;
                    continue;
                }
            };
            let now = clock.now();
            let request = out.resp.token.clone().ok_or(PairError::Token)?;
            let request_exp = check_from_vault(&request, &vault.relay.pk, &own_pk, now).map_err(|_| PairError::Token)?;
            let state = DeviceState {
                ik_seed,
                kem_seed,
                relay_seed,
                relay_url: own_url.clone(),
                vault: vault.clone(),
                vault_token: Zeroizing::new(request.clone()),
                vault_token_exp: request_exp,
                issued_exp,
                phase: Phase::Pending,
                pairing_deadline: deadline,
                device_id: None,
                vault_id: None,
                epoch: out.epoch.snapshot(),
            };
            // Stored before hs.fin goes out and before hs.resp is acked.
            state.save(store)?;
            deposit(&transport, &vault.relay, &Token::from_received(request), &out.fin).await?;
            transport.ack(&own_url, &m.msg_id).await?;
            return Ok(Pairing {
                transport,
                clock,
                state,
                epoch: out.epoch,
                sas: out.sas.ok_or(PairError::Handshake(HandshakeError::Body))?,
                inviter: bundle.hint_name.as_deref().and_then(shown_name),
            });
        }
    }
}

/// The relay sender, if `m` may be this handshake's `hs.resp`: a sealed
/// envelope addressed to its ephemeral key, from a decodable relay key.
fn resp_candidate(m: &Message, initiator: &Initiator) -> Option<VerifyingKey> {
    let sender = decode_key(&m.sender)?;
    let env = Envelope::parse(&m.payload).ok()?;
    (env.mode() == Mode::Sealed && env.recipient_kid().ct_eq(&initiator.eph_kid())).then_some(sender)
}

impl<T: Transport, C: Clock> Pairing<T, C> {
    /// The SAS, six digits, to compare with the member's phone.
    pub fn sas(&self) -> &str {
        &self.sas
    }

    /// What to say with the SAS: confirm on the phone.
    pub fn instruction(&self) -> &'static str {
        CONFIRM_ON_PHONE
    }

    /// The inviter's name from the code, as plain text to show (§6.4: the
    /// code's maker wrote it; it is not verified).
    pub fn inviter_name(&self) -> Option<&str> {
        self.inviter.as_deref()
    }

    /// When the pairing window ends.
    pub fn deadline(&self) -> DateTime<Utc> {
        self.state.pairing_deadline
    }

    /// Wait for the owner's answer (step 6). On `Ok` the device is paired
    /// and stored; on any `Err` it is not, and the pairing state is gone
    /// from `store`.
    pub async fn wait_for_approval(mut self, store: &mut impl Persist) -> Result<(Paired, DeviceState), PairError> {
        let result = self.wait(store).await;
        if result.is_err() {
            store.clear()?;
        }
        result.map(|p| (p, self.state))
    }

    async fn wait(&mut self, store: &mut impl Persist) -> Result<Paired, PairError> {
        let own_url = self.state.relay_url.clone();
        let own_pk = SigningKey::from_bytes(&self.state.relay_seed).verifying_key();
        loop {
            if self.clock.now() >= self.state.pairing_deadline {
                return Err(PairError::TimedOut);
            }
            for m in self.transport.collect(&own_url, COLLECT_WAIT_SECS, COLLECT_MAX).await? {
                let now = self.clock.now();
                match self.answer(&m, &own_pk, now) {
                    Answer::Paired(token, exp, paired) => {
                        self.epoch.activate(now);
                        self.state.phase = Phase::Paired;
                        self.state.vault_token = token;
                        self.state.vault_token_exp = exp;
                        self.state.device_id = Some(paired.device_id.clone());
                        self.state.vault_id = paired.vault_id.clone();
                        self.state.epoch = self.epoch.snapshot();
                        // Stored before device.paired is acked (§8.3).
                        self.state.save(store)?;
                        self.transport.ack(&own_url, &m.msg_id).await?;
                        return Ok(paired);
                    }
                    Answer::Rejected => {
                        self.transport.ack(&own_url, &m.msg_id).await?;
                        return Err(PairError::Rejected);
                    }
                    Answer::Drop => self.transport.ack(&own_url, &m.msg_id).await?,
                }
            }
        }
    }

    /// What one collected message is: only the vault's relay key, under
    /// the handshake's epoch, fresh, and a well-formed answer counts.
    fn answer(&mut self, m: &Message, own_pk: &VerifyingKey, now: DateTime<Utc>) -> Answer {
        let vault = &self.state.vault.relay;
        let from_vault = decode_key(&m.sender).is_some_and(|s| s.as_bytes() == vault.pk.as_bytes());
        let Some(env) = from_vault.then(|| Envelope::parse(&m.payload).ok()).flatten() else { return Answer::Drop };
        let Ok(inner) = self.epoch.open(&env) else { return Answer::Drop };
        if inner.check_time(now, true).is_err() || inner.response.is_some() {
            return Answer::Drop;
        }
        match inner.kind.as_str() {
            DEVICE_PAIR_REJECTED => Answer::Rejected,
            DEVICE_PAIRED => match paired_body(&inner.body) {
                Some((paired, token)) => match check_from_vault(&token, &vault.pk, own_pk, now) {
                    Ok(exp) => Answer::Paired(token, exp, paired),
                    Err(_) => Answer::Drop,
                },
                None => Answer::Drop,
            },
            _ => Answer::Drop,
        }
    }
}

enum Answer {
    Paired(Zeroizing<String>, DateTime<Utc>, Paired),
    Rejected,
    Drop,
}

/// `device.paired`'s body (§10.3) for a desktop: `device_id`, `role`
/// `desktop`, the standing `token`, and `vault_id` if given.
fn paired_body(body: &str) -> Option<(Paired, Zeroizing<String>)> {
    let o = strict_json::parse_object(body.as_bytes()).ok()?;
    let device_id = o.string("device_id").ok().filter(|d| !d.is_empty() && d.len() <= 128)?;
    if o.string("role").ok()? != "desktop" {
        return None;
    }
    let token = Zeroizing::new(o.string("token").ok()?);
    let vault_id = o.opt_string("vault_id").ok()?;
    Some((Paired { device_id, vault_id }, token))
}

#[cfg(test)]
mod tests;
