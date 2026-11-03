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
//! answer, a malformed answer, a deposit that certainly didn't arrive) is
//! "not paired", and every failure after the pending pairing was stored
//! removes it again, keys included. A temporary relay failure is retried
//! until the window ends; once the answer is stored, a failed ack is
//! harmless (the relay redelivers, and the message is a duplicate).

use std::future::Future;

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
/// The longest long-poll wait per collect, and the batch size.
const COLLECT_WAIT_SECS: i64 = 25;
const COLLECT_MAX: u32 = 32;
/// The longest device name sent in `hs.init`'s profile.
pub const MAX_DEVICE_NAME: usize = 64;
/// Retry backoff for temporary relay failures.
const BACKOFF_START_MS: u64 = 250;
const BACKOFF_MAX_MS: u64 = 10_000;

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
    /// A relay call failed for good (or until the window ended).
    Relay(RelayError),
    /// A deposit failed and certainly wasn't delivered.
    NotSent(RelayError),
    /// The handshake failed.
    Handshake(HandshakeError),
    /// A token from the vault isn't valid for this device.
    Token,
    /// The vault's answer (under the handshake's keys) doesn't check out:
    /// its body, role or token is wrong.
    BadAnswer,
    /// The device state couldn't be stored.
    Store(StoreError),
    /// Fresh keys couldn't be made.
    Keys,
    /// This desktop is already paired: a new pairing would overwrite its
    /// keys. Unpair it first.
    AlreadyPaired,
    /// The owner rejected the pairing on their phone.
    Rejected,
    /// The pairing window ended without an answer.
    TimedOut,
    /// The pairing failed as the inner error says, **and** its stored
    /// state (keys included) could not be removed: the caller must try
    /// again or tell the person.
    NotCleared(Box<PairError>),
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
            Self::BadAnswer => f.write_str("pairing: the vault's answer did not check out"),
            Self::Store(e) => write!(f, "pairing: {e}"),
            Self::Keys => f.write_str("pairing: keys could not be made"),
            Self::AlreadyPaired => f.write_str("pairing: this desktop is already paired"),
            Self::Rejected => f.write_str(crate::display::REJECTED_ON_PHONE),
            Self::TimedOut => f.write_str(crate::display::NOT_CONFIRMED),
            Self::NotCleared(e) => write!(f, "{e}; and the pairing's stored keys could not be removed"),
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

/// Remove the stored state after `e`; if that fails too, say so.
fn cleared(store: &mut impl Persist, e: PairError) -> PairError {
    match store.clear() {
        Ok(()) => e,
        Err(_) => PairError::NotCleared(Box::new(e)),
    }
}

/// Run `op` until it succeeds, fails for good, or the window ends:
/// temporary relay failures (`retryable`) are retried with backoff.
async fn retrying<R, Fut>(clock: &impl Clock, deadline: DateTime<Utc>, mut op: impl FnMut() -> Fut) -> Result<R, PairError>
where
    Fut: Future<Output = Result<R, RelayError>>,
{
    let mut delay = BACKOFF_START_MS;
    loop {
        match op().await {
            Ok(r) => return Ok(r),
            Err(e) if e.retryable() && clock.now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                delay = (delay * 2).min(BACKOFF_MAX_MS);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// The long-poll wait: 1–25 s, and no longer than the window (the floor
/// keeps collect from spinning near the end).
fn wait_secs(clock: &impl Clock, deadline: DateTime<Utc>) -> u64 {
    (deadline - clock.now()).num_seconds().clamp(1, COLLECT_WAIT_SECS) as u64
}

/// Deposit, treating "maybe delivered" as sent (the receiver dedupes) and
/// "certainly not delivered" as a failure. A temporary failure that
/// certainly didn't deliver (a connection that never opened, say) is
/// retried with backoff until `deadline`; one that may have delivered is
/// not resent (an open token is single use).
async fn deposit(
    t: &impl Transport,
    clock: &impl Clock,
    deadline: DateTime<Utc>,
    to: &RelayAddr,
    token: &Token,
    payload: &[u8],
) -> Result<(), PairError> {
    let mut delay = BACKOFF_START_MS;
    loop {
        match t.deposit(&to.url, &to.mailbox, token, payload).await {
            Ok(_) => return Ok(()),
            Err(e) if e.possibly_delivered => return Ok(()),
            Err(e) if e.error.retryable() && clock.now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                delay = (delay * 2).min(BACKOFF_MAX_MS);
            }
            Err(e) => return Err(PairError::NotSent(e.error)),
        }
    }
}

/// Start pairing from `code`: steps 1–5 above. `device_name` is this
/// desktop's name, sent to the vault (the member sees it on their phone).
/// `make_transport` gets this device's new relay key. On any error nothing
/// is left in `store` (or [`PairError::NotCleared`] says otherwise). A
/// desktop that is already paired is refused (`AlreadyPaired`) before
/// anything is spent: its keys are never overwritten. A pending state left
/// by an earlier, interrupted pairing is removed first.
pub async fn start<T: Transport, C: Clock>(
    code: &str,
    device_name: &str,
    make_transport: impl FnOnce(SigningKey) -> T,
    store: &mut impl Persist,
    clock: C,
) -> Result<Pairing<T, C>, PairError> {
    if DeviceState::load_paired(store)?.is_some() {
        return Err(PairError::AlreadyPaired);
    }
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
    // The code's own expiry bounds these steps, and never more than a
    // pairing window from now.
    let code_exp = i64::try_from(qr.exp).ok().and_then(|e| DateTime::from_timestamp(e, 0)).unwrap_or(now);
    let code_deadline = code_exp.min(now + PAIRING_WINDOW);
    let registration = retrying(&clock, code_deadline, || transport.register(&own_url)).await?;
    // Not retried: a claim is single-fetch, and a lost answer means it is gone.
    let blob = transport.get_claim(&qr.relay, &qr.claim_id).await?;
    let bundle = open_bundle(&blob, &qr, Kind::Desktop, clock.now()).map_err(PairError::Code)?;
    let vault = VaultRecord { ik: bundle.vault.ik, kem: bundle.vault.kem.clone(), relay: bundle.vault.relay.clone() };

    let now = clock.now();
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
    deposit(&transport, &clock, deadline, &vault.relay, &Token::from_received(bundle.token.clone()), initiator.envelope()).await?;

    // Step 5: hs.resp. Anything that isn't it is acked and dropped.
    let (out, resp_msg) = 'resp: loop {
        if clock.now() >= deadline {
            return Err(PairError::TimedOut);
        }
        let batch = retrying(&clock, deadline, || transport.collect(&own_url, wait_secs(&clock, deadline), COLLECT_MAX)).await?;
        for m in batch {
            if clock.now() >= deadline {
                return Err(PairError::TimedOut);
            }
            if let Some(sender) = resp_candidate(&m, &initiator) {
                match initiator.handle_resp(&m.payload, &sender, clock.now()) {
                    Ok(out) => break 'resp (out, m.msg_id),
                    Err(e) if initiator.is_done() => {
                        // It decrypted and failed: the handshake is over.
                        let _ = transport.ack(&own_url, &m.msg_id).await;
                        return Err(PairError::Handshake(e));
                    }
                    Err(_) => {}
                }
            }
            retrying(&clock, deadline, || transport.ack(&own_url, &m.msg_id)).await?;
        }
    };
    let now = clock.now();
    let request = out.resp.token.clone().ok_or(PairError::Token)?;
    let request_exp = check_from_vault(&request, &vault.relay.pk, &own_pk, now).map_err(|_| PairError::Token)?;
    let sas = out.sas.clone().ok_or(PairError::Handshake(HandshakeError::Body))?;
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
        seen: Default::default(),
        seen_inner: Default::default(),
        outbox: Vec::new(),
        asked: Default::default(),
        refused: false,
    };
    // Stored before hs.fin goes out and before hs.resp is acked; from here
    // on, any failure removes it again.
    state.save(store)?;
    if let Err(e) = deposit(&transport, &clock, deadline, &vault.relay, &Token::from_received(request), &out.fin).await {
        return Err(cleared(store, e));
    }
    // Best effort: the state is stored, so a redelivered hs.resp is only a
    // duplicate (it no longer decrypts under the finished handshake).
    let _ = transport.ack(&own_url, &resp_msg).await;
    Ok(Pairing { transport, clock, state, epoch: out.epoch, sas, inviter: bundle.hint_name.as_deref().and_then(shown_name) })
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

    /// Give up (the person cancelled): the pending pairing and its keys
    /// are removed. The vault drops its side when its window ends.
    pub fn cancel(self, store: &mut impl Persist) -> Result<(), PairError> {
        store.clear().map_err(|_| PairError::NotCleared(Box::new(PairError::TimedOut)))
    }

    /// Wait for the owner's answer (step 6). On `Ok` the device is paired
    /// and stored; on any `Err` it is not, and the pairing state is gone
    /// from `store` (or [`PairError::NotCleared`] says otherwise).
    pub async fn wait_for_approval(mut self, store: &mut impl Persist) -> Result<(Paired, DeviceState), PairError> {
        match self.wait(store).await {
            Ok(p) => Ok((p, self.state)),
            Err(e) => Err(cleared(store, e)),
        }
    }

    async fn wait(&mut self, store: &mut impl Persist) -> Result<Paired, PairError> {
        let own_url = self.state.relay_url.clone();
        let own_pk = SigningKey::from_bytes(&self.state.relay_seed).verifying_key();
        let deadline = self.state.pairing_deadline;
        loop {
            if self.clock.now() >= deadline {
                return Err(PairError::TimedOut);
            }
            let (transport, clock) = (&self.transport, &self.clock);
            let batch = retrying(clock, deadline, || transport.collect(&own_url, wait_secs(clock, deadline), COLLECT_MAX)).await?;
            for m in batch {
                let now = self.clock.now();
                if now >= deadline {
                    return Err(PairError::TimedOut);
                }
                match self.answer(&m, &own_pk, now) {
                    Answer::Paired(token, exp, paired) => {
                        self.epoch.activate(now);
                        self.state.phase = Phase::Paired;
                        self.state.vault_token = token;
                        self.state.vault_token_exp = exp;
                        self.state.device_id = Some(paired.device_id.clone());
                        self.state.vault_id = paired.vault_id.clone();
                        self.state.epoch = self.epoch.snapshot();
                        // Stored before device.paired is acked (§8.3). Once
                        // stored, a failed ack is harmless.
                        self.state.save(store)?;
                        let _ = self.transport.ack(&own_url, &m.msg_id).await;
                        return Ok(paired);
                    }
                    Answer::Rejected => {
                        let _ = self.transport.ack(&own_url, &m.msg_id).await;
                        return Err(PairError::Rejected);
                    }
                    Answer::Bad => {
                        let _ = self.transport.ack(&own_url, &m.msg_id).await;
                        return Err(PairError::BadAnswer);
                    }
                    Answer::Drop => {
                        let (transport, clock) = (&self.transport, &self.clock);
                        retrying(clock, deadline, || transport.ack(&own_url, &m.msg_id)).await?;
                    }
                }
            }
        }
    }

    /// What one collected message is. Only the vault's relay key, under
    /// the handshake's epoch, fresh, and not a response, can answer; such a
    /// message (only the vault can write one) that doesn't check out ends
    /// the pairing. Anything else is dropped.
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
                    Err(_) => Answer::Bad,
                },
                None => Answer::Bad,
            },
            _ => Answer::Drop,
        }
    }
}

enum Answer {
    Paired(Zeroizing<String>, DateTime<Utc>, Paired),
    Rejected,
    /// A `device.paired` from the vault that doesn't check out.
    Bad,
    Drop,
}

/// `device.paired`'s body (§10.3) for a desktop: `device_id`, `role`
/// `desktop`, the standing `token` (required here: a device without its
/// standing token can't reach its vault for long), and `vault_id` if
/// given.
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
