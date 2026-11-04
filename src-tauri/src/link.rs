//! This desktop's link to its vault, over the relay, through the device
//! engine (`crates/vettid-device`): the paired device's [`Session`], its
//! [`Access`] session (VAULT-MESSAGING §6.8) and the [`DeviceStore`] that
//! keeps its state. It replaces the NATS client.
//!
//! **Fail secure.** The access session counts as live only as
//! [`Access::active_at`] says, after this run's own `vault.status`
//! ([`Link::refresh`]); the UI reads a [`Snapshot`] taken after every
//! operation, whose `live_until` is never later than what `active_at`
//! says. An end the vault hasn't confirmed is never reported as ended.
//!
//! **One operation at a time.** The engine is not shared: the [`Link`]
//! sits in `AppState::link`, behind a lock, and every operation holds it.
//! The background refresh ([`spawn_refresh`]) takes it once a minute; it
//! is aborted only while the lock is held (so never in the middle of an
//! operation) or when the link is dropped anyway (lock, log-out).

use std::sync::{Arc, RwLock};

use chrono::{DateTime, TimeDelta, Utc};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use vettid_device::access::{Access, AccessError, AccessEvent, EndOutcome, RequestOutcome};
use vettid_device::pairing::{Clock, SystemClock};
use vettid_device::session::{Session, SessionError};
use vettid_device::store::Persist;
use vettid_device::transport::{Http, Transport};

use crate::credential::device_store::DeviceStore;
use crate::credential::store::CredentialError;

/// The paired device's session with its vault.
pub type DeviceSession = Session<Http, SystemClock>;

// ---------------------------------------------------------------------------
// What the person is told. NEW TEXT: every string below needs the owner's
// approval before a release (none is in an earlier build).
// ---------------------------------------------------------------------------

/// NEW TEXT (owner approval needed): the pasted code isn't a desktop
/// pairing code, can't be read, or has expired.
pub const PAIR_CODE_NOTICE: &str = "This isn't a desktop pairing code, or it has expired. Start again from your phone.";
/// NEW TEXT (owner approval needed): pairing while already paired.
pub const PAIR_ALREADY_NOTICE: &str = "This desktop is already paired. To pair it again, log out in Settings first.";
/// NEW TEXT (owner approval needed): the pairing failed for any other
/// reason (the relay, the handshake, the vault's answer).
pub const PAIR_FAILED_NOTICE: &str = "Not paired: this desktop couldn't finish pairing with your vault. Start again from your phone.";
/// NEW TEXT (owner approval needed): paired, but no access session.
pub const PAIRED_NO_ACCESS_NOTICE: &str = "This desktop is paired, but your vault hasn't given it access yet. Choose Start New Session to ask your phone.";
/// NEW TEXT (owner approval needed): `too_soon` (§10.3).
pub const REQUEST_TOO_SOON_NOTICE: &str = "Your vault asks this desktop to wait before asking again. Try again in a few minutes.";
/// NEW TEXT (owner approval needed): the owner declined the request.
pub const REQUEST_DENIED_NOTICE: &str = "Your phone declined the request. This desktop has no access.";
/// NEW TEXT (owner approval needed): the request lapsed unanswered.
pub const REQUEST_LAPSED_NOTICE: &str = "Your phone didn't answer in time. This desktop has no access. Try again.";
/// NEW TEXT (owner approval needed): a lock, log-out or End session here
/// stopped the wait.
pub const REQUEST_STOPPED_NOTICE: &str = "This desktop stopped waiting for your phone. If your phone still asks, decline it there.";
/// NEW TEXT (owner approval needed): granted, but `vault.status` didn't
/// confirm it.
pub const ACCESS_NOT_CONFIRMED_NOTICE: &str = "This desktop couldn't confirm the new session with your vault, so it has no access. Try again.";
/// NEW TEXT (owner approval needed): the vault answered with an error or
/// something that doesn't check out.
pub const REQUEST_FAILED_NOTICE: &str = "Your vault didn't give this desktop access. Try again.";
/// NEW TEXT (owner approval needed): the relay or the vault didn't answer.
pub const UNREACHABLE_NOTICE: &str = "This desktop couldn't reach your vault. Try again.";
/// NEW TEXT (owner approval needed): the ordering rule (§6.8 "Ending")
/// holds the request back.
pub const END_PENDING_NOTICE: &str = "Your vault hasn't confirmed this desktop's last End session yet, so it can't ask for a new one. Try again in a minute.";
/// NEW TEXT (owner approval needed): `token_revoked` (§8.6).
pub const REFUSED_NOTICE: &str = "Your vault no longer accepts this desktop. Remove this desktop on your phone, then log out in Settings and pair again.";
/// NEW TEXT (owner approval needed): the device state couldn't be saved.
pub const NOT_SAVED_NOTICE: &str = "This desktop couldn't save its connection to your vault on this computer. Try again.";
/// NEW TEXT (owner approval needed): [`EndOutcome::Unconfirmed`].
pub const END_UNCONFIRMED_NOTICE: &str = "Your vault didn't confirm that the session ended. It may stay open until it expires: check on your phone.";
/// NEW TEXT (owner approval needed): [`EndOutcome::Replaced`]: this
/// desktop still has access.
pub const END_REPLACED_NOTICE: &str = "Your vault didn't end this desktop's access: a newer session is open. End it on your phone, or end it here again.";
/// NEW TEXT (owner approval needed): the end wasn't answered; it stays
/// stored and is sent again.
pub const END_NOT_SENT_NOTICE: &str = "This desktop couldn't reach your vault to end the session, so it may still be open. This desktop keeps trying while it runs; you can also end it on your phone.";
/// NEW TEXT (owner approval needed): `device.unlinked`, state erased.
pub const UNLINKED_ERASED_NOTICE: &str = "Your vault removed this desktop, so this desktop deleted its pairing. To use it again, pair it from your phone.";
/// NEW TEXT (owner approval needed): `device.unlinked`, erase failed.
pub const UNLINKED_NOT_ERASED_NOTICE: &str = "Your vault removed this desktop, but its pairing couldn't be deleted from this computer. Log out in Settings, then pair again.";

/// How often the background task reads `vault.status` while a session is
/// live (or an end waits for its answer).
pub const REFRESH_EVERY: std::time::Duration = std::time::Duration::from_secs(60);
/// How long after the vault last confirmed the session (a `vault.status`
/// read, a grant confirmed by one, an answered end) it is still shown as
/// active: two refreshes. Past it, the UI shows it as not confirmed.
pub const STALE_AFTER: TimeDelta = TimeDelta::seconds(2 * REFRESH_EVERY.as_secs() as i64);

/// NEW TEXT (owner approval needed): the session may still run at the
/// vault, but the vault hasn't confirmed it for [`STALE_AFTER`].
pub const STALE_NOTICE: &str = "This desktop hasn't heard from your vault for a few minutes, so it doesn't show the session as active. It shows it again once your vault confirms it.";

/// The pause after a failed poll while waiting for a grant.
const POLL_RETRY: std::time::Duration = std::time::Duration::from_secs(2);

/// A store failure's own plain notice, if it has one (the rest say only
/// "I/O error: ...", which isn't for the person).
pub fn plain_store_notice(e: &CredentialError) -> Option<String> {
    use CredentialError::*;
    match e {
        Unreadable | KeyringUnavailable | NoConfigDir | ParentNotPrivate | ParentIsLink | NoMachineId | NotPrivate
        | LoggedOutMeanwhile => Some(e.to_string()),
        _ => None,
    }
}

/// What the UI may know without waiting for the link. Taken after every
/// operation; holds no secret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// A paired device's state is open in memory.
    pub unlocked: bool,
    /// The id the vault gave this device.
    pub device_id: Option<String>,
    /// The access session the vault last named, if live.
    pub session_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    /// The last moment at which [`Access::active_at`] was true, as of the
    /// snapshot: never later.
    pub live_until: Option<DateTime<Utc>>,
    /// The last exchange with the vault got an answer.
    pub reachable: bool,
    /// The vault's mailbox refused this device (§8.6): no session is live.
    pub refused: bool,
    /// The access session is current as far as this desktop knows, but the
    /// vault hasn't confirmed it for [`STALE_AFTER`]: not shown as live.
    pub stale: bool,
}

impl Snapshot {
    /// Whether the access session is live at `t`.
    pub fn active_at(&self, t: DateTime<Utc>) -> bool {
        self.live_until.is_some_and(|u| t <= u)
    }

    /// The same, without the session: what an operation that is ending it
    /// shows meanwhile.
    pub fn without_session(&self) -> Snapshot {
        Snapshot { session_id: None, expires_at: None, live_until: None, ..self.clone() }
    }
}

/// The last whole second at or after `now` at which `access` is active,
/// found by bisection ([`Access::active_at`] is true up to a point, then
/// false): `None` if it isn't active now.
fn live_until(access: &Access, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    if !access.active_at(now) {
        return None;
    }
    let end = access.current()?.expires_at;
    let (mut lo, mut hi) = (now, end.max(now));
    if access.active_at(hi) {
        // Not reached by active_at's definition; stop at the expiry.
        return Some(hi);
    }
    while hi - lo > TimeDelta::seconds(1) {
        let mid = lo + (hi - lo) / 2;
        if access.active_at(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Some(lo)
}

/// Why an access request ended without a live session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestFailed {
    TooSoon,
    Denied,
    Lapsed,
    Stopped,
    NotConfirmed,
    Unlinked,
    Access(AccessError),
}

/// Whether the vault (or the relay on its behalf) answered, after `e`.
fn answered(e: &AccessError) -> bool {
    !matches!(e, AccessError::Session(SessionError::Relay(_) | SessionError::TimedOut))
}

/// The plain notice for a failed access operation; `store` is the store's
/// own failure, if any.
pub fn access_notice(e: &AccessError, store: Option<&CredentialError>) -> String {
    match e {
        AccessError::Session(SessionError::Refused) => REFUSED_NOTICE.into(),
        AccessError::Session(SessionError::Relay(_) | SessionError::TimedOut) => UNREACHABLE_NOTICE.into(),
        AccessError::Session(SessionError::Store(_)) => store.and_then(plain_store_notice).unwrap_or_else(|| NOT_SAVED_NOTICE.into()),
        AccessError::EndUnconfirmed => END_PENDING_NOTICE.into(),
        _ => REQUEST_FAILED_NOTICE.into(),
    }
}

/// The plain notice for a failed request.
pub fn request_notice(f: &RequestFailed, store: Option<&CredentialError>) -> String {
    match f {
        RequestFailed::TooSoon => REQUEST_TOO_SOON_NOTICE.into(),
        RequestFailed::Denied => REQUEST_DENIED_NOTICE.into(),
        RequestFailed::Lapsed => REQUEST_LAPSED_NOTICE.into(),
        RequestFailed::Stopped => REQUEST_STOPPED_NOTICE.into(),
        RequestFailed::NotConfirmed => ACCESS_NOT_CONFIRMED_NOTICE.into(),
        RequestFailed::Unlinked => UNLINKED_NOT_ERASED_NOTICE.into(),
        RequestFailed::Access(e) => access_notice(e, store),
    }
}

/// The paired device, open. Generic over the relay transport and the clock
/// only so tests can run it against a fake vault; the app uses
/// `Link<Http, SystemClock>`.
pub struct Link<T: Transport = Http, C: Clock = SystemClock> {
    pub session: Session<T, C>,
    pub store: DeviceStore,
    pub access: Access,
    /// The last exchange with the vault got an answer.
    pub reachable: bool,
    /// The mailbox was collected once after the refusal (§8.6: a
    /// `device.unlinked` may still wait there).
    refusal_polled: bool,
    /// When the vault last confirmed what this link knows of the session:
    /// a `vault.status` read, or an answered end. `None`: never in this
    /// run (no baseline).
    confirmed: Option<DateTime<Utc>>,
}

impl<T: Transport, C: Clock> std::fmt::Debug for Link<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link").field("access", &self.access).field("reachable", &self.reachable).finish_non_exhaustive()
    }
}

impl Link {
    /// Open the paired device kept in `store`: `Ok(None)` if there is none
    /// (a pending pairing left by an interrupted run is removed). On `Err`
    /// the store's own failure comes with it.
    pub fn open(mut store: DeviceStore) -> Result<Option<Link>, (SessionError, Option<CredentialError>)> {
        match Session::open(&mut store, Http::new, SystemClock) {
            Ok(Some(session)) => Ok(Some(Link::new(session, store))),
            Ok(None) => Ok(None),
            Err(e) => Err((e, store.take_failure())),
        }
    }
}

impl<T: Transport, C: Clock> Link<T, C> {
    /// The link for an opened `session` and its `store`.
    pub fn new(session: Session<T, C>, store: DeviceStore) -> Self {
        if session.access_end_unreadable() {
            log::warn!("link: the stored unanswered end didn't read; it is settled through vault.status");
        }
        Link { session, store, access: Access::new(), reachable: false, refusal_polled: false, confirmed: None }
    }

    /// The vault's mailbox refused this device (`token_revoked`, §8.6), or
    /// the vault unlinked it: nothing more is sent, and nothing it held is
    /// live.
    pub fn refused(&self) -> bool {
        self.session.is_refused()
    }

    /// After an operation: if the device has just been found refused,
    /// collect its mailbox once, where a `device.unlinked` may still wait
    /// (§8.6); [`Link::unlinked`] then says so.
    async fn note_refused(&mut self) {
        if !self.refused() || self.refusal_polled {
            return;
        }
        self.refusal_polled = true;
        log::warn!("link: the vault's mailbox refused this device");
        match self.session.poll(&mut self.store).await {
            Ok(msgs) => {
                for m in &msgs {
                    let _ = self.access.observe(&mut self.session, &mut self.store, m);
                }
            }
            Err(e) => log::info!("link: collecting after the refusal: {}", e),
        }
    }

    /// Read `vault.status`: the baseline [`Access::active_at`] needs. An
    /// unanswered end it reports is left to [`Link::refresh`] (the
    /// background refresh), so opening the pairing doesn't wait for it; a
    /// request settles it first anyway (the ordering rule, §6.8).
    pub async fn read_status(&mut self) -> Result<(), AccessError> {
        let r = self.access.read_status(&mut self.session, &mut self.store).await.map(drop);
        self.reachable = r.as_ref().err().is_none_or(answered);
        if r.is_ok() {
            self.confirmed = Some(Utc::now());
        }
        self.note_refused().await;
        r
    }

    /// Read `vault.status`, and settle a stored unanswered end if it says
    /// there is one.
    pub async fn refresh(&mut self) -> Result<(), AccessError> {
        let r = match self.access.read_status(&mut self.session, &mut self.store).await {
            Ok(read) => {
                // The status read itself confirms what it named.
                self.confirmed = Some(Utc::now());
                if read.end_pending {
                    self.access.settle(&mut self.session, &mut self.store).await.map(drop)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(e),
        };
        self.reachable = r.as_ref().err().is_none_or(answered);
        self.note_refused().await;
        r
    }

    /// The vault removed this device (`device.unlinked`).
    pub fn unlinked(&self) -> bool {
        self.session.unlinked().is_some()
    }

    /// Whether the background refresh still has something to do: a live
    /// session to keep in view (and confirmed), an end to settle, or no
    /// baseline yet (`vault.status` failed: the session is learned once the
    /// network is back). Never for a refused device.
    pub fn keep_refreshing(&self, now: DateTime<Utc>) -> bool {
        !self.refused() && (self.access.active_at(now) || self.session.access_end().is_some() || self.confirmed.is_none())
    }

    /// What the UI may see now. A refused device shows no session; a
    /// session the vault hasn't confirmed for [`STALE_AFTER`] isn't shown
    /// as live (`stale`).
    pub fn snapshot(&self, now: DateTime<Utc>) -> Snapshot {
        let refused = self.refused();
        let known = if refused { None } else { live_until(&self.access, now) };
        let cap = self.confirmed.map(|c| c + STALE_AFTER);
        let live_until = known.zip(cap).map(|(u, c)| u.min(c)).filter(|u| *u >= now);
        let stale = known.is_some() && live_until.is_none();
        let current = live_until.and(self.access.current());
        Snapshot {
            unlocked: true,
            device_id: self.session.device_id().map(str::to_string),
            session_id: current.map(|c| c.session_id.clone()),
            expires_at: current.map(|c| c.expires_at),
            live_until,
            reachable: self.reachable,
            refused,
            stale,
        }
    }

    /// Ask the owner's apps for an access session (the vault's default
    /// length), and wait for the answer until the request lapses. Ok only
    /// once `vault.status`, read after the grant, shows it live.
    /// `on_requested` runs once the vault has taken the request; `stop`
    /// is checked between polls (each at most 25 s).
    pub async fn request_access(&mut self, on_requested: impl FnOnce(), stop: impl Fn() -> bool) -> Result<(), RequestFailed> {
        let r = self.request_and_wait(on_requested, stop).await;
        self.note_refused().await;
        if self.unlinked() {
            return Err(RequestFailed::Unlinked);
        }
        r
    }

    async fn request_and_wait(&mut self, on_requested: impl FnOnce(), stop: impl Fn() -> bool) -> Result<(), RequestFailed> {
        if stop() {
            return Err(RequestFailed::Stopped);
        }
        if self.refused() {
            return Err(RequestFailed::Access(AccessError::Session(SessionError::Refused)));
        }
        let exp = match self.access.request(&mut self.session, &mut self.store, None).await {
            Ok(RequestOutcome::Requested { exp, .. }) => exp,
            Ok(RequestOutcome::TooSoon { .. }) => {
                self.reachable = true;
                return Err(RequestFailed::TooSoon);
            }
            Err(e) => {
                self.reachable = answered(&e);
                return Err(RequestFailed::Access(e));
            }
        };
        self.reachable = true;
        on_requested();
        'wait: loop {
            if stop() {
                return Err(RequestFailed::Stopped);
            }
            if Utc::now() >= exp {
                return Err(RequestFailed::Lapsed);
            }
            match self.session.poll(&mut self.store).await {
                Ok(msgs) => {
                    self.reachable = true;
                    let mut granted = false;
                    for m in &msgs {
                        match self.access.observe(&mut self.session, &mut self.store, m) {
                            Ok(Some(AccessEvent::Granted(_))) => granted = true,
                            Ok(Some(AccessEvent::Denied)) if !granted => return Err(RequestFailed::Denied),
                            _ => {}
                        }
                    }
                    if self.unlinked() {
                        return Err(RequestFailed::Unlinked);
                    }
                    if granted {
                        break 'wait;
                    }
                }
                Err(SessionError::Refused) => return Err(RequestFailed::Access(AccessError::Session(SessionError::Refused))),
                Err(e) => {
                    self.reachable = !matches!(e, SessionError::Relay(_) | SessionError::TimedOut);
                    tokio::time::sleep(POLL_RETRY).await;
                }
            }
        }
        // The vault is the only source of a device's own session (§6.8):
        // its grant is confirmed by vault.status before it is shown.
        self.refresh().await.map_err(RequestFailed::Access)?;
        if self.access.active_at(Utc::now()) && !self.refused() {
            Ok(())
        } else {
            Err(RequestFailed::NotConfirmed)
        }
    }

    /// End all of this desktop's access (the person's End session, §6.8:
    /// no session named). The session is dropped here at once.
    pub async fn end(&mut self) -> Result<EndOutcome, AccessError> {
        let r = self.access.end(&mut self.session, &mut self.store, None).await;
        self.reachable = r.as_ref().err().is_none_or(answered);
        if r.is_ok() {
            self.confirmed = Some(Utc::now());
        }
        self.note_refused().await;
        r
    }

    /// Erase this device's stored state (after `device.unlinked`): true
    /// only if the store confirms it gone.
    pub fn erase(mut self) -> bool {
        self.store.clear().is_ok()
    }
}

/// Something the person must be told that no command they ran returns
/// (the background refresh found the device refused or removed): the
/// frontend shows it ([`NOTICE_EVENT`]).
pub type Notify = Arc<RwLock<Option<Arc<dyn Fn(String) + Send + Sync>>>>;

/// The Tauri event that carries a [`Notify`] notice to the frontend.
pub const NOTICE_EVENT: &str = "vault:notice";

/// The handles the background refresh needs (clones of `AppState`'s).
#[derive(Clone)]
pub struct Shared {
    pub link: Arc<Mutex<Option<Link>>>,
    pub snapshot: Arc<RwLock<Snapshot>>,
    pub is_registered: Arc<tokio::sync::RwLock<bool>>,
    pub notify: Notify,
}

impl Shared {
    pub fn publish(&self, s: Snapshot) {
        *self.snapshot.write().unwrap_or_else(|p| p.into_inner()) = s;
    }

    pub fn read(&self) -> Snapshot {
        self.snapshot.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Tell the person `notice` (logged only, before the app is set up).
    pub fn tell(&self, notice: &str) {
        match self.notify.read().unwrap_or_else(|p| p.into_inner()).as_ref() {
            Some(f) => f(notice.to_string()),
            None => log::warn!("link: no window to tell: {}", notice),
        }
    }
}

/// How one round of the background refresh came out.
#[derive(Debug, PartialEq, Eq)]
pub enum Round {
    /// No link: nothing to do.
    Gone,
    /// Show this, and carry on.
    Continue(Snapshot),
    /// Show this, tell the person the notice if any, and stop.
    Stop(Snapshot, Option<&'static str>),
    /// The vault removed this device; its state was erased if `erased`.
    /// The link is gone from the slot.
    Unlinked { erased: bool },
}

/// One round of the background refresh on the link in `slot`: refresh,
/// then decide. A device the vault removed is erased and taken out; a
/// refused one stops with [`REFUSED_NOTICE`].
pub async fn refresh_round<T: Transport, C: Clock>(slot: &mut Option<Link<T, C>>) -> Round {
    let Some(link) = slot.as_mut() else { return Round::Gone };
    if let Err(e) = link.refresh().await {
        log::info!("link: refresh: {}", e);
    }
    if link.unlinked() {
        let link = slot.take().expect("checked above");
        return Round::Unlinked { erased: link.erase() };
    }
    let now = Utc::now();
    let snap = link.snapshot(now);
    if link.refused() {
        Round::Stop(snap, Some(REFUSED_NOTICE))
    } else if link.keep_refreshing(now) {
        Round::Continue(snap)
    } else {
        Round::Stop(snap, None)
    }
}

/// The background refresh: after `first`, then every [`REFRESH_EVERY`], a
/// [`refresh_round`], until there is nothing left to keep up
/// ([`Link::keep_refreshing`]), the link is gone, the device is refused, or
/// the vault removed it (whose state is then erased). Refused and removed
/// are told to the person.
pub fn spawn_refresh(shared: Shared, first: std::time::Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut wait = first;
        loop {
            tokio::time::sleep(wait).await;
            wait = REFRESH_EVERY;
            let mut slot = shared.link.lock().await;
            match refresh_round(&mut slot).await {
                Round::Gone => return,
                Round::Continue(snap) => shared.publish(snap),
                Round::Stop(snap, notice) => {
                    shared.publish(snap);
                    if let Some(n) = notice {
                        shared.tell(n);
                    }
                    return;
                }
                Round::Unlinked { erased } => {
                    shared.publish(Snapshot::default());
                    if erased {
                        *shared.is_registered.write().await = false;
                        log::warn!("link: the vault removed this device; its state is erased");
                        shared.tell(UNLINKED_ERASED_NOTICE);
                    } else {
                        log::error!("link: the vault removed this device; its state couldn't be erased");
                        shared.tell(UNLINKED_NOT_ERASED_NOTICE);
                    }
                    return;
                }
            }
        }
    })
}

#[cfg(test)]
pub(crate) mod fake;

#[cfg(test)]
mod tests {
    use super::*;
    use fake::FakeVault;

    #[test]
    fn a_snapshot_is_live_only_up_to_live_until() {
        let now = Utc::now();
        let s = Snapshot { unlocked: true, live_until: Some(now), ..Default::default() };
        assert!(s.active_at(now));
        assert!(!s.active_at(now + TimeDelta::seconds(1)));
        assert!(!Snapshot::default().active_at(now));
        assert!(!s.without_session().active_at(now));
        assert!(s.without_session().unlocked);
    }

    /// Before any `vault.status` there is no baseline: nothing is live.
    #[test]
    fn no_session_is_live_without_the_vaults_word() {
        assert_eq!(live_until(&Access::new(), Utc::now()), None);
    }

    /// The plain notices: an end-pending refusal, a relay failure and a
    /// refused device each get their own; a store failure with a plain
    /// notice of its own shows that one.
    #[test]
    fn failures_map_to_plain_notices() {
        use vettid_device::store::StoreError;
        assert_eq!(access_notice(&AccessError::EndUnconfirmed, None), END_PENDING_NOTICE);
        assert_eq!(access_notice(&AccessError::Session(SessionError::TimedOut), None), UNREACHABLE_NOTICE);
        assert_eq!(access_notice(&AccessError::Session(SessionError::Refused), None), REFUSED_NOTICE);
        let store = AccessError::Session(SessionError::Store(StoreError::Io));
        assert_eq!(access_notice(&store, None), NOT_SAVED_NOTICE);
        assert_eq!(access_notice(&store, Some(&CredentialError::KeyringUnavailable)), CredentialError::KeyringUnavailable.to_string());
        assert_eq!(access_notice(&store, Some(&CredentialError::IoError("x".into()))), NOT_SAVED_NOTICE);
        assert_eq!(request_notice(&RequestFailed::Denied, None), REQUEST_DENIED_NOTICE);
        assert!(!answered(&AccessError::Session(SessionError::TimedOut)));
        assert!(answered(&AccessError::Vault("x".into())));
    }

    /// The fake vault answers `vault.status` with a live session: the link
    /// shows it live after its own status read.
    #[tokio::test]
    async fn a_session_the_vault_names_is_live() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        let snap = link.snapshot(Utc::now());
        assert!(snap.active_at(Utc::now()));
        assert_eq!(snap.session_id.as_deref(), Some("s-1"));
        assert!(!snap.refused);
    }

    /// HIGH 1: a live session, then the vault's mailbox refuses the device
    /// (`token_revoked`, §8.6): the refresh shows no session, stops, and
    /// says so.
    #[tokio::test]
    async fn a_refused_device_is_not_live_and_the_refresh_stops() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        assert!(link.snapshot(Utc::now()).active_at(Utc::now()));

        vault.revoke(false);
        let mut slot = Some(link);
        match refresh_round(&mut slot).await {
            Round::Stop(snap, notice) => {
                assert!(!snap.active_at(Utc::now()), "a refused device shows no session");
                assert!(snap.refused);
                assert_eq!(snap.session_id, None);
                assert_eq!(notice, Some(REFUSED_NOTICE));
            }
            other => panic!("got {other:?}"),
        }
        let link = slot.as_ref().unwrap();
        assert!(!link.keep_refreshing(Utc::now()));
        assert!(!link.unlinked());
        assert_eq!(vault.collects(), 1, "collected once after the refusal");
    }

    /// HIGH 1: a refused device whose mailbox still holds `device.unlinked`
    /// takes the unlinked path: its state is erased.
    #[tokio::test]
    async fn a_refusal_with_device_unlinked_waiting_is_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        vault.revoke(true);
        let mut slot = Some(link);
        assert_eq!(refresh_round(&mut slot).await, Round::Unlinked { erased: true });
        assert!(slot.is_none());
        assert!(!crate::credential::device_store::exists(dir.path()), "its state is erased");
    }

    /// MEDIUM 2: a session the vault hasn't confirmed for STALE_AFTER isn't
    /// shown as live (it is "stale"), and is again once a status read
    /// confirms it.
    #[tokio::test]
    async fn an_unconfirmed_session_goes_stale() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        let now = Utc::now();
        let snap = link.snapshot(now);
        assert!(snap.active_at(now) && !snap.stale);
        assert!(snap.live_until.unwrap() <= now + STALE_AFTER, "capped at the confirmation");
        link.confirmed = Some(now - STALE_AFTER - TimeDelta::seconds(1));
        let snap = link.snapshot(now);
        assert!(!snap.active_at(now), "not shown as live");
        assert!(snap.stale);
        assert!(link.keep_refreshing(now), "the refresh keeps trying to confirm it");
        link.refresh().await.unwrap();
        assert!(link.snapshot(Utc::now()).active_at(Utc::now()));
    }

    /// LOW 7: with no baseline (no successful vault.status yet) the refresh
    /// keeps going; once the vault says there is no session, it stops.
    #[tokio::test]
    async fn the_refresh_runs_until_there_is_a_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let (_vault, mut link) = FakeVault::paired(dir.path());
        assert!(link.keep_refreshing(Utc::now()), "no baseline yet");
        link.read_status().await.unwrap();
        assert!(!link.keep_refreshing(Utc::now()), "no session, nothing to keep up");
    }

    /// A request from a refused device isn't sent, and says why.
    #[tokio::test]
    async fn a_refused_device_doesnt_ask_for_access() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.revoke(false);
        let _ = link.read_status().await;
        assert!(link.refused());
        let r = link.request_access(|| panic!("not requested"), || false).await;
        assert_eq!(r, Err(RequestFailed::Access(AccessError::Session(SessionError::Refused))));
        assert_eq!(request_notice(&r.unwrap_err(), None), REFUSED_NOTICE);
    }
}
