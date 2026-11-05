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
use vettid_device::access::{Access, AccessError, AccessEvent, EndOutcome, RequestOutcome, Settled};
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
/// NEW TEXT (owner approval needed): the owner declined a renewal while a
/// session is still live: it runs on (0.77.0).
pub const RENEWAL_DENIED_NOTICE: &str = "Your phone declined the request. The current session continues until it ends.";
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
/// After a refusal (`token_revoked`): how long between collecting the
/// mailbox again, for a `device.unlinked` that arrives later (§8.6: a
/// refused device keeps collecting its own mailbox). It goes on for as long
/// as the app runs and the device is refused but not unlinked. Each collect
/// waits at most one poll (25 s).
pub const REFUSED_RECHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(15 * 60);
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
        Unreadable | NoProtector | NotProtected { .. } | NotOpened { .. } | LegacyNotRemoved | NoConfigDir | ParentNotPrivate
        | ParentIsLink | NotPrivate | LoggedOutMeanwhile => Some(e.to_string()),
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
    /// When this desktop itself stops treating the live session as live:
    /// the last moment of [`Access::active_at`] (a margin before
    /// `expires_at`), not capped by [`STALE_AFTER`]. `None` unless live.
    /// What "Time remaining" counts down to (#82).
    pub ends_at: Option<DateTime<Utc>>,
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
    /// An End session the vault hasn't answered yet (#80): one under way,
    /// or a stored unanswered end that the refresh keeps sending. Shown as
    /// "Ending your session…", never as ended.
    pub end_pending: bool,
    /// How the background refresh last settled a stored end (#80); `None`
    /// if it hasn't, or a new End session has started since. A stored end
    /// going away is not on its own a confirmation.
    pub end_settled: Option<EndSettled>,
    /// This link has had an End session, or opened with a stored one: an
    /// end that went away without an outcome here is then "not confirmed".
    pub end_seen: bool,
}

/// How the refresh settled a stored unanswered end (#80).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndSettled {
    /// The vault answered the end `ok`, or `vault.status` names no session.
    Confirmed,
    /// Settled without that confirmation: what to tell the person.
    NotConfirmed(&'static str),
}

/// What `settle`'s result says about the end (#80). `cleared`: the stored
/// end is gone afterwards (an error answer clears it too, unconfirmed).
fn end_settled(r: &Result<Settled, AccessError>, cleared: bool) -> Option<EndSettled> {
    match r {
        Ok(Settled::Answered | Settled::StatusNull) => Some(EndSettled::Confirmed),
        Ok(Settled::OldVault) => Some(EndSettled::NotConfirmed(END_UNCONFIRMED_NOTICE)),
        Ok(Settled::Moot) => Some(EndSettled::NotConfirmed(END_REPLACED_NOTICE)),
        Ok(Settled::Clear) => None,
        Err(_) if cleared => Some(EndSettled::NotConfirmed(END_UNCONFIRMED_NOTICE)),
        Err(_) => None,
    }
}

impl Snapshot {
    /// Whether the access session is live at `t`.
    pub fn active_at(&self, t: DateTime<Utc>) -> bool {
        self.live_until.is_some_and(|u| t <= u)
    }

    /// When the live session ends, for "Time remaining" (#82): this
    /// desktop's own end of it ([`Snapshot::ends_at`]), not
    /// [`Snapshot::live_until`] (capped at [`STALE_AFTER`] past the last
    /// confirmation, which decides only whether it is shown as live).
    /// `None` unless live at `t`.
    pub fn shown_expiry(&self, t: DateTime<Utc>) -> Option<DateTime<Utc>> {
        if !self.active_at(t) {
            return None;
        }
        self.ends_at.or(self.live_until)
    }

    /// The same, without the session: what an operation that is ending it
    /// shows meanwhile (the end pending until the link's own snapshot says
    /// how it went).
    pub fn without_session(&self) -> Snapshot {
        Snapshot { session_id: None, expires_at: None, ends_at: None, live_until: None, end_pending: true, end_settled: None, end_seen: true, ..self.clone() }
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
    /// Declined while a session is live: that one runs on (0.77.0).
    DeniedWhileLive,
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
        RequestFailed::DeniedWhileLive => RENEWAL_DENIED_NOTICE.into(),
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
    /// How the refresh last settled a stored end (#80; see [`Snapshot`]).
    end_settled: Option<EndSettled>,
    /// See [`Snapshot::end_seen`].
    end_seen: bool,
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
        let end_seen = session.access_end().is_some() || session.access_end_unreadable();
        Link { session, store, access: Access::new(), reachable: false, refusal_polled: false, confirmed: None, end_settled: None, end_seen }
    }

    /// The vault's mailbox refused this device (`token_revoked`, §8.6), or
    /// the vault unlinked it: nothing more is sent, and nothing it held is
    /// live.
    pub fn refused(&self) -> bool {
        self.session.is_refused()
    }

    /// After an operation: if the device has just been found refused,
    /// collect its mailbox once, where a `device.unlinked` may still wait
    /// (§8.6); [`Link::unlinked`] then says so. Later collects are
    /// [`Link::recheck_refused`]'s.
    async fn note_refused(&mut self) {
        if !self.refused() || self.refusal_polled {
            return;
        }
        self.refusal_polled = true;
        log::warn!("link: the vault's mailbox refused this device");
        self.collect_refused().await;
    }

    /// Collect the mailbox of a refused device once more, where a
    /// `device.unlinked` sent after the refusal may now wait (§8.6);
    /// [`Link::unlinked`] then says so. Nothing is shown or claimed on a
    /// failed collect: the device stays refused, with no session.
    pub async fn recheck_refused(&mut self) {
        if self.refused() && !self.unlinked() {
            self.collect_refused().await;
        }
    }

    async fn collect_refused(&mut self) {
        match self.session.poll(&mut self.store).await {
            Ok(msgs) => {
                for m in &msgs {
                    let e = self.access.observe(&mut self.session, &mut self.store, m);
                    self.note_end_answered(&e);
                }
            }
            Err(e) => log::info!("link: collecting after the refusal: {}", e),
        }
    }

    /// Hand the messages a request collected while it waited (the engine
    /// holds them for the next poll) to [`Access::observe`], and drop
    /// them: this link only polls while it waits for a grant, so they
    /// would otherwise pile up. Missed session events are recovered by
    /// `vault.status` anyway (§6.8).
    fn drain_held(&mut self) {
        for m in self.session.take_held() {
            let e = self.access.observe(&mut self.session, &mut self.store, &m);
            self.note_end_answered(&e);
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
        self.drain_held();
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
                    let r = self.access.settle(&mut self.session, &mut self.store).await;
                    // #80: kept, so the UI tells a confirmed end from one
                    // that only stopped being sent.
                    if let Some(s) = end_settled(&r, self.session.access_end().is_none()) {
                        self.set_end_settled(s);
                    }
                    r.map(drop)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(e),
        };
        self.reachable = r.as_ref().err().is_none_or(answered);
        self.drain_held();
        self.note_refused().await;
        r
    }

    /// Record how a stored end settled (#80), with a log line the staging
    /// checks can see.
    fn set_end_settled(&mut self, s: EndSettled) {
        match &s {
            EndSettled::Confirmed => log::info!("link: the stored end is confirmed"),
            EndSettled::NotConfirmed(_) => log::info!("link: the stored end went without a confirmation"),
        }
        self.end_settled = Some(s);
    }

    /// A late `ok` to a stored end, handled on its own (`observe`): that is
    /// the vault's confirmation (#80).
    fn note_end_answered(&mut self, e: &Result<Option<AccessEvent>, AccessError>) {
        if matches!(e, Ok(Some(AccessEvent::EndAnswered))) {
            self.set_end_settled(EndSettled::Confirmed);
        }
    }

    /// The vault removed this device (`device.unlinked`).
    pub fn unlinked(&self) -> bool {
        self.session.unlinked().is_some()
    }

    /// Whether the background refresh still has something to do: a live
    /// session to keep in view (and confirmed), an end to settle, or no
    /// baseline yet (`vault.status` failed: the session is learned once the
    /// network is back). A refused device has none of those (nothing is
    /// sent to it), but its mailbox is still looked at for a
    /// `device.unlinked` (§8.6): true while it is refused and not unlinked.
    /// So whoever finds a refusal, or stops the refresh and restarts it
    /// "if needed", restarts it for that too.
    pub fn keep_refreshing(&self, now: DateTime<Utc>) -> bool {
        if self.refused() {
            return !self.unlinked();
        }
        self.access.active_at(now) || self.session.access_end().is_some() || self.confirmed.is_none()
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
            ends_at: live_until.and(known),
            live_until,
            reachable: self.reachable,
            refused,
            stale,
            end_pending: self.session.access_end().is_some(),
            end_settled: self.end_settled.clone(),
            end_seen: self.end_seen,
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
        // #80 (lead review M1): a stored unanswered end is settled here
        // first, as the ordering rule needs anyway (§6.8), so its outcome is
        // recorded; Access::request then finds nothing to settle.
        if self.session.access_end().is_some() {
            let r = self.access.settle(&mut self.session, &mut self.store).await;
            if let Some(s) = end_settled(&r, self.session.access_end().is_none()) {
                self.set_end_settled(s);
            }
            if let Err(e) = r {
                self.reachable = answered(&e);
                return Err(RequestFailed::Access(e));
            }
        }
        // Access::request (the vault's default length: nothing to check; the
        // ordering rule settled first), with the answer's ts: a denial the
        // vault sent before it is about an earlier request.
        let (answered_at, outcome) = match self.access.request_answered(&mut self.session, &mut self.store, None).await {
            Ok((outcome, ts)) => (ts, Ok(outcome)),
            Err(e) => (Utc::now(), Err(e)),
        };
        let exp = match outcome {
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
                        let e = self.access.observe(&mut self.session, &mut self.store, m);
                        self.note_end_answered(&e);
                        match e {
                            Ok(Some(AccessEvent::Granted(_))) => granted = true,
                            // A denial from before this request's answer is
                            // about an earlier one.
                            Ok(Some(AccessEvent::Denied)) if !granted && m.ts >= answered_at => {
                                return Err(if self.access.active_at(Utc::now()) { RequestFailed::DeniedWhileLive } else { RequestFailed::Denied });
                            }
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
        // A new end: an earlier one's settling no longer applies (#80).
        self.end_settled = None;
        self.end_seen = true;
        let r = self.access.end(&mut self.session, &mut self.store, None).await;
        self.reachable = r.as_ref().err().is_none_or(answered);
        if r.is_ok() {
            self.confirmed = Some(Utc::now());
        }
        // #80: this end's own outcome; a stored end still pending has none yet.
        self.end_settled = match &r {
            Ok(EndOutcome::Ended) => Some(EndSettled::Confirmed),
            Ok(EndOutcome::Unconfirmed) => Some(EndSettled::NotConfirmed(END_UNCONFIRMED_NOTICE)),
            Ok(EndOutcome::Replaced) => Some(EndSettled::NotConfirmed(END_REPLACED_NOTICE)),
            Err(_) if self.session.access_end().is_none() => Some(EndSettled::NotConfirmed(END_UNCONFIRMED_NOTICE)),
            Err(_) => None,
        };
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

/// One recheck of a refused link in `slot` ([`Link::recheck_refused`]): a
/// device the vault has removed since is erased and taken out; otherwise it
/// is left as it was (refused, no session).
pub async fn recheck_refused_round<T: Transport, C: Clock>(slot: &mut Option<Link<T, C>>) -> Round {
    let Some(link) = slot.as_mut() else { return Round::Gone };
    link.recheck_refused().await;
    if link.unlinked() {
        let link = slot.take().expect("checked above");
        return Round::Unlinked { erased: link.erase() };
    }
    Round::Continue(link.snapshot(Utc::now()))
}

/// What the person is told, and the state kept, once the vault removed the
/// device: the same wherever it was found.
async fn finish_unlinked(shared: &Shared, erased: bool) {
    shared.publish(Snapshot::default());
    if erased {
        *shared.is_registered.write().await = false;
        log::warn!("link: the vault removed this device; its state is erased");
        shared.tell(UNLINKED_ERASED_NOTICE);
    } else {
        log::error!("link: the vault removed this device; its state couldn't be erased");
        shared.tell(UNLINKED_NOT_ERASED_NOTICE);
    }
}

/// The background refresh's loop over `link`: after `first`, a
/// [`refresh_round`] every [`REFRESH_EVERY`] until there is nothing left to
/// keep up ([`Link::keep_refreshing`]) or the link is gone. A refused
/// device is told so once ([`REFUSED_NOTICE`]); from then on, and for as
/// long as it is refused but not unlinked, the loop collects its mailbox
/// every `refused_every` ([`recheck_refused_round`]), for a
/// `device.unlinked` that comes later (§8.6). `Some(erased)` once the vault
/// removed the device, `None` otherwise. Dropping or aborting the task
/// stops it (lock, log-out, End session).
pub async fn refresh_loop<T: Transport, C: Clock>(
    link: &Mutex<Option<Link<T, C>>>,
    first: std::time::Duration,
    refused_every: std::time::Duration,
    show: impl Fn(Snapshot),
    tell: impl Fn(&'static str),
) -> Option<bool> {
    let mut wait = first;
    loop {
        tokio::time::sleep(wait).await;
        let mut slot = link.lock().await;
        if slot.as_ref().is_some_and(|l| l.refused()) {
            // Already found refused (by this task, or by an operation that
            // told the person): only the slow look for `device.unlinked`.
            wait = refused_every;
            match recheck_refused_round(&mut slot).await {
                Round::Gone => return None,
                Round::Unlinked { erased } => return Some(erased),
                Round::Continue(snap) | Round::Stop(snap, _) => show(snap),
            }
            continue;
        }
        wait = REFRESH_EVERY;
        match refresh_round(&mut slot).await {
            Round::Gone => return None,
            Round::Continue(snap) => show(snap),
            Round::Stop(snap, notice) => {
                show(snap);
                if let Some(n) = notice {
                    tell(n);
                }
                if notice == Some(REFUSED_NOTICE) {
                    wait = refused_every;
                } else {
                    return None;
                }
            }
            Round::Unlinked { erased } => return Some(erased),
        }
    }
}

/// The background refresh as a task: [`refresh_loop`] over the shared link.
/// Whoever finds a refusal (this task, extend_session, End session, unlock)
/// starts it again if [`Link::keep_refreshing`], which holds for a device
/// that is refused but not unlinked.
pub fn spawn_refresh(shared: Shared, first: std::time::Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let unlinked = refresh_loop(&shared.link, first, REFUSED_RECHECK_EVERY, |snap| shared.publish(snap), |n| shared.tell(n)).await;
        if let Some(erased) = unlinked {
            finish_unlinked(&shared, erased).await;
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
        assert_eq!(access_notice(&store, Some(&CredentialError::NoProtector)), CredentialError::NoProtector.to_string());
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
        assert!(link.keep_refreshing(Utc::now()), "kept up: only to look for device.unlinked");
        assert!(!link.unlinked());
        assert_eq!(vault.collects(), 1, "collected once after the refusal");
    }

    /// #65: a `device.unlinked` that arrives after the refusal (and after
    /// the one collect that followed it) is found by a later recheck: the
    /// device is erased. Before it arrives a recheck collects again and
    /// changes nothing: still refused, no session shown.
    #[tokio::test]
    async fn a_device_unlinked_after_the_refusal_is_found_by_a_recheck() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        vault.revoke(false);
        let mut slot = Some(link);
        assert!(matches!(refresh_round(&mut slot).await, Round::Stop(_, Some(REFUSED_NOTICE))));
        assert_eq!(vault.collects(), 1, "collected once after the refusal");

        match recheck_refused_round(&mut slot).await {
            Round::Continue(snap) => {
                assert!(snap.refused);
                assert!(!snap.active_at(Utc::now()), "no session shown");
            }
            other => panic!("got {other:?}"),
        }
        assert_eq!(vault.collects(), 2, "collected again");
        assert!(slot.is_some());
        assert!(crate::credential::device_store::exists(dir.path()), "nothing erased yet");

        vault.event("device.unlinked", "{}", Utc::now());
        assert_eq!(recheck_refused_round(&mut slot).await, Round::Unlinked { erased: true });
        assert!(slot.is_none());
        assert!(!crate::credential::device_store::exists(dir.path()), "its state is erased");
        assert_eq!(recheck_refused_round(&mut slot).await, Round::Gone);
    }

    /// A refused link is rechecked for as long as it is refused: the loop
    /// repeats well past any fixed count, with a snapshot that shows no
    /// session each time.
    #[tokio::test(start_paused = true)]
    async fn the_recheck_loop_repeats_while_the_device_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.revoke(false);
        let _ = link.read_status().await;
        assert!(link.refused());
        assert_eq!(vault.collects(), 1);
        let shown = Arc::new(std::sync::Mutex::new(Vec::<Snapshot>::new()));
        let slot = Arc::new(Mutex::new(Some(link)));
        let (s2, sh2) = (slot.clone(), shown.clone());
        let every = std::time::Duration::from_secs(900);
        let task = tokio::spawn(async move {
            refresh_loop(&s2, std::time::Duration::from_secs(1), every, |snap| sh2.lock().unwrap().push(snap), |_| {}).await
        });
        for _ in 0..12 {
            tokio::time::advance(every).await;
            for _ in 0..5 {
                tokio::task::yield_now().await;
            }
        }
        assert!(vault.collects() >= 12, "collected at every period, uncapped: {}", vault.collects());
        assert!(!task.is_finished());
        assert!(shown.lock().unwrap().iter().all(|s| s.refused && !s.active_at(Utc::now())));
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    /// Aborting the task (lock, log-out, End session) stops the rechecks.
    #[tokio::test(start_paused = true)]
    async fn an_aborted_recheck_loop_collects_no_more() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.revoke(false);
        let _ = link.read_status().await;
        let slot = Arc::new(Mutex::new(Some(link)));
        let s2 = slot.clone();
        let every = std::time::Duration::from_secs(900);
        let task = tokio::spawn(async move { refresh_loop(&s2, every, every, |_| {}, |_| {}).await });
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(every).await;
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        let before = vault.collects();
        assert!(before >= 2);
        task.abort();
        let _ = task.await;
        tokio::time::advance(every * 4).await;
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert_eq!(vault.collects(), before, "no collect after the abort");
    }

    /// The loop ends when the link is gone, and when the vault's
    /// `device.unlinked` arrives (the state is erased, `Some(true)`).
    #[tokio::test(start_paused = true)]
    async fn the_recheck_loop_ends_when_gone_or_unlinked() {
        let every = std::time::Duration::from_secs(900);
        // Gone: a lock or log-out took the link.
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.revoke(false);
        let _ = link.read_status().await;
        let slot = Arc::new(Mutex::new(Some(link)));
        let s2 = slot.clone();
        let task = tokio::spawn(async move { refresh_loop(&s2, every, every, |_| {}, |_| {}).await });
        slot.lock().await.take();
        tokio::time::advance(every).await;
        assert_eq!(task.await.unwrap(), None);

        // Unlinked: found at a later round.
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.revoke(false);
        let _ = link.read_status().await;
        let slot = Arc::new(Mutex::new(Some(link)));
        let s2 = slot.clone();
        let task = tokio::spawn(async move { refresh_loop(&s2, every, every, |_| {}, |_| {}).await });
        tokio::time::advance(every).await;
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert!(!task.is_finished(), "refused, not unlinked: it goes on");
        vault.event("device.unlinked", "{}", Utc::now());
        tokio::time::advance(every).await;
        assert_eq!(task.await.unwrap(), Some(true));
        assert!(!crate::credential::device_store::exists(dir.path()), "its state is erased");
        assert!(slot.lock().await.is_none());
    }

    /// #65: a link that isn't refused is not collected by a recheck.
    #[tokio::test]
    async fn a_recheck_leaves_a_device_that_isnt_refused_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, link) = FakeVault::paired(dir.path());
        vault.revoke(false);
        vault.event("device.unlinked", "{}", Utc::now());
        let mut slot = Some(link);
        // Not yet found refused (nothing sent): nothing is collected.
        assert!(matches!(recheck_refused_round(&mut slot).await, Round::Continue(_)));
        assert_eq!(vault.collects(), 0);
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

    /// MEDIUM 4: what a status read collected besides its answer is handed
    /// to Access and dropped, not kept for a poll that never comes.
    #[tokio::test]
    async fn a_status_read_drains_what_it_collected() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.event("device.session.ended", "{\"reason\":\"ended\"}", Utc::now());
        link.read_status().await.unwrap();
        assert!(link.session.take_held().is_empty());
    }

    /// MEDIUM 4: a denial the vault sent before this request's answer (an
    /// earlier request's) doesn't end the wait; the grant that follows is
    /// confirmed by vault.status.
    #[tokio::test]
    async fn an_earlier_denial_doesnt_end_the_wait() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        link.read_status().await.unwrap();
        vault.event("device.session.ended", "{\"reason\":\"denied\"}", Utc::now() - TimeDelta::seconds(30));
        vault.grant_on_request(("s-2", Utc::now() + TimeDelta::hours(1)));
        let mut asked = false;
        link.request_access(|| asked = true, || false).await.expect("granted");
        assert!(asked);
        let snap = link.snapshot(Utc::now());
        assert!(snap.active_at(Utc::now()));
        assert_eq!(snap.session_id.as_deref(), Some("s-2"));
    }

    /// A denial sent after the request's answer ends the wait.
    #[tokio::test]
    async fn a_denial_of_this_request_ends_the_wait() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        link.read_status().await.unwrap();
        vault.deny_on_request();
        assert_eq!(link.request_access(|| {}, || false).await, Err(RequestFailed::Denied));
        assert!(!link.snapshot(Utc::now()).active_at(Utc::now()));
    }

    /// Item 3: a renewal declined while a session is live doesn't say "no
    /// access": the session runs on.
    #[tokio::test]
    async fn a_denied_renewal_leaves_the_live_session() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        vault.deny_on_request();
        let r = link.request_access(|| {}, || false).await;
        assert_eq!(r, Err(RequestFailed::DeniedWhileLive));
        assert_eq!(request_notice(&r.unwrap_err(), None), RENEWAL_DENIED_NOTICE);
        assert!(link.snapshot(Utc::now()).active_at(Utc::now()), "it runs on");
    }

    /// Item 4: an end the vault answers is Ended, and nothing is live.
    #[tokio::test]
    async fn an_answered_end_is_ended() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        assert_eq!(link.end().await, Ok(EndOutcome::Ended));
        assert!(!link.snapshot(Utc::now()).active_at(Utc::now()));
        assert!(link.session.access_end().is_none());
    }

    /// Item 4: no answer from a vault without the `session` member:
    /// Unconfirmed (never "ended").
    #[tokio::test]
    async fn an_unanswered_end_at_an_old_vault_is_unconfirmed() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        vault.end_mode(fake::EndMode::Silent);
        vault.absent_session_member();
        assert_eq!(link.end().await, Ok(EndOutcome::Unconfirmed));
    }

    /// Item 4: no answer while the vault still shows the session: the end
    /// stays stored, unconfirmed (it is sent again later).
    #[tokio::test]
    async fn an_unanswered_end_with_the_session_current_stays_pending() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        vault.end_mode(fake::EndMode::Silent);
        assert_eq!(link.end().await, Err(AccessError::EndUnconfirmed));
        assert!(link.session.access_end().is_some());
        assert!(link.keep_refreshing(Utc::now()), "settled later by the refresh");
        // #80: the UI sees the end as pending, not as done.
        let snap = link.snapshot(Utc::now());
        assert!(snap.end_pending && !snap.active_at(Utc::now()));
    }

    /// #82: "Time remaining" runs to this desktop's own end of the session
    /// (a margin before the vault's expires_at), not to the 120 s cap.
    #[tokio::test]
    async fn the_time_shown_runs_to_the_desktops_own_end() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        let exp = Utc::now() + TimeDelta::hours(1);
        vault.set_session(Some(("s-1", exp)));
        link.read_status().await.unwrap();
        let now = Utc::now();
        let snap = link.snapshot(now);
        let shown = snap.shown_expiry(now).expect("live");
        assert!(shown < exp, "a margin before the vault's expiry");
        assert!(shown > now + TimeDelta::minutes(55), "about the hour, not the cap");
        assert!(snap.live_until.unwrap() <= now + STALE_AFTER, "live still decided by the cap");
    }

    /// #80: a confirmed end isn't pending; what an end under way shows
    /// meanwhile is.
    #[tokio::test]
    async fn a_confirmed_end_isnt_pending_and_one_under_way_is() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        let before = link.snapshot(Utc::now());
        assert!(!before.end_pending);
        let meanwhile = before.without_session();
        assert!(meanwhile.end_pending && !meanwhile.active_at(Utc::now()));
        assert_eq!(link.end().await, Ok(EndOutcome::Ended));
        let after = link.snapshot(Utc::now());
        assert!(!after.end_pending, "the vault answered");
        assert_eq!(after.end_settled, Some(EndSettled::Confirmed), "#80: and that is a confirmation");
    }

    /// Item 4: no answer, and the session the resend named was replaced by
    /// a newer one: Replaced, and this desktop shows the newer session live.
    #[tokio::test]
    async fn an_end_overtaken_by_a_newer_session_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        vault.end_mode(fake::EndMode::Replace("s-2".into(), Utc::now() + TimeDelta::hours(1)));
        assert_eq!(link.end().await, Ok(EndOutcome::Replaced));
        let snap = link.snapshot(Utc::now());
        assert!(snap.active_at(Utc::now()));
        assert_eq!(snap.session_id.as_deref(), Some("s-2"));
    }

    /// Item 4: an end an earlier run left unanswered (end_pending after a
    /// restart) is settled by the refresh.
    #[tokio::test]
    async fn an_end_left_by_an_earlier_run_is_settled() {
        let dir = tempfile::tempdir().unwrap();
        let (_vault, mut link) = FakeVault::paired_with(dir.path(), true);
        assert!(link.session.access_end().is_some());
        assert!(link.keep_refreshing(Utc::now()));
        assert!(link.snapshot(Utc::now()).end_pending, "#80: shown as pending after a restart");
        link.refresh().await.unwrap();
        assert!(link.session.access_end().is_none(), "answered");
        assert!(!link.keep_refreshing(Utc::now()));
        let snap = link.snapshot(Utc::now());
        assert!(!snap.end_pending, "#80: and no longer once answered");
        assert_eq!(snap.end_settled, Some(EndSettled::Confirmed), "#80: answered, so confirmed");
    }

    /// #80 (review H1): a stored end that an old vault settles (no answer,
    /// `vault.status` without its `session` member) goes away unconfirmed:
    /// the UI is told so, never that it ended.
    #[tokio::test]
    async fn a_stored_end_settled_by_an_old_vault_is_not_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired_with(dir.path(), true);
        vault.end_mode(fake::EndMode::Silent);
        vault.absent_session_member();
        link.refresh().await.unwrap();
        let snap = link.snapshot(Utc::now());
        assert!(!snap.end_pending, "no longer sent");
        assert_eq!(snap.end_settled, Some(EndSettled::NotConfirmed(END_UNCONFIRMED_NOTICE)));
    }

    /// #80 (lead review M1): a stored end left by an offline End session is
    /// settled by Start New Session before the refresh gets to it. The
    /// vault's `ok` is recorded as a confirmation even though the request
    /// is then denied.
    #[tokio::test]
    async fn a_stored_end_settled_by_a_request_is_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired_with(dir.path(), true);
        assert!(link.snapshot(Utc::now()).end_pending);
        vault.deny_on_request();
        assert_eq!(link.request_access(|| {}, || false).await, Err(RequestFailed::Denied));
        let snap = link.snapshot(Utc::now());
        assert!(!snap.end_pending, "the request settled it first");
        assert_eq!(snap.end_settled, Some(EndSettled::Confirmed));
    }

    /// #80: the settling outcome maps as the module says; a cleared end
    /// after an error answer is not confirmed, and a still-stored one is
    /// nothing yet.
    #[test]
    fn end_settled_maps_each_outcome() {
        assert_eq!(end_settled(&Ok(Settled::Answered), true), Some(EndSettled::Confirmed));
        assert_eq!(end_settled(&Ok(Settled::StatusNull), true), Some(EndSettled::Confirmed));
        assert_eq!(end_settled(&Ok(Settled::OldVault), true), Some(EndSettled::NotConfirmed(END_UNCONFIRMED_NOTICE)));
        assert_eq!(end_settled(&Ok(Settled::Moot), true), Some(EndSettled::NotConfirmed(END_REPLACED_NOTICE)));
        assert_eq!(end_settled(&Ok(Settled::Clear), true), None);
        assert_eq!(end_settled(&Err(AccessError::Vault("x".into())), true), Some(EndSettled::NotConfirmed(END_UNCONFIRMED_NOTICE)));
        assert_eq!(end_settled(&Err(AccessError::EndUnconfirmed), false), None);
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
