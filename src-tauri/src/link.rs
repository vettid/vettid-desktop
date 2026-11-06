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
//! **The vault's lock and hold** (VAULT-LOCK-PLAN §3.1): [`Access`] keeps
//! what the vault said ([`VaultState`]); this link adds the decay. `Open`
//! becomes `Unknown` when a status read goes unanswered, when the vault
//! hasn't confirmed it for [`STALE_AFTER`], and on [`Link::resumed`].
//! `Locked` stays while the relay answers and the status doesn't (a
//! locked vault collects nothing, §12.1); when the relay can't be reached,
//! or after a resume, it is shown "as of" the last time it was confirmed
//! (owner decision 2, 2026-11-05), until the relay answers again or a
//! status does. The desktop never sends `vault.lock` (owner decision,
//! 2026-11-05).
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
use vettid_device::access::{Access, AccessError, AccessEvent, EndOutcome, LockReason, RequestOutcome, Settled, StatusRead, VaultState, Waiting, OWNER_CHECK_REQUIRED};
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
/// `too_soon` (§10.3) with a time to name: the frontend says "You can ask
/// again at {time}." in the computer's own locale (#83). This text stays
/// for any other caller.
pub const REQUEST_TOO_SOON_NOTICE: &str = "Your vault asks this desktop to wait before asking again. Try again in a few minutes.";
/// NEW TEXT (owner approval needed, #83): `too_soon` when the time is
/// within a minute, or already past (the clocks differ).
pub const REQUEST_TOO_SOON_NOW_NOTICE: &str = "Your vault asks this desktop to wait before asking again. Try again in a minute.";

/// When the person may ask again (#83), for the frontend to show in its
/// own locale: the vault's `allowed_after`, rounded up to the next whole
/// minute so it is never too early. `None` within a minute of `now`, or if
/// already past (the clocks differ): then the notice says "in a minute".
pub fn too_soon_retry_at(at: DateTime<Utc>, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    if at <= now + TimeDelta::minutes(1) {
        return None;
    }
    let secs = at.timestamp();
    let whole = secs.rem_euclid(60) == 0 && at.timestamp_subsec_nanos() == 0;
    let up = if whole { secs } else { (secs.div_euclid(60) + 1) * 60 };
    DateTime::<Utc>::from_timestamp(up, 0)
}
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

/// The vault is held (VAULT-LOCK-PLAN §3.4 "Held", approved by the owner,
/// decision 3, 2026-11-05): what a request that the hold ended says.
pub const VAULT_HELD_NOTICE: &str = "Your vault is waiting for your daily check. Open VettID on your phone to continue.";
/// The vault was locked (VAULT-LOCK-PLAN §3.4 "Locked", approved by the
/// owner, decision 3, 2026-11-05): what a request that the lock ended says.
pub const VAULT_LOCKED_NOTICE: &str = "Your vault was locked. Unlock it on your phone to continue.";
/// The vault's state isn't known (VAULT-LOCK-PLAN §3.4 "Unknown", approved
/// by the owner, decision 3, 2026-11-05): what a request refused for that
/// says.
pub const VAULT_UNKNOWN_NOTICE: &str = "This desktop can't tell whether your vault is open. It keeps checking.";

/// How often the background task reads `vault.status` while a session is
/// live (or an end waits for its answer, or the vault is held, locked or
/// unknown).
pub const REFRESH_EVERY: std::time::Duration = std::time::Duration::from_secs(60);
/// The longest wait between refreshes while the vault is locked or unknown
/// and its status requests reach the relay unanswered (VAULT-LOCK-PLAN
/// §3.1, lead review): from [`REFRESH_EVERY`], doubling to this. A locked
/// vault collects nothing (§12.1), so each unanswered read waits at the
/// relay, in the mailbox's quota, until the vault unlocks or it expires.
/// Five minutes, not more: a desktop gets no notice of an unlock, so this
/// is how late it can be to see one (lead review).
pub const LOCKED_REFRESH_MAX: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// A window focus reads `vault.status` only when the vault hasn't confirmed
/// its state for this long ([`Link::focused`]).
pub const FOCUS_RECHECK_AFTER: TimeDelta = TimeDelta::seconds(15);

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
    /// A paired device's state is open in memory (false before unlock, or
    /// after one that failed; the vault's lock is [`Snapshot::vault`]).
    pub link_open: bool,
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
    /// The vault's lock and hold, as far as this desktop knows
    /// (VAULT-LOCK-PLAN §3.1).
    pub vault: VaultView,
    /// The publish counter (#77): set by [`Shared::publish`], one more than
    /// the snapshot it replaces, so the frontend can drop a read that
    /// returns an older snapshot than one it has already applied.
    pub seq: u64,
}

/// The vault's state as the UI shows it (VAULT-LOCK-PLAN §3.1, §3.3): what
/// [`Access::vault`] says, after this link's decay. Holds no secret (no
/// `unlock_id`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct VaultView {
    /// As of the snapshot: read it through [`VaultView::at`] (or
    /// [`Snapshot::vault_at`]), which turns an `Open` past `open_until`
    /// into `Unknown`.
    pub state: VaultShown,
    /// Open: until when it counts as confirmed (the last confirmation plus
    /// [`STALE_AFTER`]). Past it, [`VaultView::at`] shows `Unknown`.
    pub open_until: Option<DateTime<Utc>>,
    /// Open, past the deadline with the hold off (§3.6.7): the session
    /// continues.
    pub due: bool,
    /// Held: the counts, if the vault gave them. `None`: not known (never
    /// zeros, §3.6.5).
    pub waiting: Option<Counts>,
    /// Held: the owner check's deadline, if known.
    pub deadline: Option<DateTime<Utc>>,
    /// Held: when the vault locks itself unless the check is done
    /// (§3.6.8; owner decision 4, 2026-11-05).
    pub idle_lock_at: Option<DateTime<Utc>>,
    /// Locked: the `ts` of the vault's lock notice.
    pub locked_since: Option<DateTime<Utc>>,
    /// Locked, but this desktop can't check now (the relay can't be
    /// reached, or since a resume): when it was last confirmed, "locked as
    /// of" (owner decision 2, 2026-11-05). `None` otherwise.
    pub as_of: Option<DateTime<Utc>>,
    /// Locked: `"idle"`, `"owner_check"` or `"recovery"`; `None` for a lock
    /// without a known reason.
    pub reason: Option<&'static str>,
}

impl VaultView {
    /// `Open` until `until` (a confirmation plus [`STALE_AFTER`]).
    pub fn open(until: DateTime<Utc>) -> Self {
        VaultView { state: VaultShown::Open, open_until: Some(until), ..Default::default() }
    }

    /// The view at `t`: an `Open` past its `open_until` (or without one)
    /// is `Unknown`, as a session past its `live_until` is not live. A
    /// stored snapshot read late (after a suspend, or while a command holds
    /// the link) never shows an old `Open` (lead review).
    pub fn at(&self, t: DateTime<Utc>) -> VaultView {
        if self.state == VaultShown::Open && self.open_until.is_none_or(|u| t > u) {
            VaultView::default()
        } else {
            self.clone()
        }
    }
}

/// Which state [`VaultView`] shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultShown {
    /// Nothing current from the vault: "can't tell whether your vault is
    /// open". The default.
    #[default]
    Unknown,
    Open,
    Held,
    Locked,
}

/// The counts of what waits while the vault is held (§3.6.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct Counts {
    pub messages: u64,
    pub requests: u64,
    pub calls: u64,
    pub other: u64,
}

impl From<Waiting> for Counts {
    fn from(w: Waiting) -> Self {
        Counts { messages: w.messages, requests: w.requests, calls: w.calls, other: w.other }
    }
}

fn reason_name(r: LockReason) -> &'static str {
    match r {
        LockReason::Idle => "idle",
        LockReason::OwnerCheck => "owner_check",
        LockReason::Recovery => "recovery",
    }
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
    /// Whether the access session is live at `t`: up to `live_until`, and
    /// while the vault view at `t` is Open ([`Snapshot::vault_at`]).
    pub fn active_at(&self, t: DateTime<Utc>) -> bool {
        self.live_until.is_some_and(|u| t <= u) && self.vault_at(t).state == VaultShown::Open
    }

    /// The vault's state at `t` ([`VaultView::at`]): what every reader of a
    /// stored snapshot shows.
    pub fn vault_at(&self, t: DateTime<Utc>) -> VaultView {
        self.vault.at(t)
    }

    /// Whether the session is current as far as this desktop knows but not
    /// shown live for lack of the vault's word, at `t`: `stale` as of the
    /// snapshot, or a session shown then whose Open has since run out.
    pub fn stale_at(&self, t: DateTime<Utc>) -> bool {
        self.stale || (self.session_id.is_some() && self.vault.state == VaultShown::Open && self.vault_at(t).state == VaultShown::Unknown)
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
    /// Too soon after the last request; the vault's `allowed_after`.
    TooSoon(DateTime<Utc>),
    Denied,
    /// Declined while a session is live: that one runs on (0.77.0).
    DeniedWhileLive,
    Lapsed,
    Stopped,
    NotConfirmed,
    Unlinked,
    /// The vault entered its hold while the request waited, or refused it
    /// `owner_check_required`: the vault drops pending requests (§3.6.3).
    Held,
    /// The vault was locked while the request waited (VAULT-LOCK-PLAN
    /// §3.1), or before it was sent (then it isn't sent). It may still
    /// grant one that waited after an unlock: that session is shown live
    /// only once a `vault.status` names it.
    Locked,
    /// Not sent: this desktop doesn't know that the vault is open, even
    /// after reading its status (lead review).
    Unknown,
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
        RequestFailed::TooSoon(at) => match too_soon_retry_at(*at, Utc::now()) {
            Some(_) => REQUEST_TOO_SOON_NOTICE.into(),
            None => REQUEST_TOO_SOON_NOW_NOTICE.into(),
        },
        RequestFailed::Denied => REQUEST_DENIED_NOTICE.into(),
        RequestFailed::DeniedWhileLive => RENEWAL_DENIED_NOTICE.into(),
        RequestFailed::Lapsed => REQUEST_LAPSED_NOTICE.into(),
        RequestFailed::Stopped => REQUEST_STOPPED_NOTICE.into(),
        RequestFailed::NotConfirmed => ACCESS_NOT_CONFIRMED_NOTICE.into(),
        RequestFailed::Unlinked => UNLINKED_NOT_ERASED_NOTICE.into(),
        RequestFailed::Held => VAULT_HELD_NOTICE.into(),
        RequestFailed::Locked => VAULT_LOCKED_NOTICE.into(),
        RequestFailed::Unknown => VAULT_UNKNOWN_NOTICE.into(),
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
    /// When the vault last confirmed what this link knows of its lock and
    /// hold: a `vault.status` answer, a lock notice applied, or (while
    /// locked) a status read that reached the relay and got no answer.
    vault_checked: Option<DateTime<Utc>>,
    /// Locked, but not checked since a resume or a status read the relay
    /// couldn't take: shown "as of" `vault_checked`.
    locked_as_of: bool,
    /// The wait before the next refresh while the vault is locked or
    /// unknown and status reads reach the relay unanswered: `None` is
    /// [`REFRESH_EVERY`] (see [`Link::next_wait`]).
    backoff: Option<std::time::Duration>,
    /// A vault notice or a resume asks for the next refresh at once.
    read_now: bool,
    /// What the refresh loop records of its own rounds ([`LoopMarks`]).
    /// Shared with the loop, which writes to it without the link's lock,
    /// and kept in the link, so that a loop restarted by a command after a
    /// sleep still sees the gap ([`refresh_loop`], [`slept_through`]).
    marks: Arc<std::sync::Mutex<LoopMarks>>,
    /// How many times [`Link::resumed`] ran (for the logs and the tests).
    resumes: u32,
    /// When this link last sent a `vault.status` of its own (answered or
    /// not): what a focus read is throttled on ([`Link::focused`]).
    last_attempt: Option<DateTime<Utc>>,
}

/// What the refresh loop records of its own rounds, by the wall clock.
/// Written without the link's lock, so that time a command spends holding
/// the lock (a request waiting minutes for the phone) never reads as a
/// sleep (lead review).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoopMarks {
    /// When the loop's next round is due: set before each wait, and moved
    /// to at least a refresh later whenever the vault answers an operation
    /// that holds the lock.
    pub due: Option<DateTime<Utc>>,
    /// When the loop woke for that round, recorded before it waits for the
    /// lock; `None` while it sleeps.
    pub woke: Option<DateTime<Utc>>,
}

impl LoopMarks {
    /// Whether these marks show a sleep, at `now`: the loop woke well past
    /// its round ([`slept_through`] at `woke`, whatever came after while
    /// it waited for the lock); or, if it hasn't woken since, `now` is
    /// well past the round, so its timer didn't run on time (a suspend
    /// that the monotonic clock didn't count).
    pub fn slept(&self, now: DateTime<Utc>) -> bool {
        self.due.is_some_and(|d| slept_through(d, self.woke.unwrap_or(now)))
    }
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
        Link {
            session,
            store,
            access: Access::new(),
            reachable: false,
            refusal_polled: false,
            confirmed: None,
            end_settled: None,
            end_seen,
            vault_checked: None,
            locked_as_of: false,
            backoff: None,
            read_now: false,
            marks: Arc::default(),
            resumes: 0,
            last_attempt: None,
        }
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
                    self.noted(&e);
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
            self.noted(&e);
        }
    }

    /// What this link keeps of an observed message's outcome: a late `ok`
    /// to a stored end (#80), and a lock notice applied (confirmed now).
    /// Any lock or hold notice resets the backoff and asks for the next
    /// refresh at once.
    fn noted(&mut self, e: &Result<Option<AccessEvent>, AccessError>) {
        self.note_end_answered(e);
        if matches!(e, Ok(Some(AccessEvent::Locked))) {
            log::info!("link: the vault says it locked");
            self.vault_checked = Some(Utc::now());
            self.locked_as_of = false;
        }
        if matches!(e, Ok(Some(AccessEvent::Locked | AccessEvent::Held | AccessEvent::ReadStatus))) {
            self.backoff = None;
            self.read_now = true;
        }
    }

    /// How long the refresh loop waits before its next round
    /// (VAULT-LOCK-PLAN §3.1, lead review): at once after a vault notice or
    /// a resume; [`REFRESH_EVERY`] while the vault is open or held (it
    /// answers then, and [`STALE_AFTER`] needs it); while it is locked or
    /// unknown, the backoff, from [`REFRESH_EVERY`] doubling to
    /// [`LOCKED_REFRESH_MAX`], which grows only while the status requests
    /// reach the relay and go unanswered. Takes the "at once".
    pub fn next_wait(&mut self, now: DateTime<Utc>) -> std::time::Duration {
        if std::mem::take(&mut self.read_now) {
            return std::time::Duration::ZERO;
        }
        match self.vault_now(now) {
            VaultState::Locked { .. } | VaultState::Unknown => self.backoff.unwrap_or(REFRESH_EVERY),
            VaultState::Open { .. } | VaultState::Held { .. } => REFRESH_EVERY,
        }
    }

    /// The refresh loop's marks, shared with it.
    pub fn loop_marks(&self) -> Arc<std::sync::Mutex<LoopMarks>> {
        self.marks.clone()
    }

    fn marks(&self) -> std::sync::MutexGuard<'_, LoopMarks> {
        self.marks.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The refresh loop starts (at the app's start, or restarted by a
    /// command): if the previous loop's marks show a sleep
    /// ([`LoopMarks::slept`]), [`Link::resumed`]. Never from time a
    /// command held the lock: the old loop recorded its waking before it
    /// waited for it. The backoff starts again from [`REFRESH_EVERY`].
    /// Returns the loop's first wait: `first`, or none at all when a read
    /// is asked for at once (a vault notice, a resume, a focus): a restart
    /// doesn't drop it.
    pub fn refresh_started(&mut self, now: DateTime<Utc>, first: std::time::Duration) -> std::time::Duration {
        self.check_gap(now);
        self.backoff = None;
        let first = if std::mem::take(&mut self.read_now) { std::time::Duration::ZERO } else { first };
        *self.marks() = LoopMarks { due: due_after(now, first), woke: None };
        first
    }

    /// The window gained focus: [`Link::focused`], and if a read is due, a
    /// [`Link::refresh`] (`vault.status`, and a stored unanswered end
    /// settled, #80). The refresh loop's schedule, marks and backoff are
    /// left to it (lead review): a focus doesn't push its rounds back.
    /// True if it read.
    pub async fn focus_read(&mut self) -> bool {
        if self.refused() || !self.focused(Utc::now()) {
            return false;
        }
        if let Err(e) = self.refresh().await {
            log::info!("link: focus read: {}", e);
        }
        true
    }

    /// The window gained focus (VAULT-LOCK-PLAN §3.1): a sleep the marks
    /// show is a resume ([`Link::resumed`]); and whether `vault.status`
    /// should be read now. Yes when a read is asked for at once (a resume,
    /// a notice). Otherwise it is throttled on the last status *sent*,
    /// answered or not (lead review): while Open or Held, one at most every
    /// [`FOCUS_RECHECK_AFTER`] (focus comes with every switch of window);
    /// while Locked or Unknown, not before the refresh loop's backoff since
    /// then, so that switching windows neither adds reads that wait at the
    /// relay of a locked vault nor holds the link meanwhile.
    pub fn focused(&mut self, now: DateTime<Utc>) -> bool {
        self.check_gap(now);
        if std::mem::take(&mut self.read_now) {
            return true;
        }
        let wait = match self.vault_now(now) {
            VaultState::Open { .. } | VaultState::Held { .. } => FOCUS_RECHECK_AFTER,
            VaultState::Locked { .. } | VaultState::Unknown => TimeDelta::from_std(self.backoff.unwrap_or(REFRESH_EVERY)).unwrap_or(TimeDelta::MAX),
        };
        self.last_attempt.is_none_or(|a| a.checked_add_signed(wait).is_some_and(|due| now >= due))
    }

    /// The refresh loop has the lock for a round: [`Link::resumed`] if its
    /// marks show a sleep.
    pub fn refresh_woke(&mut self, now: DateTime<Utc>) {
        self.check_gap(now);
    }

    fn check_gap(&mut self, now: DateTime<Utc>) {
        let slept = self.marks().slept(now);
        if slept {
            log::info!("link: the computer slept; the vault's state is checked again");
            self.resumed();
        }
    }

    /// The vault answered an operation that holds the lock: no sleep before
    /// now is left to find, and the loop's round counts from here at the
    /// earliest (a round set for later stays: its wake is no sleep).
    fn vault_answered(&self) {
        let mut m = self.marks();
        m.due = m.due.max(due_after(Utc::now(), REFRESH_EVERY));
    }

    /// `vault.status`, once, and what its outcome says of the vault
    /// (VAULT-LOCK-PLAN §3.1). Answered: confirmed now. Unanswered (the
    /// relay or the vault didn't answer): `Open` and `Held` become
    /// `Unknown` (a held vault answers `vault.status`); and `Locked` stays
    /// `Locked` only on evidence that the relay took this status request
    /// and a collect got through after it, with the last collect not
    /// failed ([`Session::last_request_reached`],
    /// [`Session::relay_failed`]): a locked vault answers nothing (§12.1).
    /// Without that evidence (out of reach, a deposit refused for now, the
    /// outbox held after a 429 or a 5xx) it is shown "as of" (lead review
    /// M4).
    async fn status_once(&mut self) -> Result<StatusRead, AccessError> {
        self.last_attempt = Some(Utc::now());
        let r = self.access.read_status(&mut self.session, &mut self.store).await;
        let now = Utc::now();
        match &r {
            Ok(_) => {
                // The status read itself confirms what it named.
                self.confirmed = Some(now);
                self.vault_checked = Some(now);
                self.locked_as_of = false;
                // Answered: the refresh goes back to its pace, and a gap is
                // measured from here at the earliest.
                self.backoff = None;
                self.vault_answered();
            }
            Err(e) if !answered(e) => {
                self.access.status_unanswered();
                let reached = self.session.last_request_reached() && !self.session.relay_failed();
                if matches!(self.access.vault(), VaultState::Locked { .. }) {
                    if reached {
                        self.locked_as_of = false;
                        self.vault_checked = Some(now);
                    } else {
                        self.locked_as_of = true;
                    }
                }
                // Locked or unknown, and the read waits at the relay: the
                // next one waits longer, so that an overnight lock doesn't
                // fill the mailbox with reads (lead review).
                if reached && matches!(self.access.vault(), VaultState::Locked { .. } | VaultState::Unknown) {
                    self.backoff = Some(match self.backoff {
                        None => REFRESH_EVERY,
                        Some(b) => (b * 2).min(LOCKED_REFRESH_MAX),
                    });
                }
            }
            Err(_) => {}
        }
        r
    }

    /// A lock or hold notice asked for `vault.status` now
    /// ([`Access::take_status_wanted`]): read it once more. A further ask
    /// from what that read collected waits for the next refresh.
    async fn status_if_wanted(&mut self) {
        if !self.access.take_status_wanted() {
            return;
        }
        let r = self.status_once().await;
        self.reachable = r.as_ref().err().is_none_or(answered);
        self.drain_held();
    }

    /// `Open`, but the vault hasn't confirmed it within [`STALE_AFTER`]:
    /// it is then `Unknown` (VAULT-LOCK-PLAN §3.1).
    fn vault_stale(&self, now: DateTime<Utc>) -> bool {
        matches!(self.access.vault(), VaultState::Open { .. }) && self.vault_checked.is_none_or(|c| now > c + STALE_AFTER)
    }

    /// What this link knows of the vault at `now`: [`Access::vault`], with
    /// an `Open` past [`STALE_AFTER`] taken as `Unknown`.
    pub fn vault_now(&self, now: DateTime<Utc>) -> VaultState {
        if self.vault_stale(now) {
            VaultState::Unknown
        } else {
            self.access.vault().clone()
        }
    }

    /// After sleep, hibernation or a resume (VAULT-LOCK-PLAN §3.1): `Open`
    /// becomes `Unknown`, and `Locked` is shown "as of" the last time it
    /// was confirmed, until a status answers (or the relay does, and the
    /// status still doesn't). The app then reads `vault.status`.
    pub fn resumed(&mut self) {
        self.resumes += 1;
        self.backoff = None;
        self.read_now = true;
        self.access.vault_unconfirmed();
        if matches!(self.access.vault(), VaultState::Locked { .. }) {
            self.locked_as_of = true;
        }
    }

    /// The vault's state as the UI shows it, at `now`.
    fn vault_view(&self, now: DateTime<Utc>) -> VaultView {
        match self.vault_now(now) {
            VaultState::Unknown => VaultView::default(),
            VaultState::Open { due, .. } => match self.vault_checked.map(|c| c + STALE_AFTER) {
                Some(until) => VaultView { due, ..VaultView::open(until) },
                // Not reached: vault_now shows an unconfirmed Open as Unknown.
                None => VaultView::default(),
            },
            VaultState::Held { deadline, waiting, idle_lock_at } => {
                VaultView { state: VaultShown::Held, waiting: waiting.map(Counts::from), deadline, idle_lock_at, ..Default::default() }
            }
            VaultState::Locked { since, reason } => VaultView {
                state: VaultShown::Locked,
                locked_since: Some(since),
                as_of: self.locked_as_of.then(|| self.vault_checked.unwrap_or(since)),
                reason: reason.map(reason_name),
                ..Default::default()
            },
        }
    }

    /// Why a session request may not go now, if it may not: the vault is
    /// held or locked, or (after a status read, here and now) still not
    /// known to be open.
    async fn not_open_for_a_request(&mut self) -> Option<RequestFailed> {
        let refusal = |v: VaultState| match v {
            VaultState::Open { .. } => None,
            VaultState::Held { .. } => Some(RequestFailed::Held),
            VaultState::Locked { .. } => Some(RequestFailed::Locked),
            VaultState::Unknown => Some(RequestFailed::Unknown),
        };
        if let VaultState::Unknown = self.vault_now(Utc::now()) {
            if self.vault_stale(Utc::now()) {
                self.access.vault_unconfirmed();
            }
            let r = self.status_once().await;
            self.reachable = r.as_ref().err().is_none_or(answered);
            self.drain_held();
        }
        refusal(self.vault_now(Utc::now()))
    }

    /// Held or locked by a statement the vault made at or after `since`
    /// (the `ts` of its answer to a request): what ends that request's
    /// wait (VAULT-LOCK-PLAN §3.1). A hold or lock from before it is over
    /// (the vault took the request).
    fn stopped_since(&self, since: DateTime<Utc>) -> Option<RequestFailed> {
        if self.access.vault_learned_at().is_none_or(|at| at < since) {
            return None;
        }
        match self.access.vault() {
            VaultState::Held { .. } => Some(RequestFailed::Held),
            VaultState::Locked { .. } => Some(RequestFailed::Locked),
            _ => None,
        }
    }

    /// Read `vault.status`: the baseline [`Access::active_at`] needs. An
    /// unanswered end it reports is left to [`Link::refresh`] (the
    /// background refresh), so opening the pairing doesn't wait for it; a
    /// request settles it first anyway (the ordering rule, §6.8).
    pub async fn read_status(&mut self) -> Result<(), AccessError> {
        if self.vault_stale(Utc::now()) {
            self.access.vault_unconfirmed();
        }
        let r = self.status_once().await.map(drop);
        self.reachable = r.as_ref().err().is_none_or(answered);
        self.drain_held();
        self.status_if_wanted().await;
        self.note_refused().await;
        r
    }

    /// Read `vault.status`, and settle a stored unanswered end if it says
    /// there is one.
    pub async fn refresh(&mut self) -> Result<(), AccessError> {
        if self.vault_stale(Utc::now()) {
            self.access.vault_unconfirmed();
        }
        let r = match self.status_once().await {
            Ok(read) => {
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
        self.status_if_wanted().await;
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

    /// Whether the background refresh still has something to do. While
    /// the link is open, always: the vault's state is kept in view in every
    /// state, Open included, so that a lock whose notice was missed decays
    /// Open to Unknown (VAULT-LOCK-PLAN §3.1; lead review M2), besides a
    /// live session to keep confirmed, an end to settle and a baseline to
    /// get. A refused device has none of those (nothing is
    /// sent to it), but its mailbox is still looked at for a
    /// `device.unlinked` (§8.6): true while it is refused and not unlinked.
    /// So whoever finds a refusal, or stops the refresh and restarts it
    /// "if needed", restarts it for that too.
    pub fn keep_refreshing(&self, _now: DateTime<Utc>) -> bool {
        !self.refused() || !self.unlinked()
    }

    /// What the UI may see now. A refused device shows no session; a
    /// session the vault hasn't confirmed for [`STALE_AFTER`] isn't shown
    /// as live (`stale`).
    pub fn snapshot(&self, now: DateTime<Utc>) -> Snapshot {
        let refused = self.refused();
        let known = if refused { None } else { live_until(&self.access, now) };
        let cap = self.confirmed.map(|c| c + STALE_AFTER);
        let vault = if refused { VaultView::default() } else { self.vault_view(now) };
        // Live only while the vault view is Open too, so the session's cap
        // (`confirmed`, which an answered end also sets) and the vault's
        // (`vault_checked`) can't disagree (lead review L3).
        let live_until = known.zip(cap).map(|(u, c)| u.min(c)).filter(|u| *u >= now).filter(|_| vault.state == VaultShown::Open);
        // A session this desktop holds that isn't shown live for lack of
        // the vault's word: only while the vault view is Unknown. Held and
        // Locked are the vault's word, not a lack of it (lead review).
        let held_session = self.access.current().is_some_and(|c| c.expires_at > now);
        let stale = !refused && vault.state == VaultShown::Unknown && held_session && live_until.is_none();
        let current = live_until.and(self.access.current());
        Snapshot {
            link_open: true,
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
            // A refused device knows nothing of the vault.
            vault,
            // Set when published (Shared::publish).
            seq: 0,
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
        // Defense in depth (lead review): no request while the vault isn't
        // Open, so none waits at the relay through a lock or a hold and is
        // granted after an unlock nobody expected. Unknown: the status is
        // read first; the request goes only if it says Open.
        if let Some(f) = self.not_open_for_a_request().await {
            return Err(f);
        }
        // Access::request (the vault's default length: nothing to check; the
        // ordering rule settled first), with the answer's ts: a denial the
        // vault sent before it is about an earlier request.
        let (answered_at, outcome) = match self.access.request_answered(&mut self.session, &mut self.store, None).await {
            Ok((outcome, ts)) => (ts, Ok(outcome)),
            Err(e) => (Utc::now(), Err(e)),
        };
        if outcome.as_ref().err().is_none_or(answered) {
            self.vault_answered();
        }
        let exp = match outcome {
            Ok(RequestOutcome::Requested { exp, .. }) => exp,
            Ok(RequestOutcome::TooSoon { allowed_after }) => {
                self.reachable = true;
                return Err(RequestFailed::TooSoon(allowed_after));
            }
            // Refused while held (§3.6.3): Access has the vault held.
            Err(AccessError::Vault(code)) if code == OWNER_CHECK_REQUIRED => {
                self.reachable = true;
                return Err(RequestFailed::Held);
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
                    if !msgs.is_empty() {
                        self.vault_answered();
                    }
                    let mut granted = false;
                    for m in &msgs {
                        let e = self.access.observe(&mut self.session, &mut self.store, m);
                        self.noted(&e);
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
                    // VAULT-LOCK-PLAN §3.1: held (the vault drops pending
                    // requests, §3.6.3) or locked since the vault took this
                    // request: the wait ends, a grant in the same batch
                    // included (it is shown only once a status names it).
                    if let Some(f) = self.stopped_since(answered_at) {
                        return Err(f);
                    }
                    if granted {
                        break 'wait;
                    }
                    // A lock notice this desktop couldn't place: the status
                    // says where the vault is (its answer, and what else it
                    // collected, come with the next poll's batch first).
                    if self.access.take_status_wanted() {
                        let _ = self.status_once().await;
                        if let Some(f) = self.stopped_since(answered_at) {
                            return Err(f);
                        }
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
        if let Some(f) = self.stopped_since(answered_at) {
            return Err(f);
        }
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
            self.vault_answered();
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

/// Called when a published snapshot changes what the UI shows of the
/// vault's state or whether a session is live (#77): the frontend reads the
/// session again at once ([`CHANGED_EVENT`]) instead of on its next poll.
pub type Changed = Arc<RwLock<Option<Arc<dyn Fn() + Send + Sync>>>>;

/// The Tauri event a [`Changed`] call emits (no payload).
pub const CHANGED_EVENT: &str = "vault:changed";

/// What a change of which [`Shared::publish`] tells the UI at once:
/// everything the screen shows of the vault at `now` (its state, Locked
/// "as of" or not, the reason, the counts, the deadline, `idle_lock_at`,
/// `due`), and whether a session is live. Not `open_until`, which every
/// confirmation moves and the screen doesn't show (an Open past it is
/// Unknown here already).
fn shown(s: &Snapshot, now: DateTime<Utc>) -> (VaultView, bool) {
    (VaultView { open_until: None, ..s.vault_at(now) }, s.active_at(now))
}

/// The handles the background refresh needs (clones of `AppState`'s).
#[derive(Clone)]
pub struct Shared {
    pub link: Arc<Mutex<Option<Link>>>,
    pub snapshot: Arc<RwLock<Snapshot>>,
    pub is_registered: Arc<tokio::sync::RwLock<bool>>,
    pub notify: Notify,
    pub changed: Changed,
}

impl Shared {
    /// Store `s` as what the UI may know, with the next publish counter
    /// ([`Snapshot::seq`]); if that changes what the screen shows of the
    /// vault or whether a session is live, call [`Changed`] (#77).
    pub fn publish(&self, s: Snapshot) {
        let now = Utc::now();
        let (before, after) = {
            let mut g = self.snapshot.write().unwrap_or_else(|p| p.into_inner());
            let before = shown(&g, now);
            let seq = g.seq + 1;
            *g = Snapshot { seq, ..s };
            (before, shown(&g, now))
        };
        if before != after {
            if let Some(f) = self.changed.read().unwrap_or_else(|p| p.into_inner()).as_ref() {
                f();
            }
        }
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

/// Whether the computer slept (or hibernated) through a wait of the
/// refresh loop that was due to end at `due`: the wall clock at `woke` is
/// more than two refreshes past it (VAULT-LOCK-PLAN §3.1, lead review M1).
/// The wall clock, not `Instant`: whether a monotonic clock counts the
/// time asleep differs by OS (it does on Windows, not on Linux or macOS),
/// while the wall clock always moves on. A clock set forward that far reads
/// as a resume too, which is the safe side (Open becomes Unknown until a
/// status answers).
pub fn slept_through(due: DateTime<Utc>, woke: DateTime<Utc>) -> bool {
    due.checked_add_signed(TimeDelta::seconds(2 * REFRESH_EVERY.as_secs() as i64)).is_some_and(|late| woke > late)
}

/// `now` plus `wait`, if that is a time.
fn due_after(now: DateTime<Utc>, wait: std::time::Duration) -> Option<DateTime<Utc>> {
    TimeDelta::from_std(wait).ok().and_then(|w| now.checked_add_signed(w))
}

/// The background refresh's loop over `link`: after `first`, a
/// [`refresh_round`] every [`REFRESH_EVERY`] until there is nothing left to
/// keep up ([`Link::keep_refreshing`], which since #77 holds while the link
/// is open) or the link is gone. A wall-clock jump past a round reads as a
/// sleep or resume ([`slept_through`]): [`Link::resumed`] first. A refused
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
    // A loop restarted by a command (the old task aborted) still sees a
    // sleep that came before it: the old loop's marks are kept in the link.
    let marks = match link.lock().await.as_mut() {
        Some(l) => {
            wait = l.refresh_started(Utc::now(), first);
            l.loop_marks()
        }
        None => Arc::default(),
    };
    loop {
        tokio::time::sleep(wait).await;
        // Recorded before waiting for the lock: an operation holding it (a
        // request waiting for the phone) is not a sleep.
        marks.lock().unwrap_or_else(|p| p.into_inner()).woke = Some(Utc::now());
        let mut slot = link.lock().await;
        if let Some(l) = slot.as_mut() {
            l.refresh_woke(Utc::now());
        }
        if slot.as_ref().is_some_and(|l| l.refused()) {
            // Already found refused (by this task, or by an operation that
            // told the person): only the slow look for `device.unlinked`.
            wait = refused_every;
            match recheck_refused_round(&mut slot).await {
                Round::Gone => return None,
                Round::Unlinked { erased } => return Some(erased),
                Round::Continue(snap) | Round::Stop(snap, _) => show(snap),
            }
            *marks.lock().unwrap_or_else(|p| p.into_inner()) = LoopMarks { due: due_after(Utc::now(), wait), woke: None };
            continue;
        }
        let round = refresh_round(&mut slot).await;
        // The pace of the next round (the backoff while locked or unknown),
        // and when it is due, by the wall clock.
        wait = match slot.as_mut() {
            Some(l) => {
                let now = Utc::now();
                let w = if l.refused() { refused_every } else { l.next_wait(now) };
                *l.marks() = LoopMarks { due: due_after(now, w), woke: None };
                w
            }
            None => REFRESH_EVERY,
        };
        match round {
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
        let s = Snapshot { link_open: true, live_until: Some(now), vault: VaultView::open(now), ..Default::default() };
        assert!(s.active_at(now));
        assert!(!s.active_at(now + TimeDelta::seconds(1)));
        assert!(!Snapshot::default().active_at(now));
        assert!(!s.without_session().active_at(now));
        assert!(s.without_session().link_open);
    }

    /// Before any `vault.status` there is no baseline: nothing is live.
    #[test]
    fn no_session_is_live_without_the_vaults_word() {
        assert_eq!(live_until(&Access::new(), Utc::now()), None);
    }

    /// #83: the time to name is rounded up to the minute (never early),
    /// and there is none within a minute or once past (clock skew).
    #[test]
    fn too_soon_retry_at_rounds_up_and_drops_near_times() {
        use chrono::TimeZone;
        let t = |h, m, s| Utc.with_ymd_and_hms(2026, 11, 5, h, m, s).unwrap();
        let now = t(9, 0, 0);
        assert_eq!(too_soon_retry_at(t(9, 5, 30), now), Some(t(9, 6, 0)));
        assert_eq!(too_soon_retry_at(t(9, 6, 0), now), Some(t(9, 6, 0)));
        assert_eq!(too_soon_retry_at(t(9, 0, 50), now), None);
        assert_eq!(too_soon_retry_at(t(8, 58, 0), now), None);
        // The notices: the frontend names the time; "in a minute" when near.
        assert_eq!(request_notice(&RequestFailed::TooSoon(Utc::now() + TimeDelta::minutes(7)), None), REQUEST_TOO_SOON_NOTICE);
        assert_eq!(request_notice(&RequestFailed::TooSoon(Utc::now()), None), REQUEST_TOO_SOON_NOW_NOTICE);
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
        // Both confirmations age together, as they do when status reads
        // stop (the stale notice is for an Unknown vault only, #77).
        link.confirmed = Some(now - STALE_AFTER - TimeDelta::seconds(1));
        link.vault_checked = link.confirmed;
        let snap = link.snapshot(now);
        assert!(!snap.active_at(now), "not shown as live");
        assert!(snap.stale);
        assert!(link.keep_refreshing(now), "the refresh keeps trying to confirm it");
        link.refresh().await.unwrap();
        assert!(link.snapshot(Utc::now()).active_at(Utc::now()));
    }

    /// LOW 7: with no baseline (no successful vault.status yet) the refresh
    /// keeps going. (Once the vault says there is no session it used to
    /// stop; since lead review M2 of #77 it goes on while the link is open,
    /// so that the vault's Open decays: see
    /// `an_idle_open_vault_decays_to_unknown`.)
    #[tokio::test]
    async fn the_refresh_runs_until_there_is_a_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let (_vault, mut link) = FakeVault::paired(dir.path());
        assert!(link.keep_refreshing(Utc::now()), "no baseline yet");
        link.read_status().await.unwrap();
        assert!(link.keep_refreshing(Utc::now()), "no session, but the vault's state is kept in view");
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
        // #90: say which failure, if it ever fails again.
        if let Err(f) = link.request_access(|| asked = true, || false).await {
            panic!("not granted: {f:?}");
        }
        assert!(asked);
        let snap = link.snapshot(Utc::now());
        assert!(snap.active_at(Utc::now()));
        assert_eq!(snap.session_id.as_deref(), Some("s-2"));
    }

    /// #90, a regression guard for the fake vault (test infrastructure),
    /// not for the device: one way the test above could fail by timing. The
    /// fake once stamped each message with the wall clock as it was then. A
    /// clock that stepped back after an earlier message left that message
    /// stamped ahead of the grant and of the status confirming it: both
    /// looked older than what this desktop had already learned, were
    /// (rightly) ignored as stale, and the request ended `NotConfirmed`.
    /// Here an earlier message is stamped 10 s ahead (an `ended`, as a
    /// clock 10 s fast would have stamped it). The fake's stamps no longer
    /// go back (`State::now` stamps after the last message, #92): the grant
    /// comes after it and is confirmed. With `State::now` as it was, this
    /// fails with `NotConfirmed`. Not covered: the device's own clock (a
    /// step back holds its outbox, #105) and a store write failing on
    /// Windows; #90 lists both.
    #[tokio::test]
    async fn a_message_stamped_ahead_doesnt_lose_the_grant() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        link.read_status().await.unwrap();
        vault.event("device.session.ended", "{\"reason\":\"ended\"}", Utc::now() + TimeDelta::seconds(10));
        vault.grant_on_request(("s-2", Utc::now() + TimeDelta::hours(1)));
        if let Err(f) = link.request_access(|| {}, || false).await {
            panic!("not granted: {f:?}");
        }
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
        // Nothing left to settle; the refresh goes on for the vault's
        // state (lead review M2 of #77).
        assert!(link.keep_refreshing(Utc::now()));
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

    // -----------------------------------------------------------------------
    // The vault's lock and hold (VAULT-LOCK-PLAN §3.1, §4).
    // -----------------------------------------------------------------------

    use fake::{owner_check, AfterRequest, UNLOCK_1};

    const UNLOCK_2: &str = "fedcba9876543210fedcba9876543210";
    /// The type the desktop never sends, put together at run time so that
    /// no string literal here holds it or a piece of it (see
    /// `no_code_path_sends_vault_lock`).
    fn vault_lock() -> String {
        ["vault", "lock"].join(".")
    }

    /// Owner decision (2026-11-05): the desktop never sends `vault.lock`.
    fn never_sent_a_lock(vault: &FakeVault) {
        assert!(!vault.deposited().iter().any(|k| *k == vault_lock()), "{:?}", vault.deposited());
    }

    fn statuses(vault: &FakeVault) -> usize {
        vault.deposited().iter().filter(|k| *k == "vault.status").count()
    }

    fn locking_body(unlock_id: &str) -> String {
        format!(r#"{{"unlock_id":"{unlock_id}"}}"#)
    }

    /// A paired link whose vault names a live session s-1, read.
    async fn live(dir: &std::path::Path) -> (FakeVault, Link<FakeVault, SystemClock>) {
        let (vault, mut link) = FakeVault::paired(dir);
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        let snap = link.snapshot(Utc::now());
        assert!(snap.active_at(Utc::now()));
        assert_eq!(snap.vault, VaultView::open(link.vault_checked.unwrap() + STALE_AFTER));
        (vault, link)
    }

    /// A lock from the phone, its notice collected by the refresh (whose
    /// status the locked vault leaves unanswered): Locked, with its reason,
    /// nothing live, and the refresh keeps going.
    #[tokio::test]
    async fn a_lock_notice_naming_this_unlock_shows_locked() {
        for (reason, shown) in [(None, None), (Some("idle"), Some("idle")), (Some("owner_check"), Some("owner_check")), (Some("recovery"), Some("recovery"))] {
            let dir = tempfile::tempdir().unwrap();
            let (vault, mut link) = live(dir.path()).await;
            let since = vault.lock_vault(reason);
            assert!(link.refresh().await.is_err(), "a locked vault doesn't answer");
            let now = Utc::now();
            let snap = link.snapshot(now);
            assert!(!snap.active_at(now));
            assert_eq!(snap.vault.state, VaultShown::Locked);
            assert_eq!(snap.vault.reason, shown);
            assert_eq!(snap.vault.locked_since, Some(since));
            assert_eq!(snap.vault.as_of, None, "the relay answers: confirmed, not \"as of\"");
            assert!(link.keep_refreshing(now));
            never_sent_a_lock(&vault);
        }
    }

    /// A lock notice for another unlock changes nothing, and the status is
    /// read again at once.
    #[tokio::test]
    async fn a_lock_notice_for_another_unlock_reads_the_status_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        let before = statuses(&vault);
        vault.event_now("vault.locking", &locking_body(UNLOCK_2), Some(Utc::now() + TimeDelta::seconds(60)));
        link.read_status().await.unwrap();
        assert_eq!(statuses(&vault), before + 2, "read, then read again");
        let snap = link.snapshot(Utc::now());
        assert!(snap.active_at(Utc::now()));
        assert_eq!(snap.vault.state, VaultShown::Open);
        never_sent_a_lock(&vault);
    }

    /// Owner decision 1 (2026-11-05): with no unlock_id held (a vault
    /// before release L), a lock notice never shows "locked": the state is
    /// Unknown and the status is read at once. If the vault answers, it is
    /// open again; if it doesn't, it stays Unknown.
    #[tokio::test]
    async fn a_lock_notice_with_no_unlock_id_held_never_shows_locked() {
        for silent in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (vault, mut link) = FakeVault::paired(dir.path());
            vault.set_unlock_id(None);
            vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
            link.read_status().await.unwrap();
            assert!(link.snapshot(Utc::now()).active_at(Utc::now()));
            let before = statuses(&vault);
            vault.event_now("vault.locking", &locking_body(UNLOCK_1), Some(Utc::now() + TimeDelta::seconds(60)));
            link.refresh().await.unwrap();
            if silent {
                vault.lock_silently();
            }
            vault.event_now("vault.locking", &locking_body(UNLOCK_1), Some(Utc::now() + TimeDelta::seconds(60)));
            let _ = link.refresh().await;
            assert_eq!(statuses(&vault), before + 4, "each notice read the status again");
            let snap = link.snapshot(Utc::now());
            assert_ne!(snap.vault.state, VaultShown::Locked);
            if silent {
                assert_eq!(snap.vault.state, VaultShown::Unknown);
                assert!(!snap.active_at(Utc::now()));
                assert!(link.keep_refreshing(Utc::now()));
            } else {
                assert_eq!(snap.vault.state, VaultShown::Open);
                assert!(snap.active_at(Utc::now()));
            }
        }
    }

    /// A lock notice collected after its `exp` (R6) is dropped: nothing
    /// changes.
    #[tokio::test]
    async fn an_expired_lock_notice_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.event_now("vault.locking", &locking_body(UNLOCK_1), Some(Utc::now() - TimeDelta::seconds(1)));
        link.read_status().await.unwrap();
        let snap = link.snapshot(Utc::now());
        assert!(snap.active_at(Utc::now()));
        assert_eq!(snap.vault.state, VaultShown::Open);
    }

    /// A held vault (by its status): the hold with its counts, the deadline
    /// and idle_lock_at; nothing live; the refresh goes on, and the hold
    /// ends with an `ok` status. Without counts, none are made up.
    #[tokio::test]
    async fn a_held_vault_shows_the_hold_and_nothing_live() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.hold(true, r#""waiting":{"messages":3,"requests":1,"calls":0,"other":2},"idle_lock_at":"2026-11-06T09:00:00.000Z""#);
        link.refresh().await.unwrap();
        let now = Utc::now();
        let snap = link.snapshot(now);
        assert!(!snap.active_at(now), "suspended while held (§3.6.3)");
        assert_eq!(snap.vault.state, VaultShown::Held);
        assert_eq!(snap.vault.waiting, Some(Counts { messages: 3, requests: 1, calls: 0, other: 2 }));
        assert!(snap.vault.deadline.is_some());
        assert_eq!(snap.vault.idle_lock_at, vettid_vms::envelope::parse_ts("2026-11-06T09:00:00.000Z"));
        assert!(link.keep_refreshing(now));
        vault.hold(true, "");
        link.refresh().await.unwrap();
        assert_eq!(link.snapshot(Utc::now()).vault.waiting, None, "not known: never zeros");
        vault.hold(false, "");
        link.refresh().await.unwrap();
        let snap = link.snapshot(Utc::now());
        assert!(snap.active_at(Utc::now()));
        assert_eq!(snap.vault.state, VaultShown::Open);
        never_sent_a_lock(&vault);
    }

    /// `due` (past the deadline, the hold off): the session stays live.
    #[tokio::test]
    async fn a_due_vault_stays_live() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.set_owner_check(Some(owner_check("due", false, "")));
        link.refresh().await.unwrap();
        let snap = link.snapshot(Utc::now());
        assert!(snap.active_at(Utc::now()));
        assert_eq!(snap.vault, VaultView { due: true, ..VaultView::open(link.vault_checked.unwrap() + STALE_AFTER) });
    }

    /// `owner_check_required` to Start New Session: Held.
    #[tokio::test]
    async fn owner_check_required_sets_held() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        link.read_status().await.unwrap();
        // Requests refused, while the status (read earlier) said ok.
        vault.hold(true, "");
        vault.set_owner_check(Some(owner_check("ok", false, "")));
        let r = link.request_access(|| panic!("not taken"), || false).await;
        assert_eq!(r, Err(RequestFailed::Held));
        assert_eq!(request_notice(&r.unwrap_err(), None), VAULT_HELD_NOTICE);
        assert_eq!(link.snapshot(Utc::now()).vault.state, VaultShown::Held);
        assert!(link.keep_refreshing(Utc::now()));
    }

    /// Open becomes Unknown when a status goes unanswered (a lock whose
    /// notice was missed, R6): not live, never "locked", and the refresh
    /// goes on.
    #[tokio::test]
    async fn open_becomes_unknown_on_an_unanswered_status() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.lock_silently();
        assert_eq!(link.refresh().await, Err(AccessError::Session(SessionError::TimedOut)));
        let snap = link.snapshot(Utc::now());
        assert!(!snap.active_at(Utc::now()));
        assert_eq!(snap.vault.state, VaultShown::Unknown);
        assert!(link.keep_refreshing(Utc::now()));
        vault.unlock(UNLOCK_2);
        link.refresh().await.unwrap();
        assert!(link.snapshot(Utc::now()).active_at(Utc::now()));
    }

    /// Open becomes Unknown once STALE_AFTER passes without a confirmation,
    /// and Open again once a status confirms it.
    #[tokio::test]
    async fn open_becomes_unknown_past_stale_after() {
        let dir = tempfile::tempdir().unwrap();
        let (_vault, mut link) = live(dir.path()).await;
        let now = Utc::now();
        link.vault_checked = Some(now - STALE_AFTER - TimeDelta::seconds(1));
        link.confirmed = link.vault_checked;
        let snap = link.snapshot(now);
        assert_eq!(snap.vault.state, VaultShown::Unknown);
        assert!(!snap.active_at(now), "no session shown live");
        assert_eq!(snap.session_id, None);
        assert_eq!(link.vault_now(now), VaultState::Unknown);
        assert!(link.keep_refreshing(now));
        link.refresh().await.unwrap();
        let snap = link.snapshot(Utc::now());
        assert_eq!(snap.vault.state, VaultShown::Open);
        assert!(snap.active_at(Utc::now()));
    }

    /// Lead review L3: the session's cap (`confirmed`, which an answered end
    /// sets too) and the vault's (`vault_checked`) can't disagree: with the
    /// vault view no longer Open, no session is shown live, even though the
    /// session was confirmed lately. It is "stale" meanwhile.
    #[tokio::test]
    async fn no_session_is_shown_live_unless_the_vault_view_is_open() {
        let dir = tempfile::tempdir().unwrap();
        let (_vault, mut link) = live(dir.path()).await;
        let now = Utc::now();
        link.vault_checked = Some(now - STALE_AFTER - TimeDelta::seconds(1));
        link.confirmed = Some(now);
        let snap = link.snapshot(now);
        assert_eq!(snap.vault.state, VaultShown::Unknown);
        assert!(!snap.active_at(now));
        assert_eq!((snap.session_id.as_deref(), snap.ends_at, snap.live_until), (None, None, None));
        assert!(snap.stale, "shown as not confirmed");
    }

    /// Lead review M2: an idle desktop (Open, no session) keeps refreshing,
    /// so a lock whose notice it missed doesn't leave Open on the screen:
    /// past STALE_AFTER the view is Unknown, and so after the next refresh,
    /// which the locked vault leaves unanswered.
    #[tokio::test]
    async fn an_idle_open_vault_decays_to_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        link.read_status().await.unwrap();
        assert_eq!(link.snapshot(Utc::now()).vault.state, VaultShown::Open);
        assert!(link.keep_refreshing(Utc::now()), "Open, no session: still refreshing");
        vault.lock_silently();
        let now = Utc::now();
        link.vault_checked = Some(now - STALE_AFTER - TimeDelta::seconds(1));
        assert_eq!(link.snapshot(now).vault.state, VaultShown::Unknown);
        let mut slot = Some(link);
        match refresh_round(&mut slot).await {
            Round::Continue(snap) => assert_eq!(snap.vault.state, VaultShown::Unknown),
            other => panic!("got {other:?}"),
        }
        never_sent_a_lock(&vault);
    }

    /// Lead review L2: a held vault answers `vault.status`, so an
    /// unanswered one turns Held into Unknown.
    #[tokio::test]
    async fn held_becomes_unknown_on_an_unanswered_status() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.hold(true, "");
        link.refresh().await.unwrap();
        assert_eq!(link.snapshot(Utc::now()).vault.state, VaultShown::Held);
        vault.lock_silently();
        assert!(link.refresh().await.is_err());
        let snap = link.snapshot(Utc::now());
        assert_eq!(snap.vault.state, VaultShown::Unknown);
        assert!(!snap.active_at(Utc::now()));
    }

    /// Lead review M3: a newer lock notice for another unlock makes Open
    /// Unknown (never Locked) until the status read at once says; if that
    /// read goes unanswered too, it stays Unknown.
    #[tokio::test]
    async fn a_newer_lock_notice_for_another_unlock_leaves_nothing_live() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.event_now("vault.locking", &locking_body(UNLOCK_2), Some(Utc::now() + TimeDelta::seconds(60)));
        let msgs = link.session.poll(&mut link.store).await.unwrap();
        assert_eq!(msgs.len(), 1);
        for m in &msgs {
            assert_eq!(link.access.observe(&mut link.session, &mut link.store, m), Ok(Some(AccessEvent::ReadStatus)));
        }
        let snap = link.snapshot(Utc::now());
        assert!(!snap.active_at(Utc::now()), "not live while the status is read");
        assert_eq!(snap.vault.state, VaultShown::Unknown);
        assert!(link.access.take_status_wanted(), "the status is still asked for");
        // The re-read, unanswered: still Unknown, never Locked.
        vault.event_now("vault.locking", &locking_body(UNLOCK_2), Some(Utc::now() + TimeDelta::seconds(60)));
        vault.lock_silently();
        let _ = link.refresh().await;
        assert_eq!(link.snapshot(Utc::now()).vault.state, VaultShown::Unknown);
    }

    /// Lead review M4: deposits refused for now (a 503) while collects
    /// work: the status request never reached the relay, so a Locked
    /// shown "as of" stays "as of", and its confirmation time doesn't move.
    #[tokio::test]
    async fn locked_stays_as_of_while_the_status_isnt_deposited() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.lock_vault(None);
        let _ = link.refresh().await;
        assert_eq!(link.snapshot(Utc::now()).vault.state, VaultShown::Locked);
        // Reached and unanswered: confirmed.
        let _ = link.refresh().await;
        assert!(link.session.last_request_reached());
        let snap = link.snapshot(Utc::now());
        assert_eq!((snap.vault.state, snap.vault.as_of), (VaultShown::Locked, None));
        link.resumed();
        let checked = link.vault_checked.expect("confirmed");
        vault.fail_deposits(true);
        for _ in 0..2 {
            let _ = link.refresh().await;
            assert!(!link.session.relay_failed(), "collects get through");
            assert!(!link.session.last_request_reached(), "the status wasn't deposited");
            let snap = link.snapshot(Utc::now());
            assert_eq!(snap.vault.state, VaultShown::Locked);
            assert_eq!(snap.vault.as_of, Some(checked), "still as of the last confirmation");
        }
        never_sent_a_lock(&vault);
    }

    /// Lead review: while locked, status reads that reach the relay
    /// unanswered back off, from REFRESH_EVERY doubling to
    /// LOCKED_REFRESH_MAX; a vault notice brings the next read forward and
    /// starts the backoff again; an answer resets it.
    #[tokio::test]
    async fn the_refresh_backs_off_while_locked_and_resets_on_an_answer() {
        let secs = std::time::Duration::from_secs;
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        assert_eq!(link.next_wait(Utc::now()), REFRESH_EVERY, "open: the usual pace");
        vault.lock_vault(None);
        let _ = link.refresh().await;
        assert!(matches!(link.vault_now(Utc::now()), VaultState::Locked { .. }));
        assert_eq!(link.next_wait(Utc::now()), secs(0), "the lock notice: the next read at once");
        let mut waits = Vec::new();
        for _ in 0..6 {
            let _ = link.refresh().await;
            assert!(link.session.last_request_reached(), "each read reached the relay");
            waits.push(link.next_wait(Utc::now()));
        }
        assert_eq!(waits, [secs(60), secs(120), secs(240), secs(300), secs(300), secs(300)]);
        assert_eq!(LOCKED_REFRESH_MAX, secs(300));
        // A notice (here one this desktop can't place) brings the read
        // forward, and the backoff starts again.
        vault.event_now("vault.locking", &locking_body(UNLOCK_2), Some(Utc::now() + TimeDelta::seconds(60)));
        let _ = link.refresh().await;
        assert_eq!(link.next_wait(Utc::now()), secs(0));
        let _ = link.refresh().await;
        assert!(link.next_wait(Utc::now()) < LOCKED_REFRESH_MAX, "started again");
        // Unlocked: answered, back to the usual pace.
        vault.unlock(UNLOCK_2);
        link.refresh().await.unwrap();
        assert_eq!(link.next_wait(Utc::now()), REFRESH_EVERY);
        assert_eq!(link.backoff, None);
        // Held: the vault answers, so the pace stays.
        vault.hold(true, "");
        link.refresh().await.unwrap();
        assert_eq!(link.next_wait(Utc::now()), REFRESH_EVERY);
        never_sent_a_lock(&vault);
    }

    /// The backoff grows only on reads that reached the relay: out of
    /// reach, nothing waits there, and the pace stays REFRESH_EVERY.
    #[tokio::test]
    async fn the_backoff_doesnt_grow_while_the_relay_is_out_of_reach() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.lock_vault(None);
        let _ = link.refresh().await;
        assert_eq!(link.next_wait(Utc::now()), std::time::Duration::ZERO);
        vault.offline(true);
        for _ in 0..2 {
            let _ = link.refresh().await;
            assert!(!link.session.last_request_reached());
            assert_eq!(link.next_wait(Utc::now()), REFRESH_EVERY);
        }
    }

    /// Lead review (M1 gap): a loop restarted by a command after a sleep
    /// still sees the gap, from the round the old loop expected, kept in
    /// the link: it resumes at its start (Open becomes Unknown), and reads
    /// the status at once (the read the resume asks for survives the
    /// restart); a vault that answers is Open again, one that doesn't
    /// stays Unknown. Without a gap, nothing changes and nothing is read.
    #[tokio::test(start_paused = true)]
    async fn a_restarted_loop_sees_a_sleep_before_it() {
        for (gap, answers) in [(true, true), (true, false), (false, true)] {
            let dir = tempfile::tempdir().unwrap();
            let (vault, mut link) = live(dir.path()).await;
            if !answers {
                vault.lock_silently();
            }
            let before = statuses(&vault);
            if gap {
                // The old loop set its round 8 hours ago and never woke for
                // it (its timer didn't count the suspend).
                *link.marks() = LoopMarks { due: Some(Utc::now() - TimeDelta::hours(8)), woke: None };
            }
            let slot = Arc::new(Mutex::new(Some(link)));
            let s2 = slot.clone();
            let task = tokio::spawn(async move { refresh_loop(&s2, REFRESH_EVERY, REFUSED_RECHECK_EVERY, |_| {}, |_| {}).await });
            for _ in 0..5 {
                tokio::task::yield_now().await;
            }
            {
                let g = slot.lock().await;
                let l = g.as_ref().unwrap();
                let snap = l.snapshot(Utc::now());
                assert_eq!(l.resumes, u32::from(gap));
                assert_eq!(statuses(&vault) > before, gap, "a read at once only after the resume");
                if gap && !answers {
                    assert_eq!(snap.vault.state, VaultShown::Unknown, "resumed, and the vault didn't answer");
                    assert!(!snap.active_at(Utc::now()));
                } else {
                    assert_eq!(snap.vault.state, VaultShown::Open);
                    assert!(snap.active_at(Utc::now()));
                }
                assert!(l.marks().due.is_some_and(|d| d > Utc::now()), "the new loop's round is set");
            }
            task.abort();
            let _ = task.await;
        }
    }

    /// Lead review (false resume): a request that waits minutes for the
    /// phone holds the lock; the old loop woke on time meanwhile and waited
    /// for it. A grant answered after 4 minutes, then a refresh restart:
    /// the session stays live, and `resumed()` isn't called. Without the
    /// grant's answers (nothing moved the round), the old loop's on-time
    /// waking still shows no sleep. The clock is the marks': the old loop's
    /// round set 4 minutes before now.
    #[tokio::test(start_paused = true)]
    async fn time_spent_holding_the_lock_is_no_sleep() {
        for answered in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let (vault, mut link) = FakeVault::paired(dir.path());
            link.read_status().await.unwrap();
            let round = Utc::now() - TimeDelta::minutes(4) + TimeDelta::seconds(60);
            // The old loop's round, 3 minutes ago, and its on-time waking.
            *link.marks() = LoopMarks { due: Some(round), woke: Some(round) };
            if answered {
                vault.grant_on_request(("s-2", Utc::now() + TimeDelta::hours(1)));
                link.request_access(|| {}, || false).await.expect("granted");
                assert!(link.marks().due.is_some_and(|d| d > Utc::now()), "the belt: the vault's answers moved the round");
            } else {
                vault.set_session(Some(("s-2", Utc::now() + TimeDelta::hours(1))));
                link.read_status().await.unwrap();
                // As if nothing had moved the round: only the old loop's
                // on-time waking keeps this from reading as a sleep.
                *link.marks() = LoopMarks { due: Some(round), woke: Some(round) };
            }
            assert!(link.snapshot(Utc::now()).active_at(Utc::now()));
            let slot = Arc::new(Mutex::new(Some(link)));
            let s2 = slot.clone();
            let task = tokio::spawn(async move { refresh_loop(&s2, REFRESH_EVERY, REFUSED_RECHECK_EVERY, |_| {}, |_| {}).await });
            for _ in 0..5 {
                tokio::task::yield_now().await;
            }
            {
                let g = slot.lock().await;
                let l = g.as_ref().unwrap();
                assert_eq!(l.resumes, 0, "no resume (answered: {answered})");
                let snap = l.snapshot(Utc::now());
                assert!(snap.active_at(Utc::now()), "the session stays live");
                assert_eq!(snap.session_id.as_deref(), Some("s-2"));
                assert_eq!(snap.vault.state, VaultShown::Open);
            }
            task.abort();
            let _ = task.await;
        }
        // The marks themselves: an on-time waking is no sleep however late
        // `now` is; a waking well past the round is one; no waking and
        // `now` well past the round is one.
        let due = Utc::now() - TimeDelta::minutes(10);
        assert!(!LoopMarks { due: Some(due), woke: Some(due) }.slept(Utc::now()));
        assert!(LoopMarks { due: Some(due), woke: Some(due + TimeDelta::minutes(5)) }.slept(Utc::now()));
        assert!(LoopMarks { due: Some(due), woke: None }.slept(Utc::now()));
        assert!(!LoopMarks::default().slept(Utc::now()));
    }

    fn requests(vault: &FakeVault) -> usize {
        vault.deposited().iter().filter(|k| *k == "device.session.request").count()
    }

    /// Lead review: a stored snapshot read after STALE_AFTER (after a
    /// suspend, or while a command holds the link) shows Unknown and
    /// nothing live, as `active_at` does for the session.
    #[tokio::test]
    async fn a_stored_snapshot_read_late_shows_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let (_vault, link) = live(dir.path()).await;
        let now = Utc::now();
        let snap = link.snapshot(now);
        assert_eq!(snap.vault.open_until, link.vault_checked.map(|c| c + STALE_AFTER));
        assert_eq!(snap.vault_at(now).state, VaultShown::Open);
        assert!(snap.active_at(now));
        let late = link.vault_checked.unwrap() + STALE_AFTER + TimeDelta::seconds(1);
        assert_eq!(snap.vault_at(late).state, VaultShown::Unknown);
        assert!(!snap.active_at(late), "nothing live");
        assert_eq!(snap.shown_expiry(late), None);
        assert!(snap.stale_at(late), "shown as not confirmed");
        // An Open view without an `open_until` is never Open.
        let bare = VaultView { state: VaultShown::Open, ..Default::default() };
        assert_eq!(bare.at(now).state, VaultShown::Unknown);
    }

    /// Lead review: `stale` ("hasn't heard from your vault") only while the
    /// vault view is Unknown. Held and Locked are the vault's word.
    #[tokio::test]
    async fn only_an_unknown_vault_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.hold(true, "");
        link.refresh().await.unwrap();
        let snap = link.snapshot(Utc::now());
        assert_eq!((snap.vault.state, snap.stale), (VaultShown::Held, false));
        vault.hold(false, "");
        link.refresh().await.unwrap();
        vault.lock_vault(None);
        let _ = link.refresh().await;
        let snap = link.snapshot(Utc::now());
        assert_eq!((snap.vault.state, snap.stale), (VaultShown::Locked, false));

        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.lock_silently();
        let _ = link.refresh().await;
        let snap = link.snapshot(Utc::now());
        assert_eq!((snap.vault.state, snap.stale), (VaultShown::Unknown, true), "a session held, no word from the vault");
    }

    /// Lead review (defense in depth): no session request while the vault
    /// is held or locked: refused with its notice, and nothing sent.
    #[tokio::test]
    async fn no_request_goes_while_held_or_locked() {
        for locked in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (vault, mut link) = live(dir.path()).await;
            if locked {
                vault.lock_vault(None);
                let _ = link.refresh().await;
            } else {
                vault.hold(true, "");
                link.refresh().await.unwrap();
            }
            let r = link.request_access(|| panic!("not sent"), || false).await;
            let (want, notice) = if locked { (RequestFailed::Locked, VAULT_LOCKED_NOTICE) } else { (RequestFailed::Held, VAULT_HELD_NOTICE) };
            assert_eq!(r, Err(want));
            assert_eq!(request_notice(&r.unwrap_err(), None), notice);
            assert_eq!(requests(&vault), 0, "nothing sent");
            never_sent_a_lock(&vault);
        }
    }

    /// Unknown: the status is read first; if it doesn't say Open, the
    /// request is refused with the Unknown text and not sent. If it says
    /// Open, the request goes.
    #[tokio::test]
    async fn a_request_while_unknown_reads_the_status_first() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.lock_silently();
        let _ = link.refresh().await;
        assert_eq!(link.snapshot(Utc::now()).vault.state, VaultShown::Unknown);
        let before = statuses(&vault);
        let r = link.request_access(|| panic!("not sent"), || false).await;
        assert_eq!(r, Err(RequestFailed::Unknown));
        assert_eq!(request_notice(&r.unwrap_err(), None), VAULT_UNKNOWN_NOTICE);
        assert_eq!(statuses(&vault), before + 1, "a status read was made");
        assert_eq!(requests(&vault), 0, "nothing sent");

        // No status read yet (Unknown at start), and the vault answers:
        // the request goes, and is granted.
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        assert_eq!(link.snapshot(Utc::now()).vault.state, VaultShown::Unknown);
        vault.grant_on_request(("s-2", Utc::now() + TimeDelta::hours(1)));
        link.request_access(|| {}, || false).await.expect("granted");
        assert_eq!(requests(&vault), 1);
        assert!(link.snapshot(Utc::now()).active_at(Utc::now()));
    }

    /// #77: a published snapshot that changes the vault's state or whether
    /// a session is live calls `changed`; one that changes neither doesn't.
    #[test]
    fn publish_tells_the_ui_of_a_change_at_once() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = calls.clone();
        let changed: Changed = Arc::new(RwLock::new(Some(Arc::new(move || {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }))));
        let shared = Shared {
            link: Arc::new(Mutex::new(None)),
            snapshot: Arc::default(),
            is_registered: Arc::default(),
            notify: Arc::default(),
            changed,
        };
        let count = || calls.load(std::sync::atomic::Ordering::SeqCst);
        let now = Utc::now();
        let open = VaultView::open(now + TimeDelta::minutes(2));
        let live = Snapshot { link_open: true, live_until: Some(now + TimeDelta::minutes(2)), vault: open.clone(), ..Default::default() };
        shared.publish(live.clone());
        assert_eq!(count(), 1, "unknown to open and live");
        shared.publish(Snapshot { reachable: true, ..live.clone() });
        assert_eq!(count(), 1, "nothing shown changed");
        shared.publish(Snapshot { vault: VaultView { state: VaultShown::Held, ..Default::default() }, live_until: None, ..live.clone() });
        assert_eq!(count(), 2, "held");
        shared.publish(Snapshot { vault: VaultView { state: VaultShown::Locked, ..Default::default() }, live_until: None, ..live.clone() });
        assert_eq!(count(), 3, "locked");
        shared.publish(Snapshot { live_until: None, ..live.clone() });
        assert_eq!(count(), 4, "open, not live");
        // Everything else the screen shows of the vault (lead review).
        let locked = VaultView { state: VaultShown::Locked, locked_since: Some(now), ..Default::default() };
        let mut n = 4;
        for v in [
            locked.clone(),
            VaultView { as_of: Some(now), ..locked.clone() },
            locked.clone(),
            VaultView { reason: Some("idle"), ..locked.clone() },
            VaultView { state: VaultShown::Held, ..Default::default() },
            VaultView { state: VaultShown::Held, waiting: Some(Counts { messages: 1, ..Default::default() }), ..Default::default() },
            VaultView { state: VaultShown::Held, waiting: Some(Counts { messages: 2, ..Default::default() }), ..Default::default() },
            VaultView { state: VaultShown::Held, waiting: Some(Counts { messages: 2, ..Default::default() }), idle_lock_at: Some(now), ..Default::default() },
            VaultView { due: true, ..open.clone() },
        ] {
            shared.publish(Snapshot { vault: v.clone(), live_until: None, ..live.clone() });
            n += 1;
            assert_eq!(count(), n, "{v:?}");
        }
        // A new confirmation only moves open_until: nothing shown changes.
        shared.publish(Snapshot { vault: VaultView { due: true, ..VaultView::open(now + TimeDelta::minutes(3)) }, live_until: None, ..live.clone() });
        assert_eq!(count(), n, "open_until alone");
        // Each publish takes the next counter.
        let before = shared.read().seq;
        shared.publish(live);
        assert_eq!(shared.read().seq, before + 1);
    }

    /// Lead review: focus reads are throttled on the last status sent, not
    /// the last confirmation. While Unknown (a status unanswered), two
    /// focuses 20 s apart read once: not again before the loop's backoff.
    /// While Open, a focus more than FOCUS_RECHECK_AFTER after the last
    /// read still reads.
    #[tokio::test]
    async fn focus_reads_are_throttled_on_the_last_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.lock_silently();
        let _ = link.refresh().await;
        assert_eq!(link.snapshot(Utc::now()).vault.state, VaultShown::Unknown);
        let backoff = link.next_wait(Utc::now());
        assert_eq!(backoff, REFRESH_EVERY);
        // The last attempt a backoff ago: the first focus reads.
        link.last_attempt = Some(Utc::now() - TimeDelta::seconds(61));
        let before = statuses(&vault);
        assert!(link.focus_read().await, "due: read");
        assert_eq!(statuses(&vault), before + 1);
        // A second focus 20 s later: not before the backoff, though that
        // read wasn't answered either.
        assert!(!link.focused(Utc::now() + TimeDelta::seconds(20)));
        assert!(!link.focus_read().await);
        assert_eq!(statuses(&vault), before + 1, "one read for the two focuses");
        // The backoff later (grown by that unanswered read), it reads
        // again; and a resume always does.
        let wait = TimeDelta::from_std(link.backoff.expect("backing off")).unwrap();
        assert!(!link.focused(Utc::now() + wait - TimeDelta::seconds(5)));
        assert!(link.focused(Utc::now() + wait + TimeDelta::seconds(1)));
        link.resumed();
        assert!(link.focused(Utc::now()), "a read asked for at once");

        // Open: a focus 16 s after the last read reads.
        let dir = tempfile::tempdir().unwrap();
        let (_vault, mut link) = live(dir.path()).await;
        assert!(!link.focused(Utc::now()), "just read");
        assert!(link.focused(Utc::now() + TimeDelta::seconds(16)));
    }

    /// Lead review M2: a focus read settles a stored end (#80) and leaves
    /// the refresh loop's marks as they are; a fresh focus reads nothing.
    #[tokio::test]
    async fn a_focus_read_settles_a_stored_end_and_keeps_the_loop() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired_with(dir.path(), true);
        let marks = LoopMarks { due: Some(Utc::now() + TimeDelta::seconds(40)), woke: None };
        *link.marks() = marks;
        assert!(link.focus_read().await, "nothing confirmed yet: read");
        assert!(link.session.access_end().is_none(), "the stored end is settled");
        assert_eq!(link.snapshot(Utc::now()).end_settled, Some(EndSettled::Confirmed));
        assert!(vault.deposited().iter().any(|k| k == "device.session.end"));
        let after = *link.marks();
        assert_eq!(after.woke, None);
        assert!(after.due >= marks.due, "the loop's round isn't moved earlier, nor reset: {after:?}");
        let before = statuses(&vault);
        assert!(!link.focus_read().await, "just confirmed: nothing read");
        assert_eq!(statuses(&vault), before);
    }

    /// A read asked for at once (here by a resume) survives a refresh
    /// restart: the restarted loop reads at once, not after `first`.
    #[tokio::test(start_paused = true)]
    async fn a_read_asked_for_survives_a_restart() {
        for asked in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let (vault, mut link) = live(dir.path()).await;
            if asked {
                link.resumed();
            }
            let before = statuses(&vault);
            let slot = Arc::new(Mutex::new(Some(link)));
            let s2 = slot.clone();
            let task = tokio::spawn(async move { refresh_loop(&s2, REFRESH_EVERY, REFUSED_RECHECK_EVERY, |_| {}, |_| {}).await });
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
            // No time has passed: only a read asked for at once has run.
            let _ = slot.lock().await;
            assert_eq!(statuses(&vault) > before, asked, "asked: {asked}");
            if asked {
                assert!(slot.lock().await.as_ref().unwrap().snapshot(Utc::now()).active_at(Utc::now()), "read again: live");
            }
            task.abort();
            let _ = task.await;
        }
    }

    /// A focus reads the status only when the vault's word is older than
    /// FOCUS_RECHECK_AFTER, or a read is asked for, and it takes a sleep
    /// the marks show as a resume.
    #[tokio::test]
    async fn a_focus_reads_the_status_only_when_due() {
        let dir = tempfile::tempdir().unwrap();
        let (_vault, mut link) = live(dir.path()).await;
        let now = Utc::now();
        assert!(!link.focused(now), "just confirmed");
        assert!(link.focused(now + FOCUS_RECHECK_AFTER + TimeDelta::seconds(1)), "older: read");
        link.read_now = true;
        assert!(link.focused(now), "asked for");
        assert!(!link.focused(now), "taken");
        *link.marks() = LoopMarks { due: Some(now - TimeDelta::hours(3)), woke: None };
        assert!(link.focused(now), "a sleep: resumed, and read");
        assert_eq!(link.resumes, 1);
        assert_eq!(link.snapshot(now).vault.state, VaultShown::Unknown);
    }

    /// Lead review M1: the refresh loop takes a wall-clock jump of more
    /// than two refreshes past the expected round as a sleep or resume.
    #[test]
    fn a_wall_clock_jump_past_the_round_reads_as_a_resume() {
        let due = Utc::now();
        let two = TimeDelta::seconds(2 * REFRESH_EVERY.as_secs() as i64);
        assert!(!slept_through(due, due));
        assert!(!slept_through(due, due + TimeDelta::seconds(5)), "a late round");
        assert!(!slept_through(due, due + two), "exactly two refreshes late");
        assert!(slept_through(due, due + two + TimeDelta::seconds(1)));
        assert!(slept_through(due, due + TimeDelta::hours(8)), "a night asleep");
        assert!(!slept_through(due, due - TimeDelta::hours(1)), "a clock set back");
        assert!(!slept_through(DateTime::<Utc>::MAX_UTC, DateTime::<Utc>::MAX_UTC), "no overflow");
    }

    /// After sleep or resume, Open becomes Unknown (nothing live) until a
    /// status answers.
    #[tokio::test]
    async fn open_becomes_unknown_on_resume() {
        let dir = tempfile::tempdir().unwrap();
        let (_vault, mut link) = live(dir.path()).await;
        link.resumed();
        let snap = link.snapshot(Utc::now());
        assert!(!snap.active_at(Utc::now()));
        assert_eq!(snap.vault.state, VaultShown::Unknown);
        assert!(link.keep_refreshing(Utc::now()));
        link.refresh().await.unwrap();
        assert!(link.snapshot(Utc::now()).active_at(Utc::now()));
    }

    /// Owner decision 2 (2026-11-05): Locked with the relay out of reach is
    /// "locked as of" the last confirmation, and Locked again once the
    /// relay answers (the status still doesn't). After a resume too.
    #[tokio::test]
    async fn locked_without_the_relay_is_as_of_until_it_answers() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.lock_vault(Some("idle"));
        let _ = link.refresh().await;
        let snap = link.snapshot(Utc::now());
        assert_eq!((snap.vault.state, snap.vault.as_of), (VaultShown::Locked, None));
        let checked = link.vault_checked.expect("confirmed");

        vault.offline(true);
        let _ = link.refresh().await;
        let snap = link.snapshot(Utc::now());
        assert_eq!(snap.vault.state, VaultShown::Locked);
        assert_eq!(snap.vault.as_of, Some(checked), "as of the last confirmation");
        assert!(!snap.active_at(Utc::now()));
        assert!(link.keep_refreshing(Utc::now()));

        vault.offline(false);
        let _ = link.refresh().await;
        let snap = link.snapshot(Utc::now());
        assert_eq!((snap.vault.state, snap.vault.as_of), (VaultShown::Locked, None), "the relay answers again");

        link.resumed();
        let snap = link.snapshot(Utc::now());
        assert_eq!(snap.vault.state, VaultShown::Locked);
        assert!(snap.vault.as_of.is_some(), "after a resume: as of");
        let _ = link.refresh().await;
        assert_eq!(link.snapshot(Utc::now()).vault.as_of, None);
        never_sent_a_lock(&vault);
    }

    /// A pending session request ends when the vault enters its hold (the
    /// vault drops it, §3.6.3).
    #[tokio::test]
    async fn a_pending_request_ends_on_a_hold() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        link.read_status().await.unwrap();
        let deadline = vettid_vms::envelope::format_ts(Utc::now() - TimeDelta::minutes(1));
        vault.after_request(AfterRequest::Hold(format!(r#"{{"deadline":"{deadline}","waiting":{{"messages":1,"requests":0,"calls":0,"other":0}}}}"#)));
        let mut asked = false;
        let r = link.request_access(|| asked = true, || false).await;
        assert!(asked, "the vault took the request first");
        assert_eq!(r, Err(RequestFailed::Held));
        let snap = link.snapshot(Utc::now());
        assert_eq!(snap.vault.state, VaultShown::Held);
        assert_eq!(snap.vault.waiting, Some(Counts { messages: 1, requests: 0, calls: 0, other: 0 }));
        never_sent_a_lock(&vault);
    }

    /// A pending session request ends when the vault locks; a grant that
    /// comes after the unlock is shown live only once a status names it.
    #[tokio::test]
    async fn a_pending_request_ends_on_a_lock_and_a_later_grant_waits_for_a_status() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired(dir.path());
        link.read_status().await.unwrap();
        vault.after_request(AfterRequest::Lock);
        let r = link.request_access(|| {}, || false).await;
        assert_eq!(r, Err(RequestFailed::Locked));
        assert_eq!(request_notice(&r.unwrap_err(), None), VAULT_LOCKED_NOTICE);
        assert_eq!(link.snapshot(Utc::now()).vault.state, VaultShown::Locked);

        // Unlocked on the phone, and the request granted.
        vault.unlock(UNLOCK_2);
        let exp = Utc::now() + TimeDelta::hours(1);
        let grant = format!(r#"{{"session_id":"s-2","expires_at":"{}"}}"#, vettid_vms::envelope::format_ts(exp));
        vault.event_now("device.session.granted", &grant, None);
        vault.set_session(Some(("s-2", exp)));
        let msgs = link.session.poll(&mut link.store).await.unwrap();
        let mut granted = false;
        for m in &msgs {
            granted |= matches!(link.access.observe(&mut link.session, &mut link.store, m), Ok(Some(AccessEvent::Granted(_))));
        }
        assert!(granted);
        let snap = link.snapshot(Utc::now());
        assert!(!snap.active_at(Utc::now()), "the grant alone shows nothing live");
        assert_eq!(snap.vault.state, VaultShown::Locked);

        link.refresh().await.unwrap();
        let snap = link.snapshot(Utc::now());
        assert!(snap.active_at(Utc::now()));
        assert_eq!(snap.session_id.as_deref(), Some("s-2"));
        assert_eq!(link.access.unlock_id(), Some(UNLOCK_2));
        never_sent_a_lock(&vault);
    }

    /// A stored end stays stored and shown pending through a lock (#80),
    /// and is settled once the vault answers again.
    #[tokio::test]
    async fn a_stored_end_keeps_retrying_through_a_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = FakeVault::paired_with(dir.path(), true);
        vault.lock_silently();
        for _ in 0..2 {
            assert!(link.refresh().await.is_err());
            assert!(link.session.access_end().is_some(), "kept");
            assert!(link.snapshot(Utc::now()).end_pending);
            assert!(link.keep_refreshing(Utc::now()));
        }
        vault.unlock(UNLOCK_2);
        link.refresh().await.unwrap();
        assert!(link.session.access_end().is_none());
        let snap = link.snapshot(Utc::now());
        assert!(!snap.end_pending);
        assert_eq!(snap.end_settled, Some(EndSettled::Confirmed));
        assert!(vault.deposited().iter().any(|k| k == "device.session.end"));
        never_sent_a_lock(&vault);
    }

    /// Owner decision (2026-11-05): the desktop never sends `vault.lock`,
    /// through a lock, a resume, a hold, a request and an end.
    #[tokio::test]
    async fn the_desktop_sends_no_vault_lock_through_a_lock_and_a_hold() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut link) = live(dir.path()).await;
        vault.lock_vault(None);
        let _ = link.refresh().await;
        link.resumed();
        let _ = link.refresh().await;
        vault.unlock(UNLOCK_2);
        link.refresh().await.unwrap();
        vault.hold(true, "");
        link.refresh().await.unwrap();
        let _ = link.request_access(|| {}, || false).await;
        let _ = link.end().await;
        assert!(!vault.deposited().is_empty());
        never_sent_a_lock(&vault);
    }

    /// A tripwire for `vault.lock` (owner decision, 2026-11-05: the desktop
    /// never sends it), not a proof. The real guards are the engine's:
    /// `outbox_allowed` keeps the type out of the stored outbox (§8.6), so
    /// it can go only through `Session::send_once`, and the first check
    /// below is that nothing outside the engine calls `send_once`. Across
    /// every crate under src-tauri (the desktop, vettid-device,
    /// vettid-relay, vettid-vms), outside the engine's own guard
    /// (`crates/vettid-device/src/session.rs`) and test files, it fails on:
    /// - a call of `send_once(`;
    /// - a string literal that holds the type (not `vault.locking`), or an
    ///   obvious piece of it: one word ending in `vault.` or starting with
    ///   `.lock`, or a `vault.{` (a `format!`) (lead review L5). A type
    ///   put together from variables (`join`, `format!` of other strings)
    ///   gets past this scan.
    #[test]
    fn no_code_path_sends_vault_lock() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                if p.is_dir() {
                    if !["target", "node_modules", "gen"].contains(&name.as_str()) {
                        walk(&p, out);
                    }
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let kind = vault_lock();
        let building = |seg: &str| {
            let named = seg.match_indices(&kind).any(|(i, _)| !seg[i + kind.len()..].starts_with("ing"));
            // A piece of a type is one word: a sentence ending in "your
            // vault." is not one.
            let piece = !seg.contains(char::is_whitespace)
                && (seg.ends_with(&format!("{}.", "vault")) || seg.starts_with(&format!(".{}", "lock")));
            named || piece || seg.contains(&format!("{}.{{", "vault"))
        };
        // The check itself catches what it should, and not more.
        for (seg, hit) in [
            (kind.clone(), true),
            (format!("{kind} now"), true),
            (format!("{}.{{}}", "vault"), true),
            (format!("{}.", "vault"), true),
            (format!(".{}", "lock"), true),
            (format!("{kind}ing"), false),
            (format!("to your {}.", "vault"), false),
        ] {
            assert_eq!(building(&seg), hit, "{seg}");
        }
        let call = concat!("send", "_once(");
        let (mut found, mut in_guard, mut crates) = (Vec::new(), 0, std::collections::BTreeSet::new());
        let mut files = Vec::new();
        walk(&root.join("src"), &mut files);
        walk(&root.join("crates"), &mut files);
        for f in files {
            let rel = f.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if let Some(c) = rel.strip_prefix("crates/").and_then(|r| r.split('/').next()) {
                crates.insert(c.to_string());
            }
            let guard = rel == "crates/vettid-device/src/session.rs";
            let test = rel.contains("/tests/") || rel.ends_with("/tests.rs") || rel.starts_with("tests/");
            let text = std::fs::read_to_string(&f).unwrap();
            for (i, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                let hit = line.contains(call) || line.split('"').skip(1).step_by(2).any(building);
                if hit && guard {
                    in_guard += 1;
                } else if hit && !test {
                    found.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        }
        for c in ["vettid-device", "vettid-relay", "vettid-vms"] {
            assert!(crates.contains(c), "{c} scanned: {crates:?}");
        }
        assert!(in_guard > 0, "the engine's guard is where the type is named");
        assert!(found.is_empty(), "the lock type named, built or sendable outside the engine's guard: {found:#?}");
    }
}
