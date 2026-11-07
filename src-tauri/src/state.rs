use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

use crate::link::{Changed, Link, Notify, Shared, Snapshot};
use crate::session::delegation::DelegationManager;

#[cfg(feature = "webrtc")]
use crate::webrtc::CallSession;

// ---------------------------------------------------------------------------
// Central application state — managed by Tauri
// ---------------------------------------------------------------------------

pub struct AppState {
    /// The paired device's link to its vault, once unlocked (see
    /// `crate::link`). Every operation on it holds this lock.
    pub link: Arc<Mutex<Option<Link>>>,

    /// What the UI reads without waiting for the link: taken after every
    /// operation on it, and cleared first by every reset.
    pub snapshot: Arc<std::sync::RwLock<Snapshot>>,

    /// The background refresh (`link::spawn_refresh`), if running. Stopped
    /// by every session-ending path: lock, log-out, End session; it stops
    /// itself when the session has expired and no end waits.
    pub refresh_task: Arc<std::sync::Mutex<Option<JoinHandle<()>>>>,

    /// Tells the frontend what the background refresh found (set up in
    /// `lib.rs` once there is a window).
    pub notify: Notify,

    /// Tells the frontend that what it shows of the vault, or whether a
    /// session is live, has changed (#77; set up in `lib.rs`).
    pub changed: Changed,

    /// Pending phone-approval tracker.
    pub delegation: Arc<Mutex<DelegationManager>>,

    /// Whether the user is registered (a pairing is saved).
    pub is_registered: Arc<RwLock<bool>>,

    /// Pairings under way (`register`): while one is, `unlock` leaves the
    /// device store alone (opening it would remove the pending pairing).
    pub pairing: Arc<std::sync::atomic::AtomicUsize>,

    /// One opening of the device store at a time: held by `unlock` from its
    /// first check to the link's install, and by `register` until its first
    /// save (the end of `pairing::start`). Taken before `link`, never
    /// while holding it or `session_op`.
    pub opening: Arc<Mutex<()>>,

    /// Held for the whole of End session and of Start New Session, so the
    /// two never overlap (#33).
    pub session_op: Arc<Mutex<()>>,

    /// Memory resets (End session, log-out) this process has started
    /// and finished (#43). A reset bumps `resets_started` before it clears
    /// anything and `resets_finished` when it's done. `unlock` (and a
    /// pairing) installs its link only if none was under way when it
    /// started and none started since; a wait for the phone's answer stops
    /// when one starts.
    pub resets_started: Arc<std::sync::atomic::AtomicU64>,
    pub resets_finished: Arc<std::sync::atomic::AtomicU64>,

    /// The notice `unlock` gave when the saved pairing couldn't be opened
    /// (#97), so Start New Session repeats it, which may be the more specific
    /// advice for a failure that passes ("sign out and back in"), rather
    /// than a generic one. Cleared once a link is installed.
    pub unlock_notice: Arc<std::sync::Mutex<Option<String>>>,

    /// Wrong passphrases at unlock, and the wait before the next try (#13
    /// item 4; [`PassphraseTries`]).
    pub passphrase_tries: Arc<std::sync::Mutex<PassphraseTries>>,

    /// Currently active WebRTC call session, if any. Only one call at a time
    /// — multi-call (call-waiting) would warrant a HashMap keyed by call_id,
    /// but the Android app is single-call and we follow that model.
    #[cfg(feature = "webrtc")]
    pub active_call: Arc<Mutex<Option<Arc<CallSession>>>>,
}

/// The longest wait between passphrase tries at unlock.
pub const PASSPHRASE_WAIT_CAP: std::time::Duration = std::time::Duration::from_secs(30);

/// After this many wrong passphrases in a row, unlock adds that the saved
/// pairing may be damaged (a damaged file answers the same as a wrong
/// passphrase).
pub const MAYBE_DAMAGED_AFTER: u32 = 5;

/// Wrong passphrases in a row at unlock, and when the next try may run (#13
/// item 4): after each wrong one the wait doubles, 1, 2, 4, 8, 16 s, then 30 s
/// each time; reset when a pairing opens. It lives in memory, so quitting
/// resets it. That is a stated residual (lead review): it only slows guessing
/// at the keyboard; Argon2id is what slows guessing at a copy of the file.
#[derive(Debug, Default)]
pub struct PassphraseTries {
    wrong: u32,
    next_at: Option<std::time::Instant>,
}

impl PassphraseTries {
    /// How long until the next try may run, if it may not yet.
    pub fn wait_left(&self, now: std::time::Instant) -> Option<std::time::Duration> {
        self.next_at.and_then(|t| t.checked_duration_since(now)).filter(|d| !d.is_zero())
    }

    /// A wrong passphrase at `now`: the wait before the next try.
    pub fn wrong(&mut self, now: std::time::Instant) -> std::time::Duration {
        self.wrong = self.wrong.saturating_add(1);
        let wait = std::time::Duration::from_secs(1 << (self.wrong - 1).min(5)).min(PASSPHRASE_WAIT_CAP);
        self.next_at = Some(now + wait);
        wait
    }

    /// Wrong passphrases in a row.
    pub fn wrong_in_a_row(&self) -> u32 {
        self.wrong
    }

    /// A pairing opened (or a new one was made): no wait.
    pub fn reset(&mut self) {
        *self = PassphraseTries::default();
    }
}

/// How long the restarted refresh waits before its first round: nothing to
/// wait for if `now`; for a refused device the rounds are the slow
/// mailbox rechecks, so the first waits as long as they do; else a minute.
fn first_wait(now: bool, refused: bool) -> std::time::Duration {
    if refused {
        crate::link::REFUSED_RECHECK_EVERY
    } else if now {
        std::time::Duration::ZERO
    } else {
        crate::link::REFRESH_EVERY
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            link: Arc::new(Mutex::new(None)),
            snapshot: Arc::new(std::sync::RwLock::new(Snapshot::default())),
            refresh_task: Arc::new(std::sync::Mutex::new(None)),
            notify: Arc::new(std::sync::RwLock::new(None)),
            changed: Arc::new(std::sync::RwLock::new(None)),
            delegation: Arc::new(Mutex::new(DelegationManager::new())),
            is_registered: Arc::new(RwLock::new(false)),
            pairing: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            opening: Arc::new(Mutex::new(())),
            session_op: Arc::new(Mutex::new(())),
            resets_started: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            resets_finished: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            unlock_notice: Arc::new(std::sync::Mutex::new(None)),
            passphrase_tries: Arc::new(std::sync::Mutex::new(PassphraseTries::default())),
            #[cfg(feature = "webrtc")]
            active_call: Arc::new(Mutex::new(None)),
        }
    }

    /// The handles the background refresh shares.
    pub fn shared(&self) -> Shared {
        Shared {
            link: self.link.clone(),
            snapshot: self.snapshot.clone(),
            is_registered: self.is_registered.clone(),
            notify: self.notify.clone(),
            changed: self.changed.clone(),
        }
    }

    /// What the UI may know now.
    pub fn snapshot(&self) -> Snapshot {
        self.shared().read()
    }

    pub fn publish(&self, s: Snapshot) {
        self.shared().publish(s)
    }

    /// Stop the background refresh, if it runs.
    pub fn stop_refresh(&self) {
        if let Some(h) = self.refresh_task.lock().unwrap_or_else(|p| p.into_inner()).take() {
            h.abort();
        }
    }

    /// (Re)start the background refresh: at once if `now`, else after
    /// [`crate::link::REFRESH_EVERY`]. Call it with `link` locked, so the
    /// task it replaces isn't in the middle of an operation.
    pub fn start_refresh(&self, now: bool) {
        // The snapshot is published before this is called.
        let first = first_wait(now, self.snapshot().refused);
        let h = crate::link::spawn_refresh(self.shared(), first);
        if let Some(old) = self.refresh_task.lock().unwrap_or_else(|p| p.into_inner()).replace(h) {
            old.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_refused_device_restarts_with_the_slow_wait() {
        assert_eq!(first_wait(false, true), crate::link::REFUSED_RECHECK_EVERY);
        assert_eq!(first_wait(true, true), crate::link::REFUSED_RECHECK_EVERY, "an end can't be sent to it");
        assert_eq!(first_wait(true, false), Duration::ZERO);
        assert_eq!(first_wait(false, false), crate::link::REFRESH_EVERY);
    }

    #[test]
    fn the_passphrase_wait_doubles_to_30_s() {
        let t0 = std::time::Instant::now();
        let mut t = PassphraseTries::default();
        assert_eq!(t.wait_left(t0), None, "the first try doesn't wait");
        let waits: Vec<u64> = (0..8).map(|_| t.wrong(t0).as_secs()).collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(t.wrong_in_a_row(), 8);
        assert_eq!(t.wait_left(t0), Some(Duration::from_secs(30)));
        assert_eq!(t.wait_left(t0 + Duration::from_secs(29)), Some(Duration::from_secs(1)));
        assert_eq!(t.wait_left(t0 + Duration::from_secs(30)), None);
        for _ in 0..100 {
            t.wrong(t0);
        }
        assert_eq!(t.wrong(t0), PASSPHRASE_WAIT_CAP, "no overflow");
        t.reset();
        assert_eq!((t.wrong_in_a_row(), t.wait_left(t0)), (0, None));
    }
}
