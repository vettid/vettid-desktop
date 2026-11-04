use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

use crate::link::{Link, Notify, Shared, Snapshot};
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

    /// Memory resets (lock, End session, log-out) this process has started
    /// and finished (#43). A reset bumps `resets_started` before it clears
    /// anything and `resets_finished` when it's done. `unlock` (and a
    /// pairing) installs its link only if none was under way when it
    /// started and none started since; a wait for the phone's answer stops
    /// when one starts.
    pub resets_started: Arc<std::sync::atomic::AtomicU64>,
    pub resets_finished: Arc<std::sync::atomic::AtomicU64>,

    /// Currently active WebRTC call session, if any. Only one call at a time
    /// — multi-call (call-waiting) would warrant a HashMap keyed by call_id,
    /// but the Android app is single-call and we follow that model.
    #[cfg(feature = "webrtc")]
    pub active_call: Arc<Mutex<Option<Arc<CallSession>>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            link: Arc::new(Mutex::new(None)),
            snapshot: Arc::new(std::sync::RwLock::new(Snapshot::default())),
            refresh_task: Arc::new(std::sync::Mutex::new(None)),
            notify: Arc::new(std::sync::RwLock::new(None)),
            delegation: Arc::new(Mutex::new(DelegationManager::new())),
            is_registered: Arc::new(RwLock::new(false)),
            pairing: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            opening: Arc::new(Mutex::new(())),
            session_op: Arc::new(Mutex::new(())),
            resets_started: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            resets_finished: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
        let first = if now { std::time::Duration::ZERO } else { crate::link::REFRESH_EVERY };
        let h = crate::link::spawn_refresh(self.shared(), first);
        if let Some(old) = self.refresh_task.lock().unwrap_or_else(|p| p.into_inner()).replace(h) {
            old.abort();
        }
    }
}
