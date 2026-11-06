use serde::Serialize;
use tauri::State;

use crate::link::{Snapshot, VaultShown};
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct SessionStatus {
    pub state: String,
    pub session_id: Option<String>,
    pub expires_at: Option<i64>,
    pub seconds_remaining: Option<i64>,
    pub extended_count: Option<i32>,
    pub max_extensions: Option<i32>,
    /// Whether the last exchange with the vault (through the relay) got an
    /// answer. A proxy, not a heartbeat from the phone.
    pub phone_reachable: bool,
}

#[derive(Debug, Serialize)]
pub struct SessionTimer {
    pub seconds_remaining: i64,
    pub expires_at: i64,
    pub warn_30min: bool,
    pub warn_5min: bool,
}

/// The session's state, from the link's last snapshot: "active" only while
/// [`Snapshot::active_at`] says so; "suspended" while the vault is held or
/// locked (#77: the vault's word, not an expiry, and the current UI's
/// "Suspended" has no Start New Session); "expired" when unlocked without
/// a live session otherwise; "inactive" when no link is open or not paired.
fn status_of(snap: &Snapshot, now: chrono::DateTime<chrono::Utc>) -> SessionStatus {
    let none = |state: &str, reachable: bool| SessionStatus {
        state: state.to_string(),
        session_id: None,
        expires_at: None,
        seconds_remaining: None,
        extended_count: None,
        max_extensions: None,
        phone_reachable: reachable,
    };
    // The time shown is the session's own expiry (#82); live or not is
    // `active_at`, from live_until.
    match snap.shown_expiry(now) {
        Some(until) => SessionStatus {
            state: "active".to_string(),
            session_id: snap.session_id.clone(),
            expires_at: Some(until.timestamp()),
            seconds_remaining: Some((until - now).num_seconds().max(0)),
            // The vault doesn't count extensions (#82): not reported.
            extended_count: None,
            max_extensions: None,
            phone_reachable: snap.reachable,
        },
        None if snap.link_open => match snap.vault_at(now).state {
            VaultShown::Held | VaultShown::Locked => none("suspended", snap.reachable),
            VaultShown::Open | VaultShown::Unknown => none("expired", snap.reachable),
        },
        None => none("inactive", false),
    }
}

/// Get current session status.
#[tauri::command]
pub async fn get_session_status(state: State<'_, AppState>) -> Result<SessionStatus, String> {
    Ok(status_of(&state.snapshot(), chrono::Utc::now()))
}

/// Get session timer for countdown display.
#[tauri::command]
pub async fn get_session_timer(state: State<'_, AppState>) -> Result<SessionTimer, String> {
    let now = chrono::Utc::now();
    let status = status_of(&state.snapshot(), now);
    let remaining = status.seconds_remaining.unwrap_or(0);
    Ok(SessionTimer {
        seconds_remaining: remaining,
        expires_at: status.expires_at.unwrap_or_else(|| now.timestamp()),
        warn_30min: remaining <= 1800 && remaining > 0,
        warn_5min: remaining <= 300 && remaining > 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_only_while_the_snapshot_is_live() {
        let now = chrono::Utc::now();
        assert_eq!(status_of(&Snapshot::default(), now).state, "inactive");
        let mut snap = Snapshot { link_open: true, reachable: true, ..Default::default() };
        assert_eq!(status_of(&snap, now).state, "expired");
        snap.live_until = Some(now + chrono::TimeDelta::seconds(30));
        snap.vault = crate::link::VaultView::open(now + chrono::TimeDelta::seconds(30));
        snap.session_id = Some("s".into());
        let s = status_of(&snap, now);
        assert_eq!((s.state.as_str(), s.seconds_remaining), ("active", Some(30)));
        assert_eq!(status_of(&snap, now + chrono::TimeDelta::seconds(31)).state, "expired");
    }

    /// #82: the time shown is the session's own expiry (an hour here), not
    /// the 120 s freshness window that decides whether it is live.
    #[test]
    fn the_time_shown_is_the_sessions_expiry() {
        let now = chrono::Utc::now();
        let snap = Snapshot {
            link_open: true,
            session_id: Some("s".into()),
            expires_at: Some(now + chrono::TimeDelta::hours(1)),
            ends_at: Some(now + chrono::TimeDelta::minutes(59)),
            live_until: Some(now + chrono::TimeDelta::seconds(120)),
            vault: crate::link::VaultView::open(now + chrono::TimeDelta::seconds(120)),
            ..Default::default()
        };
        let s = status_of(&snap, now);
        // The desktop's own end, a margin before the vault's hour.
        assert_eq!((s.state.as_str(), s.seconds_remaining), ("active", Some(59 * 60)));
        // Past the freshness window: not live, so no time at all.
        let later = status_of(&snap, now + chrono::TimeDelta::seconds(121));
        assert_eq!((later.state.as_str(), later.seconds_remaining), ("expired", None));
    }

    /// #77: held or locked is "suspended" (the vault's word), never
    /// "expired" (which offers Start New Session); an Open past its
    /// confirmation is Unknown, so "expired" with nothing live.
    #[test]
    fn held_and_locked_are_suspended_not_expired() {
        use crate::link::VaultView;
        let now = chrono::Utc::now();
        for (state, want) in [(VaultShown::Held, "suspended"), (VaultShown::Locked, "suspended"), (VaultShown::Unknown, "expired")] {
            let snap = Snapshot { link_open: true, vault: VaultView { state, ..Default::default() }, ..Default::default() };
            assert_eq!(status_of(&snap, now).state, want, "{state:?}");
        }
        let snap = Snapshot {
            link_open: true,
            session_id: Some("s".into()),
            live_until: Some(now + chrono::TimeDelta::hours(1)),
            vault: VaultView::open(now + chrono::TimeDelta::seconds(120)),
            ..Default::default()
        };
        assert_eq!(status_of(&snap, now).state, "active");
        assert_eq!(status_of(&snap, now + chrono::TimeDelta::seconds(121)).state, "expired", "the stored Open ran out");
    }
}
