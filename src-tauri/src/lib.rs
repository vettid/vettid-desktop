pub mod crypto;
pub mod fingerprint;
pub mod credential;
pub mod nats;
pub mod registration;
pub mod session;
pub mod commands;
pub mod state;
pub mod tray;
#[cfg(feature = "webrtc")]
pub mod webrtc;

use commands::{auth, calls, vault, session as session_cmd};
use state::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize env_logger so `log::info!` / `log::warn!` calls across
    // the codebase actually surface. Defaults to `info` for our crate
    // and `warn` for noisy dependencies; users can override at launch
    // time with `RUST_LOG=...`. Without this every log call was a no-op
    // and pairing failures left no breadcrumb in stderr.
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(
            "info,vettid_desktop=debug,async_nats=info,reqwest=warn",
        ),
    )
    .format_timestamp_millis()
    .try_init();

    tauri::Builder::default()
        // Single-instance plugin: must be registered first per its
        // docs so it can short-circuit before any other setup runs.
        // On a second launch the callback fires in the running
        // process — we show + focus the existing window instead of
        // letting two binaries fight over the NATS subscription.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
                let _ = win.unminimize();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::new())
        .setup(|app| {
            tray::install(app.handle())?;
            // Compute the device fingerprint now, on a background
            // thread. Hashing the executable is slow on a debug build;
            // doing it at startup means it is ready before the user
            // can reach pairing, instead of blocking request-session.
            auth::warm_device_fingerprint();
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the main window only hides it — the listener and tray
            // keep running. The user quits via the tray menu (or Cmd+Q on macOS).
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            // Auth commands
            auth::register,
            auth::unlock,
            auth::lock,
            auth::logout,
            auth::extend_session,
            auth::end_session,
            auth::get_session_info,
            auth::get_status,
            // Vault commands — independent
            vault::list_connections,
            vault::get_connection,
            vault::list_feed,
            vault::query_audit,
            vault::list_connection_audit,
            vault::list_messages,
            vault::list_secrets_catalog,
            vault::list_proposals,
            vault::list_personal_data,
            vault::list_wallets,
            vault::get_wallet_balance,
            vault::list_devices,
            vault::get_profile,
            vault::get_profile_photo,
            vault::get_vault_snapshot,
            vault::get_secret,
            vault::request_secrets_unlock,
            vault::cancel_pending_operation,
            vault::get_wallet_transactions,
            vault::get_conversation,
            vault::list_call_history,
            // Vault commands — phone-required
            vault::request_secret,
            vault::add_secret,
            vault::update_secret,
            vault::delete_secret,
            vault::delete_personal_data_fields,
            vault::rotate_connection_keys,
            vault::authenticate_connection,
            vault::get_connection_verify_state,
            // Data-sharing — grants, share policies, presence overrides.
            vault::grant_request,
            vault::grant_request_group,
            vault::grant_approve,
            vault::grant_deny,
            vault::grant_revoke,
            vault::grant_list_pending,
            vault::grant_list_inbound,
            vault::grant_list_outbound,
            vault::grant_list_my_requests,
            vault::grant_fetch_remote,
            vault::share_policy_get,
            vault::share_policy_set,
            vault::presence_override_set,
            vault::get_turn_credentials,
            vault::mark_calls_seen,
            vault::cast_vote,
            vault::send_btc,
            vault::send_message,
            vault::create_wallet,
            vault::get_wallet_address,
            vault::get_fee_estimates,
            vault::delete_wallet,
            vault::set_wallet_visibility,
            vault::request_payment,
            vault::update_profile,
            vault::update_personal_data,
            vault::revoke_connection,
            vault::mark_message_read,
            // Session commands
            session_cmd::get_session_status,
            session_cmd::get_session_timer,
            // Call signaling
            calls::initiate_call,
            calls::answer_call,
            calls::decline_call,
            calls::end_call,
            calls::send_ice_candidate,
            calls::apply_remote_answer,
            calls::apply_remote_ice,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
