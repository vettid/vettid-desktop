pub mod crypto;
pub mod fingerprint;
pub mod credential;
pub mod nats;
pub mod registration;
pub mod session;
pub mod commands;
pub mod state;
pub mod tray;

use commands::{auth, calls, vault, session as session_cmd};
use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::new())
        .setup(|app| {
            tray::install(app.handle())?;
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
            auth::get_status,
            // Vault commands — independent
            vault::list_connections,
            vault::get_connection,
            vault::list_feed,
            vault::query_audit,
            vault::list_messages,
            vault::list_secrets_catalog,
            vault::list_proposals,
            vault::list_personal_data,
            vault::list_wallets,
            vault::get_wallet_balance,
            vault::get_transaction_history,
            vault::list_devices,
            vault::get_profile,
            vault::get_conversation,
            vault::list_call_history,
            // Vault commands — phone-required
            vault::request_secret,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
