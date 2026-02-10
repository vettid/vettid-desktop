pub mod crypto;
pub mod fingerprint;
pub mod credential;
pub mod nats;
pub mod registration;
pub mod session;
pub mod commands;

use commands::{auth, vault, session as session_cmd};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            // Auth commands
            auth::register,
            auth::unlock,
            auth::lock,
            auth::get_status,
            // Vault commands
            vault::list_connections,
            vault::get_connection,
            vault::list_feed,
            vault::query_audit,
            vault::list_messages,
            vault::list_secrets_catalog,
            vault::request_secret,
            // Session commands
            session_cmd::get_session_status,
            session_cmd::get_session_timer,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
