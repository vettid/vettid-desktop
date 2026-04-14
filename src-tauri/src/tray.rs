//! System tray (Linux) / menu bar (macOS) integration.
//!
//! Uses Tauri v2's TrayIconBuilder. The tray persists for the lifetime of the
//! app and exposes Show / Hide / Quit. Closing the main window hides it
//! instead of quitting (handled in `lib.rs`), so background NATS push events
//! continue to flow into the OS notification center.
//!
//! ## macOS specifics
//! - The icon is set via `with_icon(default_window_icon)` and macOS will
//!   render it in the menu bar at the system text size. For a polished v1 we
//!   should ship a dedicated black/alpha *template* icon so macOS can re-tint
//!   for light/dark menu bars; the app icon used here is fine for a dev build.
//! - `Cmd+Q` quits the app; the tray's Quit menu item does the same.
//! - We do NOT set `LSUIElement = true`, so the Dock icon is visible. Toggling
//!   that into a runtime "menu-bar-only" Settings option is a follow-up.

use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, Runtime,
};

pub fn install<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show VettID", true, None::<&str>)?;
    let hide = MenuItem::with_id(app, "hide", "Hide", true, None::<&str>)?;
    let separator = tauri::menu::PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &hide, &separator, &quit])?;

    let icon = tray_icon(app);

    TrayIconBuilder::with_id("main")
        .tooltip("VettID Desktop")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .icon(icon)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "hide" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // Left click toggles the window. macOS users expect this; on Linux
            // the menu opens via right-click as configured above.
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let visible = window.is_visible().unwrap_or(false);
                    let _ = if visible { window.hide() } else {
                        let _ = window.show();
                        window.set_focus()
                    };
                }
            }
        })
        .build(app)?;

    Ok(())
}

fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Pick the tray icon. We reuse the default window icon (256×256 PNG bundled
/// by `tauri.conf.json` icon list) — Tauri scales it down for the menu bar.
fn tray_icon<R: Runtime>(app: &AppHandle<R>) -> Image<'_> {
    app.default_window_icon()
        .cloned()
        .expect("default window icon must be configured in tauri.conf.json")
}
