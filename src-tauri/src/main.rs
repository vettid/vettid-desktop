// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Disable WebKitGTK's DMABUF renderer on Linux. The default code
    // path crashes hard (SIGBUS) on Fedora 44 + mesa 26.0.6 + Wayland
    // under memory pressure — the GPU buffer gets truncated mid-share
    // and the entire webkit triplet dies. Falling back to the
    // shared-memory renderer trades a small composition perf hit for
    // a stable webview. Must be set BEFORE webkit initializes, so
    // here in main() rather than via .desktop file or shell env.
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
    }
    vettid_desktop::run();
}
