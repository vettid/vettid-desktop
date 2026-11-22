//! The navigation guard: a webview of this app may load only the app's
//! own pages.
//!
//! Tauri gives the app's frontend access to its commands by the origin of
//! the page. A flaw in that check (GHSA-7gmj-67g7-phm9, and tauri#15266 for
//! an app without an `AppManifest`, as this one) once let a remote page call
//! the commands. Nothing in the app navigates away from its own pages, but
//! nothing enforced it either. This guard does: every navigation of every
//! webview the app makes is checked here first, so a future flaw of the
//! same kind fails secure.
//!
//! Allowed: `tauri://localhost` (macOS, Linux) and `http(s)://tauri.localhost`
//! (Windows), each with no port and no user, and in a debug build the
//! configured `devUrl`'s origin. Anything else (another host, a port,
//! `file:`, `data:`, `blob:`, `about:`) is refused and logged, without the
//! query, the fragment or a non-hierarchical URL's body.
//!
//! The check compares scheme, host and port itself; it does not call
//! `Url::origin()`.

use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Manager, Runtime, Url};

/// The plugin's name.
pub const NAME: &str = "vettid-nav-guard";

/// The guard, as a plugin: its navigation hook applies to every webview
/// the app creates, the configuration's windows included.
pub fn plugin<R: Runtime>() -> TauriPlugin<R> {
    Builder::new(NAME)
        .on_navigation(|webview, url| {
            let dev = if cfg!(debug_assertions) {
                webview.app_handle().config().build.dev_url.clone()
            } else {
                None
            };
            let ok = allowed(url, dev.as_ref());
            if ok {
                log::debug!("navigation allowed: {}", for_log(url));
            } else {
                log::warn!("navigation refused: {}", for_log(url));
            }
            ok
        })
        .build()
}

/// Whether a webview may load `url`: the app's own pages, or `dev`'s
/// origin when one is given (a debug build's `devUrl`).
pub fn allowed(url: &Url, dev: Option<&Url>) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "tauri" => url.host_str() == Some("localhost") && url.port().is_none(),
        "http" | "https" => {
            (url.host_str() == Some("tauri.localhost") && url.port().is_none()) || dev.is_some_and(|d| same_origin(url, d))
        }
        _ => false,
    }
}

/// The same scheme, host and port (the default port when none is given).
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() && a.host_str().is_some() && a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
}

/// What is logged of a refused URL: scheme, host, port and path, never the
/// query or the fragment, and only the scheme of a URL with no host (a
/// `data:` or `blob:` URL's body can be anything).
fn for_log(url: &Url) -> String {
    match url.host_str() {
        Some(host) => match url.port() {
            Some(port) => format!("{}://{}:{}{}", url.scheme(), host, port, url.path()),
            None => format!("{}://{}{}", url.scheme(), host, url.path()),
        },
        None => format!("{}: (not shown)", url.scheme()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn own_pages_pass() {
        for s in [
            "tauri://localhost",
            "tauri://localhost/",
            "tauri://localhost/index.html",
            "http://tauri.localhost/",
            "http://tauri.localhost/assets/index.js",
            "https://tauri.localhost/",
            "HTTP://TAURI.LOCALHOST/",
        ] {
            assert!(allowed(&u(s), None), "{s} refused");
        }
    }

    #[test]
    fn everything_else_is_refused() {
        for s in [
            "http://tauri.example.com/",
            "https://tauri.example.com/",
            "https://tauri.localhost.evil/",
            "http://tauri.localhost.evil.com/",
            "http://tauri.localhost./",
            "http://evil.tauri.localhost/",
            "http://tauri.localhost:8080/",
            "tauri://localhost:1/",
            "tauri://evil/",
            "tauri://localhost.evil/",
            "http://user@tauri.localhost/",
            "http://user:pw@tauri.localhost/",
            "http://localhost/",
            "http://localhost:5173/",
            "http://ipc.localhost/",
            "https://example.com/",
            "file:///C:/Windows/System32/",
            "file://localhost/etc/passwd",
            "data:text/html,<script>alert(1)</script>",
            "blob:http://tauri.localhost/0b8f",
            "blob:blob:http://tauri.localhost/0b8f",
            "about:blank",
            "javascript:alert(1)",
            "ws://tauri.localhost/",
        ] {
            assert!(!allowed(&u(s), None), "{s} allowed");
        }
    }

    #[test]
    fn dev_origin_passes_only_when_given_and_only_itself() {
        let dev = u("http://localhost:5173");
        assert!(allowed(&u("http://localhost:5173/"), Some(&dev)));
        assert!(allowed(&u("http://localhost:5173/src/main.ts"), Some(&dev)));
        assert!(!allowed(&u("http://localhost:5173/"), None));
        for s in ["http://localhost:5174/", "https://localhost:5173/", "http://127.0.0.1:5173/", "http://localhost/", "http://localhost.evil:5173/"] {
            assert!(!allowed(&u(s), Some(&dev)), "{s} allowed against the dev origin");
        }
        // A dev URL with no host never makes anything pass.
        let odd = u("data:text/plain,x");
        assert!(!allowed(&u("data:text/plain,x"), Some(&odd)));
    }

    #[test]
    fn logs_no_query_fragment_or_body() {
        assert_eq!(for_log(&u("https://evil.example.com:444/p/a?token=secret#frag")), "https://evil.example.com:444/p/a");
        assert_eq!(for_log(&u("data:text/html,secret")), "data: (not shown)");
        assert!(!for_log(&u("blob:https://evil.example/secret-id")).contains("secret"));
    }

    /// Every webview the app makes gets the guard: the plugin is registered
    /// on the builder, and no source file builds a webview or window of
    /// its own (the configuration's windows are made after the plugins,
    /// so the plugin's hook covers them). A new place that builds one must
    /// keep the guard and change this test.
    #[test]
    fn every_webview_has_the_guard() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let lib = std::fs::read_to_string(root.join("lib.rs")).expect("lib.rs");
        assert!(lib.contains(".plugin(nav_guard::plugin())"), "lib.rs does not register the navigation guard");
        let mut files = vec![root];
        let mut seen = 0;
        while let Some(p) = files.pop() {
            if p.is_dir() {
                for e in std::fs::read_dir(&p).expect("read_dir") {
                    files.push(e.expect("entry").path());
                }
                continue;
            }
            if p.extension().and_then(|e| e.to_str()) != Some("rs") || p.ends_with("nav_guard.rs") {
                continue;
            }
            seen += 1;
            let text = std::fs::read_to_string(&p).expect("source");
            for builder in ["WebviewWindowBuilder", "WebviewBuilder", "WindowBuilder", "add_child("] {
                assert!(!text.contains(builder), "{} builds a webview or window ({builder}): give it the guard and update this test", p.display());
            }
        }
        assert!(seen > 10, "only {seen} source files found");
    }
}
