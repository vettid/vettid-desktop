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
//! Allowed is only the origin this platform serves the app from, with no
//! port and no user or password:
//! - `tauri://localhost` on macOS and Linux;
//! - `http://tauri.localhost` on Windows (`https://` only if the app's
//!   windows set `useHttpsScheme`, which they don't: a test checks it).
//!
//! `http(s)://tauri.localhost` off Windows, and `https://tauri.localhost`
//! on Windows, are not the app: they resolve to the loopback address, where
//! any local program may listen. In a debug build the configured
//! `devUrl`'s origin is allowed too. Anything else (another host, a port,
//! `file:`, `data:`, `blob:`, `about:`) is refused and logged, without the
//! query, the fragment or a host-less URL's body.
//!
//! The check compares scheme, host and port itself; it does not call
//! `Url::origin()`.
//!
//! What the guard cannot see (upstream, outside this hook):
//! - a navigation to a URL the `url` crate cannot parse is let through
//!   without calling the hook (tauri-runtime-wry falls back to allowing it);
//! - a navigation before the webview is registered with the app does not
//!   reach the plugins' hooks;
//! - on Windows, WebView2's `NavigationStarting` does not cover iframes.
//!   The CSP (`default-src 'self'`) keeps other origins out of frames.
//!
//! New windows: with no `on_new_window` handler, wry refuses a page's
//! request for one. A test keeps any such handler, and any webview or
//! window built in code, from being added without the guard.

use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Manager, Runtime, Url};

/// The plugin's name.
pub const NAME: &str = "vettid-nav-guard";

/// Whether the app's windows use `https://tauri.localhost` on Windows
/// (`useHttpsScheme`). They don't; a test checks tauri.conf.json.
const USE_HTTPS_SCHEME: bool = false;

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

/// Whether a webview may load `url`: the app's own origin on this
/// platform, or `dev`'s origin when one is given (a debug build's
/// `devUrl`).
pub fn allowed(url: &Url, dev: Option<&Url>) -> bool {
    allowed_on(url, dev, cfg!(windows), USE_HTTPS_SCHEME)
}

/// `allowed`, for a given platform: Windows (`windows`) or not, and on
/// Windows with `https` (`useHttpsScheme`) or not.
fn allowed_on(url: &Url, dev: Option<&Url>, windows: bool, https: bool) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    own_origin(url, windows, https) || dev.is_some_and(|d| same_origin(url, d))
}

/// The one origin the app is served from on the platform.
fn own_origin(url: &Url, windows: bool, https: bool) -> bool {
    let (scheme, host) = match (windows, https) {
        (false, _) => ("tauri", "localhost"),
        (true, false) => ("http", "tauri.localhost"),
        (true, true) => ("https", "tauri.localhost"),
    };
    url.scheme() == scheme && url.host_str() == Some(host) && url.port().is_none()
}

/// The same scheme, host and port (the default port when none is given).
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str().is_some()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// What is logged of a URL: scheme, host, port and path, never the query
/// or the fragment, and only the scheme of a URL with no host (a `data:`
/// or `blob:` URL's body can be anything).
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

    /// The platforms the guard is checked for, whatever this test runs on:
    /// (name, windows, https).
    const PLATFORMS: [(&str, bool, bool); 3] = [
        ("macOS and Linux", false, false),
        ("Windows", true, false),
        ("Windows with useHttpsScheme", true, true),
    ];

    /// Every URL that is the app's own origin on some platform.
    const OWN: [&str; 3] = [
        "tauri://localhost/",
        "http://tauri.localhost/",
        "https://tauri.localhost/",
    ];

    #[test]
    fn only_the_platforms_own_origin_passes() {
        for (name, windows, https) in PLATFORMS {
            let own = match (windows, https) {
                (false, _) => "tauri://localhost/",
                (true, false) => "http://tauri.localhost/",
                (true, true) => "https://tauri.localhost/",
            };
            for s in OWN {
                assert_eq!(
                    allowed_on(&u(s), None, windows, https),
                    s == own,
                    "{name}: {s}"
                );
            }
            // Paths on the own origin, and a host in capitals, pass.
            let base = u(own);
            assert!(
                allowed_on(&base.join("index.html").unwrap(), None, windows, https),
                "{name}"
            );
            assert!(
                allowed_on(&base.join("assets/index.js").unwrap(), None, windows, https),
                "{name}"
            );
        }
        assert!(allowed_on(&u("HTTP://TAURI.LOCALHOST/"), None, true, false));
        assert!(allowed_on(&u("tauri://localhost"), None, false, false));
    }

    #[test]
    fn this_build_takes_its_platforms_origin() {
        let own = if cfg!(windows) {
            "http://tauri.localhost/"
        } else {
            "tauri://localhost/"
        };
        for s in OWN {
            assert_eq!(allowed(&u(s), None), s == own, "{s}");
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
            "http://:pw@tauri.localhost/",
            "tauri://user@localhost/",
            "tauri://:pw@localhost/",
            "http://localhost/",
            "http://localhost:5173/",
            "http://ipc.localhost/",
            "ipc://localhost/",
            "asset://localhost/",
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
            for (name, windows, https) in PLATFORMS {
                assert!(
                    !allowed_on(&u(s), None, windows, https),
                    "{name}: {s} allowed"
                );
            }
        }
    }

    #[test]
    fn dev_origin_passes_only_when_given_and_only_itself() {
        let dev = u("http://localhost:5173");
        for (name, windows, https) in PLATFORMS {
            assert!(
                allowed_on(&u("http://localhost:5173/"), Some(&dev), windows, https),
                "{name}"
            );
            assert!(
                allowed_on(
                    &u("http://localhost:5173/src/main.ts"),
                    Some(&dev),
                    windows,
                    https
                ),
                "{name}"
            );
            assert!(
                !allowed_on(&u("http://localhost:5173/"), None, windows, https),
                "{name}"
            );
            for s in [
                "http://localhost:5174/",
                "https://localhost:5173/",
                "http://127.0.0.1:5173/",
                "http://localhost/",
                "http://localhost.evil:5173/",
                "http://user@localhost:5173/",
            ] {
                assert!(
                    !allowed_on(&u(s), Some(&dev), windows, https),
                    "{name}: {s} allowed against the dev origin"
                );
            }
        }
        // A dev URL with no host never makes anything pass.
        let odd = u("data:text/plain,x");
        assert!(!allowed(&u("data:text/plain,x"), Some(&odd)));
    }

    #[test]
    fn logs_no_query_fragment_or_body() {
        assert_eq!(
            for_log(&u("https://evil.example.com:444/p/a?token=secret#frag")),
            "https://evil.example.com:444/p/a"
        );
        assert_eq!(
            for_log(&u("https://evil.example.com/p?token=secret#frag")),
            "https://evil.example.com/p"
        );
        assert_eq!(for_log(&u("data:text/html,secret")), "data: (not shown)");
        assert!(!for_log(&u("blob:https://evil.example/secret-id")).contains("secret"));
    }

    /// The guard assumes the Windows origin is `http://tauri.localhost`: no
    /// window may set `useHttpsScheme` unless USE_HTTPS_SCHEME follows.
    #[test]
    fn the_config_matches_the_assumed_scheme() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json");
        let conf: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("tauri.conf.json"))
                .expect("JSON");
        let windows = conf["app"]["windows"].as_array().expect("app.windows");
        assert!(!windows.is_empty());
        for w in windows {
            let https = w
                .get("useHttpsScheme")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            assert_eq!(
                https, USE_HTTPS_SCHEME,
                "a window's useHttpsScheme is {https}: update USE_HTTPS_SCHEME"
            );
        }
    }

    /// Every webview the app makes gets the guard: the plugin is registered
    /// on the builder (on a line of code, not a comment), and no source file
    /// builds a webview or window of its own or handles new-window requests
    /// (the configuration's windows are made after the plugins, so the
    /// plugin's hook covers them). A new place that does must keep the
    /// guard and change this test.
    #[test]
    fn every_webview_has_the_guard() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let lib = std::fs::read_to_string(root.join("lib.rs")).expect("lib.rs");
        let registered = lib
            .lines()
            .filter(|l| l.trim_start().starts_with(".plugin(nav_guard::plugin())"))
            .count();
        assert_eq!(
            registered, 1,
            "lib.rs registers the navigation guard {registered} times on a line of code, want once"
        );
        assert!(!lib.contains("/*"), "lib.rs has a block comment: check by hand that the guard is not inside one, then update this test");
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
            for builder in [
                "WebviewWindowBuilder",
                "WebviewBuilder",
                "WindowBuilder",
                "add_child(",
                "on_new_window",
            ] {
                assert!(
                    !text.contains(builder),
                    "{} builds a webview or window, or handles new windows ({builder}): give it the guard and update this test",
                    p.display()
                );
            }
        }
        assert!(seen > 10, "only {seen} source files found");
    }
}
