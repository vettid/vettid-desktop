//! Opening a link in a message (VAULT-MESSAGING §10.5 "Links"): only an
//! `https://` URL, and only after the member said so in a native prompt
//! that shows the link's host.
//!
//! The window hands over the link's text as the message shows it; the
//! check, the prompt and the opening are all here. The window has no way of
//! its own to open a URL (its capability has no `shell:` permission), so
//! nothing it does can open a link without this prompt.
//!
//! - The text is checked as it is (length, control and bidi characters,
//!   whitespace, `https://`, no user or password), then parsed with the
//!   `url` crate and checked again (scheme exactly `https`, no user or
//!   password, a host). What opens is the parsed URL as `url` writes it,
//!   never the window's text.
//! - The prompt shows the parsed host: an internationalised name as
//!   punycode, with the port when it isn't 443.
//! - One prompt at a time: another call while one is shown answers busy.
//! - An "Open" sooner than `MIN_CONFIRM_MS` after the prompt appeared
//!   counts as not confirmed (a held key's repeats).
//! - Where the dialog's first button is its default (Windows, macOS),
//!   Cancel is first, so Return or Enter cancels.
//!
//! The URL is never logged: its path or query can hold anything.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rfd::{MessageButtons, MessageDialogResult};
use serde::Serialize;
use tauri::{AppHandle, Url, WebviewWindow};

/// The longest link text, in UTF-8 bytes, that may be opened (and the
/// longest URL once parsed). 2048 is the usual practical bound for a URL
/// (the sitemaps protocol's limit, and below the 2083 characters older
/// Windows browsers took). Real links fit; a longer "link" is more likely
/// to hide its real end than to be one, and a member can still copy it.
pub const MAX_LINK_LEN: usize = 2048;

/// An "Open" answered sooner than this after the prompt appeared is not a
/// confirmation. A member who opens a link with Enter and holds it a moment
/// too long sends repeats of Enter to the prompt as soon as it shows; this
/// keeps those repeats from answering it before the host can be read. The
/// prompt is then closed with nothing opened, and the member clicks the
/// link again.
pub const MIN_CONFIRM_MS: u64 = 500;

/// The prompt's buttons (the view's words for them).
pub const OPEN_LABEL: &str = "Open";
pub const CANCEL_LABEL: &str = "Cancel";

/// The isolates around the host, as in the view's `openLinkQuestion`.
const FSI: char = '\u{2068}';
const PDI: char = '\u{2069}';

/// The prompt's text (§10.5: "show its host and ask"), word for word the
/// view's `openLinkQuestion`.
pub fn question(host: &str) -> String {
    format!("Open this link in your browser? It goes to {FSI}{host}{PDI}.")
}

/// Why a link's text isn't opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Longer than `MAX_LINK_LEN` (as given, or once parsed).
    TooLong,
    /// A control character (Unicode Cc) or a bidi formatting character.
    ControlOrBidi,
    /// White space (the view never makes a link of text that has it).
    WhiteSpace,
    /// Not `https://`.
    NotHttps,
    /// A user name or password before the host.
    UserInfo,
    /// The `url` crate can't parse it.
    Unparsable,
    /// No host.
    NoHost,
}

impl Refusal {
    /// For the log (never the URL itself).
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::TooLong => "too long",
            Refusal::ControlOrBidi => "control or bidi character",
            Refusal::WhiteSpace => "white space",
            Refusal::NotHttps => "not https",
            Refusal::UserInfo => "user or password",
            Refusal::Unparsable => "not a URL",
            Refusal::NoHost => "no host",
        }
    }
}

/// A link that passed every check: what opens, and the host the prompt shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    url: Url,
    host: String,
}

impl Link {
    /// The URL that opens: the parsed URL as the `url` crate writes it.
    pub fn url(&self) -> &str {
        self.url.as_str()
    }

    /// The host as the prompt shows it: punycode, with a port that isn't 443.
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// The bidi formatting characters: ALM, LRM, RLM, the embeddings and
/// overrides (LRE..RLO) and the isolates (LRI..PDI).
fn is_bidi(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// The checks on the text as given, before it is parsed.
pub fn check_raw(raw: &str) -> Result<(), Refusal> {
    if raw.len() > MAX_LINK_LEN {
        return Err(Refusal::TooLong);
    }
    if raw.chars().any(|c| c.is_control() || is_bidi(c)) {
        return Err(Refusal::ControlOrBidi);
    }
    if raw.chars().any(char::is_whitespace) {
        return Err(Refusal::WhiteSpace);
    }
    let rest = match raw.get(..8) {
        Some(p) if p.eq_ignore_ascii_case("https://") => &raw[8..],
        _ => return Err(Refusal::NotHttps),
    };
    // The authority ends at the path, query or fragment (`\` is a path
    // separator for https too).
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return Err(Refusal::UserInfo);
    }
    if authority.is_empty() {
        return Err(Refusal::NoHost);
    }
    Ok(())
}

/// The checks on the parsed URL; the host as the prompt shows it.
pub fn check_parsed(url: Url) -> Result<Link, Refusal> {
    if url.scheme() != "https" {
        return Err(Refusal::NotHttps);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Refusal::UserInfo);
    }
    let name = match (url.host(), url.host_str()) {
        (Some(_), Some(h)) if !h.is_empty() => h.to_owned(),
        _ => return Err(Refusal::NoHost),
    };
    if url.as_str().len() > MAX_LINK_LEN {
        return Err(Refusal::TooLong);
    }
    let host = match url.port() {
        Some(port) => format!("{name}:{port}"),
        None => name,
    };
    Ok(Link { url, host })
}

/// Every check, in order: the text, then the parsed URL.
pub fn check(raw: &str) -> Result<Link, Refusal> {
    check_raw(raw)?;
    let url = Url::parse(raw).map_err(|_| Refusal::Unparsable)?;
    check_parsed(url)
}

/// Asks the member; `true` only for "Open".
pub trait Prompt {
    fn confirm(&self, question: &str) -> bool;
}

/// The system didn't open a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFailed;

/// Opens a URL in the member's browser.
pub trait Browser {
    fn open(&self, url: &str) -> Result<(), OpenFailed>;
}

/// A monotonic clock.
pub trait Clock {
    fn now(&self) -> Instant;
}

/// What happened to a link that passed the checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Confirmed and handed to the browser.
    Opened,
    /// Cancelled, or the prompt closed.
    NotConfirmed,
    /// "Open" sooner than `MIN_CONFIRM_MS`: not opened.
    TooFast,
}

/// Why nothing opened, other than the member's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    Refused(Refusal),
    /// Another link's prompt is shown.
    Busy,
    /// Confirmed, but the system didn't open it.
    NotOpened,
}

impl LinkError {
    /// What the window gets.
    pub fn code(self) -> &'static str {
        match self {
            LinkError::Refused(_) => "refused",
            LinkError::Busy => "busy",
            LinkError::NotOpened => "not_opened",
        }
    }

    /// For the log.
    pub fn reason(self) -> &'static str {
        match self {
            LinkError::Refused(r) => r.as_str(),
            LinkError::Busy => "another link's prompt is shown",
            LinkError::NotOpened => "the system didn't open it",
        }
    }
}

/// Holds the one-prompt-at-a-time flag while a prompt is shown.
struct Held<'a>(&'a AtomicBool);

impl<'a> Held<'a> {
    fn take(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Held(flag))
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Checks `raw`, asks the member, and opens the checked URL only on an
/// "Open" given at least `MIN_CONFIRM_MS` after the prompt appeared.
/// `showing` is set while a prompt is shown: a call meanwhile is busy.
pub fn open_link(
    raw: &str,
    showing: &AtomicBool,
    prompt: &dyn Prompt,
    browser: &dyn Browser,
    clock: &dyn Clock,
) -> Result<Outcome, LinkError> {
    let link = check(raw).map_err(LinkError::Refused)?;
    let _held = Held::take(showing).ok_or(LinkError::Busy)?;
    let shown = clock.now();
    let yes = prompt.confirm(&question(link.host()));
    let waited = clock.now().saturating_duration_since(shown);
    if !yes {
        return Ok(Outcome::NotConfirmed);
    }
    if waited < Duration::from_millis(MIN_CONFIRM_MS) {
        return Ok(Outcome::TooFast);
    }
    browser.open(link.url()).map_err(|_| LinkError::NotOpened)?;
    Ok(Outcome::Opened)
}

/// Whether the dialog backend makes its first button the default (Return
/// or Enter): rfd's Windows task dialog (`nDefaultButton` 0) and macOS
/// alert do. There Cancel goes first. rfd's GTK dialog sets no default,
/// and GTK's answer for a dismissed dialog isn't checked here, so on Linux
/// "Open" keeps the affirmative place and Cancel the cancelling one.
const CANCEL_FIRST: bool = cfg!(any(windows, target_os = "macos"));

/// The prompt's buttons, Cancel first or not. rfd answers a button by its
/// label (`Custom`), and a dismissed dialog as `Cancel`.
pub fn buttons_for(cancel_first: bool) -> MessageButtons {
    if cancel_first {
        MessageButtons::OkCancelCustom(CANCEL_LABEL.to_owned(), OPEN_LABEL.to_owned())
    } else {
        MessageButtons::OkCancelCustom(OPEN_LABEL.to_owned(), CANCEL_LABEL.to_owned())
    }
}

/// Whether the dialog's answer is "Open": its label, and nothing else.
pub fn confirmed(answer: &MessageDialogResult) -> bool {
    matches!(answer, MessageDialogResult::Custom(label) if label == OPEN_LABEL)
}

/// The native dialog (rfd), over the window that asked.
struct NativePrompt {
    app: AppHandle,
    window: WebviewWindow,
}

impl Prompt for NativePrompt {
    fn confirm(&self, question: &str) -> bool {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let title = self.app.package_info().name.clone();
        let question = question.to_owned();
        let window = self.window.clone();
        // Made on the main thread (macOS needs it there), answered on
        // another, as tauri-plugin-dialog does.
        let ran = self.app.run_on_main_thread(move || {
            let answer = rfd::AsyncMessageDialog::new()
                .set_title(title)
                .set_description(question)
                .set_buttons(buttons_for(CANCEL_FIRST))
                .set_parent(&window)
                .show();
            std::thread::spawn(move || {
                let _ = tx.send(tauri::async_runtime::block_on(answer));
            });
        });
        if ran.is_err() {
            return false;
        }
        // No answer (the app closing) is not a confirmation.
        rx.recv().is_ok_and(|answer| confirmed(&answer))
    }
}

/// The member's default browser, through the shell plugin from Rust (no
/// scope applies there; the window has no shell permission).
struct ShellBrowser {
    app: AppHandle,
}

impl Browser for ShellBrowser {
    fn open(&self, url: &str) -> Result<(), OpenFailed> {
        use tauri_plugin_shell::ShellExt;
        #[allow(deprecated)]
        self.app.shell().open(url, None).map_err(|_| OpenFailed)
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Set while a link's prompt is shown.
static SHOWING: AtomicBool = AtomicBool::new(false);

/// Opens a link in a message, after the member's "Open" in a native prompt
/// showing its host. `text` is the link as the message shows it. Answers
/// `opened`, `not_confirmed` or `too_fast`; or the error `refused`, `busy`
/// or `not_opened`.
#[tauri::command]
pub async fn open_message_link(
    app: AppHandle,
    window: WebviewWindow,
    text: String,
) -> Result<Outcome, String> {
    let done = tauri::async_runtime::spawn_blocking(move || {
        let prompt = NativePrompt { app: app.clone(), window };
        let browser = ShellBrowser { app };
        open_link(&text, &SHOWING, &prompt, &browser, &SystemClock)
    })
    .await;
    match done {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(e)) => {
            log::warn!("message link not opened: {}", e.reason());
            Err(e.code().to_owned())
        }
        Err(_) => {
            log::warn!("message link not opened: its prompt failed");
            Err(LinkError::NotOpened.code().to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn refused(raw: &str) -> Refusal {
        check(raw).expect_err(raw)
    }

    fn parsed(s: &str) -> Url {
        Url::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn other_schemes_are_refused() {
        for raw in [
            "http://example.com/",
            "file:///C:/Windows/System32/calc.exe",
            "file://server/share",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vettid://pair?code=1",
            "ms-settings:privacy",
            "https:example.com",
            "https:/example.com",
            "ftp://example.com/",
            "//example.com/",
            "example.com",
        ] {
            assert_eq!(refused(raw), Refusal::NotHttps, "{raw}");
        }
        // The same, once parsed.
        for s in [
            "http://example.com/",
            "file:///C:/x",
            "javascript:alert(1)",
            "data:text/plain,x",
            "vettid://pair",
        ] {
            assert_eq!(check_parsed(parsed(s)), Err(Refusal::NotHttps), "{s}");
        }
    }

    #[test]
    fn a_user_or_password_is_refused() {
        for raw in [
            "https://user@example.com/",
            "https://user:pw@example.com/",
            "https://:pw@example.com/",
            "https://@example.com/",
            "https://good.com@evil.example/",
            "https://a@b@evil.example/",
            "https://user@example.com\\path",
        ] {
            assert_eq!(refused(raw), Refusal::UserInfo, "{raw}");
        }
        // An @ after the host is the path's.
        assert!(check("https://example.com/@user").is_ok());
        assert!(check("https://example.com?to=a@b").is_ok());
        // Once parsed.
        assert_eq!(check_parsed(parsed("https://user@example.com/")), Err(Refusal::UserInfo));
        assert_eq!(check_parsed(parsed("https://:pw@example.com/")), Err(Refusal::UserInfo));
    }

    #[test]
    fn no_host_is_refused() {
        for raw in ["https://", "https:///", "https://?q", "https://#f", "https:///path"] {
            assert_eq!(refused(raw), Refusal::NoHost, "{raw}");
        }
        // Once parsed: the url crate keeps an https URL from losing its host,
        // and a URL with no host isn't https.
        let mut u = parsed("https://example.com/");
        assert!(u.set_host(None).is_err());
        assert!(check_parsed(u).is_ok());
        assert_eq!(check_parsed(parsed("data:,x")), Err(Refusal::NotHttps));
    }

    #[test]
    fn a_control_character_is_refused() {
        for c in ['\u{0}', '\u{7}', '\t', '\n', '\r', '\u{1B}', '\u{7F}', '\u{85}', '\u{9F}'] {
            for raw in [
                format!("https://example.com/a{c}b"),
                format!("https://exa{c}mple.com/"),
                format!("{c}https://example.com/"),
                format!("https://example.com/{c}"),
            ] {
                assert_eq!(refused(&raw), Refusal::ControlOrBidi, "{raw:?}");
            }
        }
    }

    #[test]
    fn a_bidi_character_is_refused() {
        for c in [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
            '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            for raw in [
                format!("https://example.com/{c}gpj.exe"),
                format!("https://exa{c}mple.com/"),
                format!("https://example.com/?q={c}"),
            ] {
                assert_eq!(refused(&raw), Refusal::ControlOrBidi, "{raw:?}");
            }
        }
    }

    #[test]
    fn white_space_is_refused() {
        for raw in ["https://example.com/a b", "https://example.com/\u{A0}", "https://example.com/\u{3000}", " https://example.com/"] {
            assert_eq!(refused(raw), Refusal::WhiteSpace, "{raw:?}");
        }
    }

    #[test]
    fn over_the_length_cap_is_refused() {
        let base = "https://example.com/";
        let at_cap = format!("{base}{}", "a".repeat(MAX_LINK_LEN - base.len()));
        assert_eq!(at_cap.len(), MAX_LINK_LEN);
        assert!(check(&at_cap).is_ok());
        let over = format!("{at_cap}a");
        assert_eq!(refused(&over), Refusal::TooLong);
        // In bytes: a multi-byte character counts by its bytes.
        let wide = format!("{base}{}", "\u{E9}".repeat((MAX_LINK_LEN - base.len()) / 2 + 1));
        assert!(wide.chars().count() < MAX_LINK_LEN);
        assert_eq!(refused(&wide), Refusal::TooLong);
        // Once parsed: percent-encoding can take a URL over the cap.
        let grows = format!("{base}{}", "\u{E9}".repeat((MAX_LINK_LEN - base.len()) / 2));
        assert!(check_raw(&grows).is_ok());
        assert_eq!(check(&grows), Err(Refusal::TooLong));
    }

    #[test]
    fn unparsable_is_refused() {
        for raw in ["https://exa%mple.com/", "https://[::1/", "https://example.com:99999/"] {
            assert_eq!(refused(raw), Refusal::Unparsable, "{raw}");
        }
    }

    #[test]
    fn the_host_shows_as_punycode_with_its_port() {
        let l = check("https://b\u{FC}cher.example/").expect("IDN");
        assert_eq!(l.host(), "xn--bcher-kva.example");
        assert_eq!(l.url(), "https://xn--bcher-kva.example/");
        assert_eq!(check("https://example.com:8443/x").expect("port").host(), "example.com:8443");
        assert_eq!(check("https://b\u{FC}cher.example:8443/").expect("both").host(), "xn--bcher-kva.example:8443");
        // 443 is https's own port: not shown, as the view's URL.host.
        assert_eq!(check("https://example.com:443/x").expect("443").host(), "example.com");
        assert_eq!(check("HTTPS://EXAMPLE.com/").expect("case").host(), "example.com");
        assert_eq!(check("https://[::1]:8443/").expect("v6").host(), "[::1]:8443");
        assert_eq!(
            question("xn--bcher-kva.example:8443"),
            "Open this link in your browser? It goes to \u{2068}xn--bcher-kva.example:8443\u{2069}."
        );
    }

    /// A clock the fake prompt moves on.
    struct FakeClock {
        start: Instant,
        at: Cell<Duration>,
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.start + self.at.get()
        }
    }

    /// A prompt that answers `yes` after `after`, recording what it asked.
    struct FakePrompt<'a> {
        clock: &'a FakeClock,
        yes: bool,
        after: Duration,
        asked: RefCell<Vec<String>>,
        during: Option<Box<dyn Fn() + 'a>>,
    }

    impl Prompt for FakePrompt<'_> {
        fn confirm(&self, question: &str) -> bool {
            self.asked.borrow_mut().push(question.to_owned());
            if let Some(f) = &self.during {
                f();
            }
            self.clock.at.set(self.clock.at.get() + self.after);
            self.yes
        }
    }

    #[derive(Default)]
    struct FakeBrowser {
        opened: RefCell<Vec<String>>,
        fail: bool,
    }

    impl Browser for FakeBrowser {
        fn open(&self, url: &str) -> Result<(), OpenFailed> {
            self.opened.borrow_mut().push(url.to_owned());
            if self.fail {
                Err(OpenFailed)
            } else {
                Ok(())
            }
        }
    }

    fn clock() -> FakeClock {
        FakeClock { start: Instant::now(), at: Cell::new(Duration::ZERO) }
    }

    fn prompt(clock: &FakeClock, yes: bool, after_ms: u64) -> FakePrompt<'_> {
        FakePrompt {
            clock,
            yes,
            after: Duration::from_millis(after_ms),
            asked: RefCell::new(Vec::new()),
            during: None,
        }
    }

    const RAW: &str = "HTTPS://B\u{FC}cher.Example:8443/p?q=1#f";
    const OPENS: &str = "https://xn--bcher-kva.example:8443/p?q=1#f";

    #[test]
    fn not_confirmed_is_not_opened() {
        let c = clock();
        let p = prompt(&c, false, 2000);
        let b = FakeBrowser::default();
        let flag = AtomicBool::new(false);
        assert_eq!(open_link(RAW, &flag, &p, &b, &c), Ok(Outcome::NotConfirmed));
        assert!(b.opened.borrow().is_empty());
        assert_eq!(*p.asked.borrow(), vec![question("xn--bcher-kva.example:8443")]);
        assert!(!flag.load(Ordering::Acquire));
    }

    #[test]
    fn confirmed_after_the_minimum_opens_exactly_the_checked_url() {
        let c = clock();
        let p = prompt(&c, true, MIN_CONFIRM_MS);
        let b = FakeBrowser::default();
        let flag = AtomicBool::new(false);
        assert_eq!(open_link(RAW, &flag, &p, &b, &c), Ok(Outcome::Opened));
        assert_eq!(*b.opened.borrow(), vec![OPENS.to_owned()]);
        assert!(!flag.load(Ordering::Acquire));
    }

    #[test]
    fn confirmed_before_the_minimum_is_not_opened() {
        for ms in [0, 1, MIN_CONFIRM_MS - 1] {
            let c = clock();
            let p = prompt(&c, true, ms);
            let b = FakeBrowser::default();
            let flag = AtomicBool::new(false);
            assert_eq!(open_link(RAW, &flag, &p, &b, &c), Ok(Outcome::TooFast), "{ms} ms");
            assert!(b.opened.borrow().is_empty(), "{ms} ms");
            assert!(!flag.load(Ordering::Acquire));
        }
    }

    #[test]
    fn a_refused_link_shows_no_prompt() {
        let c = clock();
        let p = prompt(&c, true, 2000);
        let b = FakeBrowser::default();
        let flag = AtomicBool::new(false);
        for raw in ["http://example.com/", "https://u@example.com/", "https://example.com/\u{202E}"] {
            assert!(matches!(open_link(raw, &flag, &p, &b, &c), Err(LinkError::Refused(_))), "{raw:?}");
        }
        assert!(p.asked.borrow().is_empty());
        assert!(b.opened.borrow().is_empty());
    }

    #[test]
    fn busy_while_a_prompt_is_shown() {
        // Already showing: busy, and no second prompt.
        let c = clock();
        let p = prompt(&c, true, 2000);
        let b = FakeBrowser::default();
        let flag = AtomicBool::new(true);
        assert_eq!(open_link(RAW, &flag, &p, &b, &c), Err(LinkError::Busy));
        assert!(p.asked.borrow().is_empty());
        assert!(b.opened.borrow().is_empty());
        assert!(flag.load(Ordering::Acquire), "a busy call left the other prompt's flag");

        // A call made while a prompt is up is busy; the first one goes on.
        let c = clock();
        let flag = AtomicBool::new(false);
        let inner_b = FakeBrowser::default();
        let inner_c = clock();
        let inner_p = prompt(&inner_c, true, 2000);
        let inner: RefCell<Option<Result<Outcome, LinkError>>> = RefCell::new(None);
        let mut p = prompt(&c, true, 2000);
        p.during = Some(Box::new(|| {
            assert!(flag.load(Ordering::Acquire));
            *inner.borrow_mut() = Some(open_link(RAW, &flag, &inner_p, &inner_b, &inner_c));
        }));
        let b = FakeBrowser::default();
        assert_eq!(open_link(RAW, &flag, &p, &b, &c), Ok(Outcome::Opened));
        assert_eq!(*inner.borrow(), Some(Err(LinkError::Busy)));
        assert!(inner_p.asked.borrow().is_empty());
        assert!(inner_b.opened.borrow().is_empty());
        assert_eq!(*b.opened.borrow(), vec![OPENS.to_owned()]);
        assert!(!flag.load(Ordering::Acquire));
    }

    #[test]
    fn a_failed_open_says_so() {
        let c = clock();
        let p = prompt(&c, true, 2000);
        let b = FakeBrowser { fail: true, ..Default::default() };
        let flag = AtomicBool::new(false);
        assert_eq!(open_link(RAW, &flag, &p, &b, &c), Err(LinkError::NotOpened));
        assert_eq!(LinkError::NotOpened.code(), "not_opened");
        assert_eq!(LinkError::Busy.code(), "busy");
        assert_eq!(LinkError::Refused(Refusal::NoHost).code(), "refused");
    }

    /// How rfd answers a two-button dialog: a pressed button by its label,
    /// a dismissed dialog (Escape, closed) as Cancel.
    fn answer(buttons: &MessageButtons, pressed: Option<usize>) -> MessageDialogResult {
        match (buttons, pressed) {
            (MessageButtons::OkCancelCustom(first, _), Some(0)) => MessageDialogResult::Custom(first.clone()),
            (MessageButtons::OkCancelCustom(_, second), Some(1)) => MessageDialogResult::Custom(second.clone()),
            _ => MessageDialogResult::Cancel,
        }
    }

    #[test]
    fn only_the_open_button_confirms_in_either_order() {
        for cancel_first in [true, false] {
            let buttons = buttons_for(cancel_first);
            let MessageButtons::OkCancelCustom(first, second) = &buttons else {
                panic!("two custom buttons");
            };
            let (open_at, default_label) = if cancel_first { (1, CANCEL_LABEL) } else { (0, OPEN_LABEL) };
            assert_eq!(first, default_label);
            assert_eq!([first.as_str(), second.as_str()].iter().filter(|l| **l == OPEN_LABEL).count(), 1);
            assert_eq!([first.as_str(), second.as_str()].iter().filter(|l| **l == CANCEL_LABEL).count(), 1);
            assert!(confirmed(&answer(&buttons, Some(open_at))), "{cancel_first}");
            assert!(!confirmed(&answer(&buttons, Some(1 - open_at))), "{cancel_first}");
            assert!(!confirmed(&answer(&buttons, None)), "{cancel_first}");
        }
        for other in [
            MessageDialogResult::Ok,
            MessageDialogResult::Yes,
            MessageDialogResult::No,
            MessageDialogResult::Cancel,
            MessageDialogResult::Custom(CANCEL_LABEL.to_owned()),
            MessageDialogResult::Custom("open".to_owned()),
        ] {
            assert!(!confirmed(&other), "{other:?}");
        }
        assert!(CANCEL_FIRST == cfg!(any(windows, target_os = "macos")));
    }

    /// Through the prompt trait: a prompt built like the native one, over
    /// rfd's answers, opens only on its Open button, in either order.
    #[test]
    fn the_flow_through_either_button_order() {
        struct Backend<'a> {
            clock: &'a FakeClock,
            buttons: MessageButtons,
            pressed: Option<usize>,
        }
        impl Prompt for Backend<'_> {
            fn confirm(&self, _: &str) -> bool {
                self.clock.at.set(self.clock.at.get() + Duration::from_millis(MIN_CONFIRM_MS + 100));
                confirmed(&answer(&self.buttons, self.pressed))
            }
        }
        for cancel_first in [true, false] {
            let open_at = if cancel_first { 1 } else { 0 };
            for (pressed, want) in [
                (Some(open_at), Outcome::Opened),
                (Some(1 - open_at), Outcome::NotConfirmed),
                (None, Outcome::NotConfirmed),
            ] {
                let c = clock();
                let p = Backend { clock: &c, buttons: buttons_for(cancel_first), pressed };
                let b = FakeBrowser::default();
                let flag = AtomicBool::new(false);
                assert_eq!(open_link(RAW, &flag, &p, &b, &c), Ok(want), "{cancel_first} {pressed:?}");
                let opened = b.opened.borrow().clone();
                if want == Outcome::Opened {
                    assert_eq!(opened, vec![OPENS.to_owned()]);
                } else {
                    assert!(opened.is_empty());
                }
            }
        }
    }

    /// The window can't open a URL itself: no capability grants it any of
    /// the shell plugin's permissions (`shell:default` includes
    /// `shell:allow-open`). Links open only through `open_message_link`.
    #[test]
    fn no_window_has_a_shell_permission() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
        let mut seen = 0;
        for e in std::fs::read_dir(&dir).expect("capabilities") {
            let p = e.expect("entry").path();
            let text = std::fs::read_to_string(&p).expect("capability");
            seen += 1;
            let cap: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            for perm in cap["permissions"].as_array().expect("permissions") {
                let id = perm.as_str().or_else(|| perm["identifier"].as_str()).expect("identifier");
                assert!(!id.starts_with("shell:"), "{} grants {id}", p.display());
            }
            assert!(!text.contains("shell:"), "{} names a shell permission", p.display());
        }
        assert!(seen > 0);
    }

    #[test]
    fn outcomes_serialize_as_the_window_reads_them() {
        assert_eq!(serde_json::to_string(&Outcome::Opened).unwrap(), "\"opened\"");
        assert_eq!(serde_json::to_string(&Outcome::NotConfirmed).unwrap(), "\"not_confirmed\"");
        assert_eq!(serde_json::to_string(&Outcome::TooFast).unwrap(), "\"too_fast\"");
    }
}
