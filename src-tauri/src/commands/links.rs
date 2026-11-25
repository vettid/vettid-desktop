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
//!   whitespace, `https://`, no user or password, the host's length), then
//!   parsed with the `url` crate and checked again (scheme exactly `https`,
//!   no user or password, a host of `[a-z0-9.-]` (punycode) or an IP
//!   address, at most 253 bytes with labels of at most 63). What opens is
//!   the parsed URL as `url` writes it, never the window's text.
//! - The prompt shows the parsed host, with the port when it isn't 443.
//! - One prompt at a time: another call while one is shown answers busy,
//!   and so does one within `QUIET_MS` of a prompt that wasn't confirmed.
//!   A prompt with no answer after `PROMPT_TIMEOUT_SECS` counts as not
//!   confirmed, and a later answer is ignored.
//! - An "Open" sooner than `MIN_CONFIRM_MS` after the prompt was on screen
//!   counts as not confirmed (a held key's repeats).
//! - Where the dialog's first button is its default (Windows, macOS),
//!   Cancel is first, so Return or Enter cancels.
//!
//! The URL is never logged: its path or query can hold anything.

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Mutex;
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

/// The longest host the prompt shows, in bytes once in punycode, and the
/// longest label in it: DNS's own bounds (RFC 1035). A longer host would
/// wrap across the prompt, and the member would read only its first line.
pub const MAX_HOST_LEN: usize = 253;
pub const MAX_LABEL_LEN: usize = 63;

/// An "Open" answered sooner than this after the prompt was on screen is
/// not a confirmation. A member who opens a link with Enter and holds it a
/// moment too long sends repeats of Enter to the prompt as soon as it
/// shows; this keeps those repeats from answering it before the host can
/// be read. The prompt is then closed with nothing opened, the view says to
/// click the link again, and the member does.
///
/// When the prompt was on screen: rfd has no "shown" callback. On Windows
/// the wait for the answer looks for the task dialog's window (a visible
/// `#32770` window of this process with an owner) and counts from when it
/// is first seen. Elsewhere, and on Windows when the answer comes before
/// the window is seen, it counts from just before the dialog was asked for,
/// so the time the dialog takes to appear counts toward it.
///
/// On Linux it is 1000 ms: rfd's GTK dialog sets no default button and no
/// way to set one, Cancel can't safely go first there (see
/// `cancel_first_for`), and no "shown" signal is read, so this is the only
/// guard against a held key.
#[cfg(not(target_os = "linux"))]
pub const MIN_CONFIRM_MS: u64 = 500;
#[cfg(target_os = "linux")]
pub const MIN_CONFIRM_MS: u64 = 1000;

/// After a prompt that wasn't confirmed (Cancel, closed, too fast, or no
/// answer), another call answers busy for this long, so a script can't put
/// the prompt straight back up.
pub const QUIET_MS: u64 = 1000;

/// A prompt with no answer after this long counts as not confirmed: the
/// one-prompt flag is let go, so links don't stay busy until a restart, and
/// a later answer from that prompt is ignored.
pub const PROMPT_TIMEOUT_SECS: u64 = 300;

/// How often the wait for an answer looks for the dialog on screen.
const SHOWN_POLL: Duration = Duration::from_millis(15);

/// The prompt's buttons (the view's words for them).
pub const OPEN_LABEL: &str = "Open";
pub const CANCEL_LABEL: &str = "Cancel";

/// The isolates around the host, as in the view's `openLinkQuestion`.
const FSI: char = '\u{2068}';
const PDI: char = '\u{2069}';

/// The prompt's text (§10.5: "show its host and ask"), word for word the
/// view's `openLinkQuestion` (both are tested against
/// tests/fixtures/link-question.json).
pub fn question(host: &str) -> String {
    format!("Open this link in your browser? It goes to {FSI}{host}{PDI}.")
}

/// Why a link's text isn't opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Longer than `MAX_LINK_LEN` (as given, or once parsed).
    TooLong,
    /// A host longer than `MAX_HOST_LEN`, or a label in it longer than
    /// `MAX_LABEL_LEN`.
    HostTooLong,
    /// A host name, once parsed, with a character other than `a-z`, `0-9`,
    /// `.` and `-`.
    HostCharacters,
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
            Refusal::HostTooLong => "host too long",
            Refusal::HostCharacters => "host characters",
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

/// Whether a host name is within `MAX_HOST_LEN` and `MAX_LABEL_LEN`, its
/// length counted by `len` and its labels split at `is_dot`.
fn host_fits(name: &str, len: fn(&str) -> usize, is_dot: fn(char) -> bool) -> bool {
    len(name) <= MAX_HOST_LEN && name.split(is_dot).all(|label| len(label) <= MAX_LABEL_LEN)
}

/// The dots IDNA maps to `.` (full stop, ideographic, fullwidth, halfwidth).
fn is_any_dot(c: char) -> bool {
    matches!(c, '.' | '\u{3002}' | '\u{FF0E}' | '\u{FF61}')
}

fn char_len(s: &str) -> usize {
    s.chars().count()
}

/// The characters a host name may have once parsed (punycode included).
fn host_char_ok(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
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
    // The host as written, without its port. Counted in characters: a
    // name's punycode is never shorter than its characters, so a host
    // refused here would be refused once parsed too.
    if !authority.starts_with('[') {
        let name = authority.split(':').next().unwrap_or(authority);
        if !host_fits(name, char_len, is_any_dot) {
            return Err(Refusal::HostTooLong);
        }
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
    // A name (not an IP address), as the url crate writes it: lower case,
    // in punycode.
    if let Some(d) = url.domain() {
        if !d.bytes().all(host_char_ok) {
            return Err(Refusal::HostCharacters);
        }
        if !host_fits(d, str::len, |c| c == '.') {
            return Err(Refusal::HostTooLong);
        }
    }
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

/// What a prompt came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// The member answered: `open` only for the Open button. `shown` is
    /// when the prompt was seen on screen, or when it was asked for where
    /// that can't be seen (`MIN_CONFIRM_MS`).
    Answered { open: bool, shown: Instant },
    /// No answer within `PROMPT_TIMEOUT_SECS`.
    TimedOut,
    /// The prompt couldn't be shown, or gave no answer.
    Failed,
}

/// Asks the member.
pub trait Prompt {
    fn confirm(&self, question: &str, clock: &dyn Clock) -> Reply;
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
    /// Cancelled, the prompt closed, or no answer in time.
    NotConfirmed,
    /// "Open" sooner than `MIN_CONFIRM_MS`: not opened.
    TooFast,
}

/// Why nothing opened, other than the member's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    Refused(Refusal),
    /// Another link's prompt is shown, or one wasn't confirmed just now.
    Busy,
    /// The prompt couldn't be shown, or gave no answer.
    NoPrompt,
    /// Confirmed, but the system didn't open it.
    NotOpened,
}

impl LinkError {
    /// What the window gets.
    pub fn code(self) -> &'static str {
        match self {
            LinkError::Refused(_) => "refused",
            LinkError::Busy => "busy",
            LinkError::NoPrompt => "no_prompt",
            LinkError::NotOpened => "not_opened",
        }
    }

    /// For the log.
    pub fn reason(self) -> &'static str {
        match self {
            LinkError::Refused(r) => r.as_str(),
            LinkError::Busy => "another link's prompt is shown, or was just declined",
            LinkError::NoPrompt => "the prompt couldn't be shown",
            LinkError::NotOpened => "the system didn't open it",
        }
    }
}

/// One prompt at a time, and a quiet time after one that wasn't confirmed.
pub struct Gate(Mutex<GateState>);

struct GateState {
    showing: bool,
    quiet_until: Option<Instant>,
}

impl Gate {
    pub const fn new() -> Self {
        Gate(Mutex::new(GateState { showing: false, quiet_until: None }))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether a prompt is shown.
    pub fn showing(&self) -> bool {
        self.state().showing
    }

    /// The gate for one prompt, if none is shown and the quiet time is over.
    fn take(&self, now: Instant) -> Option<Held<'_>> {
        let mut s = self.state();
        if s.showing || s.quiet_until.is_some_and(|until| now < until) {
            return None;
        }
        s.showing = true;
        s.quiet_until = None;
        Some(Held { gate: self, quiet_until: None })
    }
}

impl Default for Gate {
    fn default() -> Self {
        Gate::new()
    }
}

/// Holds the gate while a prompt is shown; on release, the quiet time.
struct Held<'a> {
    gate: &'a Gate,
    quiet_until: Option<Instant>,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let mut s = self.gate.state();
        s.showing = false;
        s.quiet_until = self.quiet_until;
    }
}

/// Checks `raw`, asks the member, and opens the checked URL only on an
/// "Open" given at least `MIN_CONFIRM_MS` after the prompt was on screen.
pub fn open_link(
    raw: &str,
    gate: &Gate,
    prompt: &dyn Prompt,
    browser: &dyn Browser,
    clock: &dyn Clock,
) -> Result<Outcome, LinkError> {
    let link = check(raw).map_err(LinkError::Refused)?;
    let mut held = gate.take(clock.now()).ok_or(LinkError::Busy)?;
    let reply = prompt.confirm(&question(link.host()), clock);
    let answered = clock.now();
    let quiet = Some(answered + Duration::from_millis(QUIET_MS));
    match reply {
        Reply::Failed => Err(LinkError::NoPrompt),
        Reply::TimedOut | Reply::Answered { open: false, .. } => {
            held.quiet_until = quiet;
            Ok(Outcome::NotConfirmed)
        }
        Reply::Answered { open: true, shown }
            if answered.saturating_duration_since(shown) < Duration::from_millis(MIN_CONFIRM_MS) =>
        {
            held.quiet_until = quiet;
            Ok(Outcome::TooFast)
        }
        Reply::Answered { open: true, .. } => {
            browser.open(link.url()).map_err(|_| LinkError::NotOpened)?;
            Ok(Outcome::Opened)
        }
    }
}

/// Waits for the dialog's answer on `rx`: at most `timeout` from `asked`,
/// looking every `poll` for the dialog on screen (`shown`). The time the
/// dialog was first seen, or `asked` if it never was, goes with the answer.
/// On a time-out `rx` is dropped with the reply, so a later answer goes
/// nowhere.
pub fn wait_reply(
    rx: Receiver<MessageDialogResult>,
    asked: Instant,
    timeout: Duration,
    poll: Duration,
    clock: &dyn Clock,
    shown: &dyn Fn() -> bool,
) -> Reply {
    let mut seen: Option<Instant> = None;
    loop {
        if seen.is_none() && shown() {
            seen = Some(clock.now());
        }
        let left = timeout.saturating_sub(clock.now().saturating_duration_since(asked));
        if left.is_zero() {
            return Reply::TimedOut;
        }
        match rx.recv_timeout(left.min(poll)) {
            Ok(answer) => {
                return Reply::Answered { open: confirmed(&answer), shown: seen.unwrap_or(asked) }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Reply::Failed,
        }
    }
}

/// The platforms, for the per-platform choices below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    MacOs,
    Linux,
}

/// This build's platform.
pub const OS: Os = if cfg!(windows) {
    Os::Windows
} else if cfg!(target_os = "macos") {
    Os::MacOs
} else {
    Os::Linux
};

/// Which of rfd's dialogs the prompt uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogPath {
    /// `AsyncMessageDialog`, made on the main thread.
    Async,
    /// `MessageDialog::show`, on a thread of our own.
    Blocking,
}

/// rfd 0.16.1's async GTK dialog answers custom buttons as plain `Ok` and
/// `Cancel` (gtk3/message_dialog.rs `show_async`), and panics on any other
/// GTK response; its blocking one answers them by label (`Custom`) and
/// anything else as `Cancel`. So on Linux the prompt uses the blocking one,
/// which rfd runs on its own GTK thread. Windows and macOS answer by label
/// either way, and keep the async one (made on the main thread, as
/// tauri-plugin-dialog does).
pub fn path_for(os: Os) -> DialogPath {
    match os {
        Os::Linux => DialogPath::Blocking,
        Os::Windows | Os::MacOs => DialogPath::Async,
    }
}

/// Whether Cancel goes first: where the dialog backend makes its first
/// button the default (Return or Enter), as rfd's Windows task dialog
/// (`nDefaultButton` 0) and macOS alert do. rfd's GTK dialog sets no
/// default, and GTK's answer for a dismissed dialog isn't checked here, so
/// on Linux "Open" keeps the affirmative place and Cancel the cancelling
/// one.
pub fn cancel_first_for(os: Os) -> bool {
    match os {
        Os::Windows | Os::MacOs => true,
        Os::Linux => false,
    }
}

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

/// Whether the prompt is on screen, where that can be seen.
#[cfg(windows)]
fn dialog_shown() -> bool {
    win::task_dialog_shown()
}

#[cfg(not(windows))]
fn dialog_shown() -> bool {
    false
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowThreadProcessId, IsWindowVisible,
    };

    /// The dialog class a task dialog's window has.
    const DIALOG_CLASS: [u16; 6] = [b'#' as u16, b'3' as u16, b'2' as u16, b'7' as u16, b'7' as u16, b'0' as u16];

    /// Whether a task dialog of this process is on screen.
    pub fn task_dialog_shown() -> bool {
        find_task_dialog().is_some()
    }

    /// A visible top-level window of this process of class `#32770` (a
    /// dialog; the app makes no other than the link's prompt).
    pub fn find_task_dialog() -> Option<HWND> {
        let mut found: HWND = std::ptr::null_mut();
        // SAFETY: `each` only writes through the pointer to `found`, which
        // outlives the call; EnumWindows calls it on this thread.
        unsafe { EnumWindows(Some(each), &mut found as *mut HWND as LPARAM) };
        (!found.is_null()).then_some(found)
    }

    unsafe extern "system" fn each(hwnd: HWND, data: LPARAM) -> BOOL {
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid != std::process::id() || IsWindowVisible(hwnd) == 0 {
            return 1;
        }
        let mut class = [0u16; 16];
        let n = GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32);
        if n > 0 && class[..n as usize] == DIALOG_CLASS {
            *(data as *mut HWND) = hwnd;
            return 0;
        }
        1
    }
}

/// The native dialog (rfd), over the window that asked.
struct NativePrompt {
    app: AppHandle,
    window: WebviewWindow,
}

impl Prompt for NativePrompt {
    /// A failure we can see is `Failed`: the main thread or a new thread
    /// not taking the dialog, or the answer's sender gone (the dialog's
    /// thread ended without one). rfd answers some failures of the dialog
    /// itself as Cancel (on Windows, a `TaskDialogIndirect` that fails),
    /// and those can't be told from one.
    fn confirm(&self, question: &str, clock: &dyn Clock) -> Reply {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let title = self.app.package_info().name.clone();
        let question = question.to_owned();
        let window = self.window.clone();
        let buttons = buttons_for(cancel_first_for(OS));
        let asked = clock.now();
        let started = match path_for(OS) {
            DialogPath::Async => self
                .app
                .run_on_main_thread(move || {
                    let answer = rfd::AsyncMessageDialog::new()
                        .set_title(title)
                        .set_description(question)
                        .set_buttons(buttons)
                        .set_parent(&window)
                        .show();
                    std::thread::spawn(move || {
                        let _ = tx.send(tauri::async_runtime::block_on(answer));
                    });
                })
                .is_ok(),
            DialogPath::Blocking => std::thread::Builder::new()
                .name("link-prompt".into())
                .spawn(move || {
                    let answer = rfd::MessageDialog::new()
                        .set_title(title)
                        .set_description(question)
                        .set_buttons(buttons)
                        .set_parent(&window)
                        .show();
                    let _ = tx.send(answer);
                })
                .is_ok(),
        };
        if !started {
            return Reply::Failed;
        }
        wait_reply(rx, asked, Duration::from_secs(PROMPT_TIMEOUT_SECS), SHOWN_POLL, clock, &dialog_shown)
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
        // The `open` crate's `that_detached`: on Windows `ShellExecuteExW`
        // with the default verb, which hands an https URL to the default
        // browser; `open` on macOS, xdg-open and the like on Linux. On
        // Windows that is so only with open's `shellexecute-on-windows`
        // feature (tauri-plugin-shell turns it on); without it the URL
        // would go through `cmd /c start`. A test checks the lockfile for it.
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

/// The links' one prompt.
static GATE: Gate = Gate::new();

/// Opens a link in a message, after the member's "Open" in a native prompt
/// showing its host. `text` is the link as the message shows it. Answers
/// `opened`, `not_confirmed` or `too_fast`; or the error `refused`, `busy`,
/// `no_prompt` or `not_opened`.
#[tauri::command]
pub async fn open_message_link(
    app: AppHandle,
    window: WebviewWindow,
    text: String,
) -> Result<Outcome, String> {
    let done = tauri::async_runtime::spawn_blocking(move || {
        let prompt = NativePrompt { app: app.clone(), window };
        let browser = ShellBrowser { app };
        open_link(&text, &GATE, &prompt, &browser, &SystemClock)
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
            Err(LinkError::NoPrompt.code().to_owned())
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

    /// A host of `labels` labels of `len` letters each, joined by dots.
    fn host_of(labels: usize, len: usize) -> String {
        vec!["a".repeat(len); labels].join(".")
    }

    #[test]
    fn a_host_over_253_bytes_or_a_label_over_63_is_refused() {
        // 3 labels of 63, one of 61, and dots: 253.
        let fits = format!("{}.{}", host_of(3, 63), "a".repeat(61));
        assert_eq!(fits.len(), MAX_HOST_LEN);
        assert!(check(&format!("https://{fits}/")).is_ok());
        assert!(check(&format!("https://{fits}:8443/")).is_ok());
        let long = format!("{fits}a");
        assert_eq!(refused(&format!("https://{long}/")), Refusal::HostTooLong);
        assert_eq!(check_raw(&format!("https://{long}/")), Err(Refusal::HostTooLong));
        let label = format!("{}.example", "a".repeat(MAX_LABEL_LEN + 1));
        assert_eq!(check_raw(&format!("https://{label}/")), Err(Refusal::HostTooLong));
        assert!(check(&format!("https://{}.example/", "a".repeat(MAX_LABEL_LEN))).is_ok());
        // A 2,000-character host.
        assert_eq!(refused(&format!("https://{}/", host_of(40, 49))), Refusal::HostTooLong);
        // Once parsed, in punycode: a label of 60 characters with one
        // non-ASCII passes as written and is too long as punycode.
        let idn = format!("{}\u{FC}.example", "a".repeat(59));
        assert!(check_raw(&format!("https://{idn}/")).is_ok());
        assert_eq!(refused(&format!("https://{idn}/")), Refusal::HostTooLong);
        // And the host as a whole: five labels of 48 characters, 244 as
        // written, each longer in punycode (xn--, a dash, the encoding).
        let whole = vec![format!("{}\u{FC}", "a".repeat(47)); 5].join(".");
        assert_eq!(whole.chars().count(), 244);
        assert!(check_raw(&format!("https://{whole}/")).is_ok());
        assert_eq!(check_parsed(parsed(&format!("https://{whole}/"))), Err(Refusal::HostTooLong));
        // An address isn't a name: no label rule.
        assert!(check("https://[2001:db8::1]:8443/").is_ok());
        assert!(check("https://192.0.2.1/").is_ok());
    }

    #[test]
    fn a_host_name_has_only_a_z_0_9_dot_and_dash() {
        // What the url crate lets through in a host name, other than those.
        for raw in [
            "https://a_b.example/",
            "https://a*b.example/",
            "https://a!b.example/",
            "https://a$b.example/",
            "https://a&b.example/",
            "https://a'b.example/",
            "https://a(b).example/",
            "https://a+b.example/",
            "https://a,b.example/",
            "https://a;b.example/",
            "https://a=b.example/",
            "https://a~b.example/",
            "https://a\"b.example/",
            "https://a{b}.example/",
            "https://a`b.example/",
            "https://a$%7Bb.example/",
        ] {
            match check(raw) {
                Err(Refusal::HostCharacters) | Err(Refusal::Unparsable) => {}
                other => panic!("{raw}: {other:?}"),
            }
        }
        for raw in ["https://a_b.example/", "https://a*b.example/", "https://a~b.example/"] {
            assert_eq!(refused(raw), Refusal::HostCharacters, "{raw}");
            assert_eq!(check_parsed(parsed(raw)), Err(Refusal::HostCharacters), "{raw}");
        }
        // Lower case, digits, dots and dashes; capitals and IDN once parsed;
        // IP addresses.
        for raw in [
            "https://a-b.example-1.com/",
            "https://EXAMPLE.com/",
            "https://b\u{FC}cher.example/",
            "https://example.com./",
            "https://192.0.2.1:8443/",
            "https://[2001:db8::1]/",
        ] {
            assert!(check(raw).is_ok(), "{raw}");
        }
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
    }

    /// The prompt's text is the fixture's, which the view's test checks too.
    #[test]
    fn the_question_is_the_shared_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/link-question.json"
        ))
        .expect("fixture");
        let host = fixture["host"].as_str().expect("host");
        assert_eq!(question(host), fixture["question"].as_str().expect("question"));
        assert_eq!(
            question("xn--bcher-kva.example:8443"),
            "Open this link in your browser? It goes to \u{2068}xn--bcher-kva.example:8443\u{2069}."
        );
    }

    /// The open goes through ShellExecuteExW on Windows only with the `open`
    /// crate's `shellexecute-on-windows` feature; without it, `cmd /c
    /// start`. That feature's only dependency is `dunce`, so the lockfile
    /// lists `dunce` under `open` exactly when the feature is resolved on.
    #[test]
    fn open_goes_through_shellexecute() {
        let lock = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"))
            .expect("Cargo.lock");
        let opens: Vec<&str> = lock
            .split("\n\n")
            .filter(|b| b.starts_with("[[package]]\nname = \"open\"\n"))
            .collect();
        assert_eq!(opens.len(), 1, "one `open` in the lockfile");
        assert!(opens[0].contains("\n \"dunce\""), "open without shellexecute-on-windows:\n{}", opens[0]);
        let shell: Vec<&str> = lock
            .split("\n\n")
            .filter(|b| b.starts_with("[[package]]\nname = \"tauri-plugin-shell\"\n"))
            .collect();
        assert_eq!(shell.len(), 1);
        assert!(shell[0].contains("\n \"open\""), "tauri-plugin-shell opens through `open`");
    }

    /// A clock the fake prompt moves on.
    struct FakeClock {
        start: Instant,
        at: Cell<Duration>,
    }

    impl FakeClock {
        fn advance(&self, ms: u64) {
            self.at.set(self.at.get() + Duration::from_millis(ms));
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.start + self.at.get()
        }
    }

    /// A prompt that shows after `appear` and is answered `after` that,
    /// recording what it asked.
    struct FakePrompt<'a> {
        clock: &'a FakeClock,
        reply: Option<bool>,
        failed: bool,
        timed_out: bool,
        appear: Duration,
        after: Duration,
        asked: RefCell<Vec<String>>,
        during: Option<Box<dyn Fn() + 'a>>,
    }

    impl Prompt for FakePrompt<'_> {
        fn confirm(&self, question: &str, clock: &dyn Clock) -> Reply {
            self.asked.borrow_mut().push(question.to_owned());
            if let Some(f) = &self.during {
                f();
            }
            self.clock.at.set(self.clock.at.get() + self.appear);
            let shown = clock.now();
            self.clock.at.set(self.clock.at.get() + self.after);
            if self.failed {
                return Reply::Failed;
            }
            if self.timed_out {
                return Reply::TimedOut;
            }
            Reply::Answered { open: self.reply.unwrap_or(false), shown }
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
            reply: Some(yes),
            failed: false,
            timed_out: false,
            appear: Duration::ZERO,
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
        let gate = Gate::new();
        assert_eq!(open_link(RAW, &gate, &p, &b, &c), Ok(Outcome::NotConfirmed));
        assert!(b.opened.borrow().is_empty());
        assert_eq!(*p.asked.borrow(), vec![question("xn--bcher-kva.example:8443")]);
        assert!(!gate.showing());
    }

    #[test]
    fn confirmed_after_the_minimum_opens_exactly_the_checked_url() {
        let c = clock();
        let p = prompt(&c, true, MIN_CONFIRM_MS);
        let b = FakeBrowser::default();
        let gate = Gate::new();
        assert_eq!(open_link(RAW, &gate, &p, &b, &c), Ok(Outcome::Opened));
        assert_eq!(*b.opened.borrow(), vec![OPENS.to_owned()]);
        assert!(!gate.showing());
        // No quiet time after an Open: the next link asks at once.
        assert_eq!(open_link(RAW, &gate, &p, &b, &c), Ok(Outcome::Opened));
        assert_eq!(p.asked.borrow().len(), 2);
    }

    #[test]
    fn confirmed_before_the_minimum_is_not_opened() {
        for ms in [0, 1, MIN_CONFIRM_MS - 1] {
            let c = clock();
            let p = prompt(&c, true, ms);
            let b = FakeBrowser::default();
            let gate = Gate::new();
            assert_eq!(open_link(RAW, &gate, &p, &b, &c), Ok(Outcome::TooFast), "{ms} ms");
            assert!(b.opened.borrow().is_empty(), "{ms} ms");
            assert!(!gate.showing());
        }
    }

    /// The minimum counts from when the prompt was on screen, not from
    /// when it was asked for.
    #[test]
    fn the_minimum_counts_from_the_prompt_on_screen() {
        // On screen 400 ms after it was asked for, answered 300 ms later:
        // too fast, though 700 ms after asking.
        let c = clock();
        let mut p = prompt(&c, true, 300);
        p.appear = Duration::from_millis(400);
        let b = FakeBrowser::default();
        let gate = Gate::new();
        assert_eq!(open_link(RAW, &gate, &p, &b, &c), Ok(Outcome::TooFast));
        assert!(b.opened.borrow().is_empty());
        // Answered MIN_CONFIRM_MS after it was on screen: opened.
        let c = clock();
        let mut p = prompt(&c, true, MIN_CONFIRM_MS);
        p.appear = Duration::from_millis(400);
        let gate = Gate::new();
        assert_eq!(open_link(RAW, &gate, &p, &b, &c), Ok(Outcome::Opened));
    }

    #[test]
    fn the_minimum_is_pinned() {
        assert_eq!(MIN_CONFIRM_MS, if cfg!(target_os = "linux") { 1000 } else { 500 });
        assert_eq!(QUIET_MS, 1000);
        assert_eq!(PROMPT_TIMEOUT_SECS, 300);
    }

    #[test]
    fn a_refused_link_shows_no_prompt() {
        let c = clock();
        let p = prompt(&c, true, 2000);
        let b = FakeBrowser::default();
        let gate = Gate::new();
        for raw in ["http://example.com/", "https://u@example.com/", "https://example.com/\u{202E}", "https://a_b.example/"] {
            assert!(matches!(open_link(raw, &gate, &p, &b, &c), Err(LinkError::Refused(_))), "{raw:?}");
        }
        assert!(p.asked.borrow().is_empty());
        assert!(b.opened.borrow().is_empty());
    }

    #[test]
    fn busy_while_a_prompt_is_shown() {
        // A call made while a prompt is up is busy and shows nothing; the
        // first one goes on.
        let c = clock();
        let gate = Gate::new();
        let inner_b = FakeBrowser::default();
        let inner_c = clock();
        let inner_p = prompt(&inner_c, true, 2000);
        let inner: RefCell<Option<Result<Outcome, LinkError>>> = RefCell::new(None);
        let mut p = prompt(&c, true, 2000);
        p.during = Some(Box::new(|| {
            assert!(gate.showing());
            *inner.borrow_mut() = Some(open_link(RAW, &gate, &inner_p, &inner_b, &inner_c));
        }));
        let b = FakeBrowser::default();
        assert_eq!(open_link(RAW, &gate, &p, &b, &c), Ok(Outcome::Opened));
        assert_eq!(*inner.borrow(), Some(Err(LinkError::Busy)));
        assert!(inner_p.asked.borrow().is_empty());
        assert!(inner_b.opened.borrow().is_empty());
        assert_eq!(*b.opened.borrow(), vec![OPENS.to_owned()]);
        assert!(!gate.showing());
    }

    #[test]
    fn busy_for_a_second_after_a_prompt_that_wasnt_confirmed() {
        // Cancelled (after 2 s), too fast (at once), or no answer in time.
        for (yes, timed_out, after, first) in [
            (false, false, 2000, Outcome::NotConfirmed),
            (true, false, 0, Outcome::TooFast),
            (true, true, 2000, Outcome::NotConfirmed),
        ] {
            let c = clock();
            let gate = Gate::new();
            let b = FakeBrowser::default();
            let mut p = prompt(&c, yes, after);
            p.timed_out = timed_out;
            assert_eq!(open_link(RAW, &gate, &p, &b, &c), Ok(first));
            assert!(!gate.showing());
            // Within QUIET_MS of the answer: busy, no prompt.
            let later = prompt(&c, true, MIN_CONFIRM_MS);
            assert_eq!(open_link(RAW, &gate, &later, &b, &c), Err(LinkError::Busy), "{first:?}");
            c.advance(QUIET_MS - 1);
            assert_eq!(open_link(RAW, &gate, &later, &b, &c), Err(LinkError::Busy), "{first:?}");
            assert!(later.asked.borrow().is_empty());
            // A busy answer doesn't make the quiet time longer.
            c.advance(1);
            assert_eq!(open_link(RAW, &gate, &later, &b, &c), Ok(Outcome::Opened), "{first:?}");
            assert_eq!(later.asked.borrow().len(), 1);
            assert_eq!(*b.opened.borrow(), vec![OPENS.to_owned()]);
        }
    }

    #[test]
    fn a_prompt_with_no_answer_opens_nothing_and_lets_go() {
        let c = clock();
        let gate = Gate::new();
        let b = FakeBrowser::default();
        let mut p = prompt(&c, true, 2000);
        p.timed_out = true;
        assert_eq!(open_link(RAW, &gate, &p, &b, &c), Ok(Outcome::NotConfirmed));
        assert!(b.opened.borrow().is_empty());
        assert!(!gate.showing());
    }

    /// The wait itself: no answer within the time-out is `TimedOut`, and
    /// the answer coming later goes nowhere.
    #[test]
    fn the_wait_times_out_and_ignores_a_late_answer() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let asked = Instant::now();
        let reply = wait_reply(rx, asked, Duration::from_millis(60), Duration::from_millis(5), &SystemClock, &|| false);
        assert_eq!(reply, Reply::TimedOut);
        assert!(asked.elapsed() >= Duration::from_millis(60));
        // The receiver is gone with the reply: a late Open is refused.
        assert!(tx.send(MessageDialogResult::Custom(OPEN_LABEL.to_owned())).is_err());
    }

    #[test]
    fn the_wait_takes_the_answer_and_when_the_dialog_was_seen() {
        // Answered: the label decides; never seen on screen: counted from
        // when it was asked for.
        for (answer, open) in [
            (MessageDialogResult::Custom(OPEN_LABEL.to_owned()), true),
            (MessageDialogResult::Custom(CANCEL_LABEL.to_owned()), false),
            (MessageDialogResult::Cancel, false),
            (MessageDialogResult::Ok, false),
        ] {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            tx.send(answer.clone()).expect("send");
            let asked = Instant::now();
            let reply = wait_reply(rx, asked, Duration::from_secs(5), Duration::from_millis(5), &SystemClock, &|| false);
            assert_eq!(reply, Reply::Answered { open, shown: asked }, "{answer:?}");
        }
        // Seen on screen on the third look: counted from then.
        let c = clock();
        let looks = Cell::new(0);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let asked = c.now();
        let shown = || {
            looks.set(looks.get() + 1);
            c.advance(10);
            if looks.get() == 3 {
                tx.send(MessageDialogResult::Custom(OPEN_LABEL.to_owned())).expect("send");
                true
            } else {
                false
            }
        };
        let reply = wait_reply(rx, asked, Duration::from_secs(5), Duration::from_millis(1), &c, &shown);
        assert_eq!(reply, Reply::Answered { open: true, shown: asked + Duration::from_millis(30) });
        // The dialog's thread gone with no answer: failed.
        let (tx, rx) = std::sync::mpsc::sync_channel::<MessageDialogResult>(1);
        drop(tx);
        assert_eq!(wait_reply(rx, Instant::now(), Duration::from_secs(5), Duration::from_millis(5), &SystemClock, &|| false), Reply::Failed);
    }

    #[test]
    fn a_failed_prompt_is_its_own_error_and_opens_nothing() {
        let c = clock();
        let gate = Gate::new();
        let b = FakeBrowser::default();
        let mut p = prompt(&c, true, 2000);
        p.failed = true;
        assert_eq!(open_link(RAW, &gate, &p, &b, &c), Err(LinkError::NoPrompt));
        assert!(b.opened.borrow().is_empty());
        assert!(!gate.showing());
        assert_eq!(LinkError::NoPrompt.code(), "no_prompt");
        // Not a member's answer: no quiet time after it.
        let next = prompt(&c, true, MIN_CONFIRM_MS);
        assert_eq!(open_link(RAW, &gate, &next, &b, &c), Ok(Outcome::Opened));
    }

    #[test]
    fn a_failed_open_says_so() {
        let c = clock();
        let p = prompt(&c, true, 2000);
        let b = FakeBrowser { fail: true, ..Default::default() };
        let gate = Gate::new();
        assert_eq!(open_link(RAW, &gate, &p, &b, &c), Err(LinkError::NotOpened));
        assert_eq!(LinkError::NotOpened.code(), "not_opened");
        assert_eq!(LinkError::Busy.code(), "busy");
        assert_eq!(LinkError::Refused(Refusal::NoHost).code(), "refused");
    }

    /// What the member does with a two-button dialog.
    #[derive(Debug, Clone, Copy)]
    enum Act {
        /// Presses the first or second button.
        Press(usize),
        /// Escape, or the dialog's close box.
        Dismiss,
    }

    /// The dialogs rfd 0.16.1 shows, by what they answer (read from its
    /// backends in the cargo registry).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Backend {
        /// win_cid/message_dialog.rs, `run`, either path: a custom button
        /// by its label (ID_CUSTOM_OK 1000, ID_CUSTOM_CANCEL 1001);
        /// Escape or close is IDCANCEL, `Cancel`.
        WindowsTaskDialog,
        /// macos/message_dialog.rs, `dialog_result`, either path: the
        /// first or second button by its label; Escape is the button
        /// titled "Cancel" (NSAlert gives it Escape), anything else
        /// `Cancel`.
        MacAlert,
        /// gtk3/message_dialog.rs, `run` (blocking): the first button is
        /// GTK_RESPONSE_OK and answers its label, the second
        /// GTK_RESPONSE_CANCEL and answers its label; a closed dialog
        /// (GTK_RESPONSE_DELETE_EVENT) or anything else, `Cancel`.
        GtkBlocking,
        /// gtk3/message_dialog.rs, `show_async`: GTK_RESPONSE_OK is `Ok`,
        /// GTK_RESPONSE_CANCEL and DELETE_EVENT are `Cancel`; never a
        /// label.
        GtkAsync,
    }

    fn rfd_answer(backend: Backend, buttons: &MessageButtons, act: Act) -> MessageDialogResult {
        let MessageButtons::OkCancelCustom(first, second) = buttons else {
            panic!("two custom buttons");
        };
        match (backend, act) {
            (Backend::GtkAsync, Act::Press(0)) => MessageDialogResult::Ok,
            (Backend::GtkAsync, _) => MessageDialogResult::Cancel,
            (_, Act::Press(0)) => MessageDialogResult::Custom(first.clone()),
            (_, Act::Press(_)) => MessageDialogResult::Custom(second.clone()),
            (Backend::MacAlert, Act::Dismiss) if first == CANCEL_LABEL => MessageDialogResult::Custom(first.clone()),
            (Backend::MacAlert, Act::Dismiss) if second == CANCEL_LABEL => MessageDialogResult::Custom(second.clone()),
            (_, Act::Dismiss) => MessageDialogResult::Cancel,
        }
    }

    /// The backend each platform's prompt runs on.
    fn backend_of(os: Os) -> Backend {
        match (os, path_for(os)) {
            (Os::Windows, _) => Backend::WindowsTaskDialog,
            (Os::MacOs, _) => Backend::MacAlert,
            (Os::Linux, DialogPath::Blocking) => Backend::GtkBlocking,
            (Os::Linux, DialogPath::Async) => Backend::GtkAsync,
        }
    }

    /// On every platform, as its rfd backend answers: the Open button
    /// opens, the other button and a dismissed dialog don't.
    #[test]
    fn only_the_open_button_confirms_on_each_platform() {
        for os in [Os::Windows, Os::MacOs, Os::Linux] {
            let backend = backend_of(os);
            let buttons = buttons_for(cancel_first_for(os));
            let MessageButtons::OkCancelCustom(first, second) = &buttons else {
                panic!("two custom buttons");
            };
            let open_at = if first == OPEN_LABEL { 0 } else { 1 };
            assert_eq!([first.as_str(), second.as_str()].iter().filter(|l| **l == OPEN_LABEL).count(), 1);
            assert_eq!([first.as_str(), second.as_str()].iter().filter(|l| **l == CANCEL_LABEL).count(), 1);
            assert!(confirmed(&rfd_answer(backend, &buttons, Act::Press(open_at))), "{os:?}: Open doesn't open");
            assert!(!confirmed(&rfd_answer(backend, &buttons, Act::Press(1 - open_at))), "{os:?}: Cancel opens");
            assert!(!confirmed(&rfd_answer(backend, &buttons, Act::Dismiss)), "{os:?}: dismissed opens");
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
    }

    /// Why Linux uses the blocking dialog: through rfd's async GTK dialog,
    /// Open could never open.
    #[test]
    fn gtks_async_dialog_never_answers_open() {
        let buttons = buttons_for(cancel_first_for(Os::Linux));
        for act in [Act::Press(0), Act::Press(1), Act::Dismiss] {
            assert!(!confirmed(&rfd_answer(Backend::GtkAsync, &buttons, act)), "{act:?}");
        }
        assert_eq!(path_for(Os::Linux), DialogPath::Blocking);
        assert_eq!(backend_of(Os::Linux), Backend::GtkBlocking);
    }

    /// Cancel is the first (default) button on Windows and macOS, not on
    /// Linux; and this build runs its own platform's choice.
    #[test]
    fn cancel_is_first_where_the_first_button_is_the_default() {
        let first = |os| match buttons_for(cancel_first_for(os)) {
            MessageButtons::OkCancelCustom(first, _) => first,
            _ => panic!("two custom buttons"),
        };
        assert_eq!(first(Os::Windows), CANCEL_LABEL);
        assert_eq!(first(Os::MacOs), CANCEL_LABEL);
        assert_eq!(first(Os::Linux), OPEN_LABEL);
        #[cfg(windows)]
        assert_eq!(OS, Os::Windows);
        #[cfg(target_os = "macos")]
        assert_eq!(OS, Os::MacOs);
        #[cfg(target_os = "linux")]
        assert_eq!(OS, Os::Linux);
        assert_eq!(path_for(Os::Windows), DialogPath::Async);
        assert_eq!(path_for(Os::MacOs), DialogPath::Async);
    }

    /// Through the prompt trait, over each platform's rfd answers.
    #[test]
    fn the_flow_on_each_platform() {
        struct Native<'a> {
            clock: &'a FakeClock,
            backend: Backend,
            buttons: MessageButtons,
            act: Act,
        }
        impl Prompt for Native<'_> {
            fn confirm(&self, _: &str, clock: &dyn Clock) -> Reply {
                let shown = clock.now();
                self.clock.advance(MIN_CONFIRM_MS + 100);
                Reply::Answered { open: confirmed(&rfd_answer(self.backend, &self.buttons, self.act)), shown }
            }
        }
        for os in [Os::Windows, Os::MacOs, Os::Linux] {
            let buttons = buttons_for(cancel_first_for(os));
            let open_at = match &buttons {
                MessageButtons::OkCancelCustom(first, _) if first == OPEN_LABEL => 0,
                _ => 1,
            };
            for (act, want) in [
                (Act::Press(open_at), Outcome::Opened),
                (Act::Press(1 - open_at), Outcome::NotConfirmed),
                (Act::Dismiss, Outcome::NotConfirmed),
            ] {
                let c = clock();
                let p = Native { clock: &c, backend: backend_of(os), buttons: buttons.clone(), act };
                let b = FakeBrowser::default();
                let gate = Gate::new();
                assert_eq!(open_link(RAW, &gate, &p, &b, &c), Ok(want), "{os:?} {act:?}");
                let opened = b.opened.borrow().clone();
                if want == Outcome::Opened {
                    assert_eq!(opened, vec![OPENS.to_owned()]);
                } else {
                    assert!(opened.is_empty());
                }
            }
        }
    }

    /// No task dialog of this process is on screen in a test.
    #[cfg(windows)]
    #[test]
    fn no_task_dialog_is_seen_when_there_is_none() {
        assert!(!dialog_shown());
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
