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
//!   and so does one within `QUIET_MS` of a prompt that was cancelled,
//!   closed or not answered. A prompt with no answer after
//!   `PROMPT_TIMEOUT_SECS` counts as not confirmed.
//! - An "Open" sooner than `MIN_CONFIRM_MS` after the prompt was on screen
//!   counts as not confirmed (a held key's repeats).
//! - Cancel is the first button, so Return, Enter or Space cancels.
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
/// `#32770` window of this process that wasn't there when the prompt was
/// asked for) and counts from when it is first seen. Elsewhere, and on
/// Windows when the answer comes before the window is seen, it counts from
/// just before the dialog was asked for, so the time the dialog takes to
/// appear counts toward it.
///
/// On Linux it is 1000 ms: rfd's GTK dialog sets no default button and
/// gives no way to set one, and no "shown" signal is read there. Cancel is
/// first there too (`cancel_first_for`); this is the backstop.
#[cfg(not(target_os = "linux"))]
pub const MIN_CONFIRM_MS: u64 = 500;
#[cfg(target_os = "linux")]
pub const MIN_CONFIRM_MS: u64 = 1000;

/// After a prompt that was cancelled, closed or not answered, another call
/// answers busy for this long, so a script can't put the prompt straight
/// back up. Not after a too-fast Open: the view asks the member to click
/// the link again, and that click asks again at once.
pub const QUIET_MS: u64 = 1000;

/// A prompt with no answer after this long counts as not confirmed: the
/// one-prompt flag is let go, so links don't stay busy until a restart.
/// On Windows and Linux the prompt is closed then, and an Open pressed as
/// it closes is the error `timed_out` (the view says the link couldn't be
/// opened). On macOS rfd gives no way to close it: it stays on screen, and
/// an Open on it later opens nothing and sends `LATE_OPEN_EVENT`, so the
/// view says the same. So does one on Windows or Linux that didn't close.
pub const PROMPT_TIMEOUT_SECS: u64 = 300;

/// How long the wait goes on for the answer of a prompt it closed at the
/// time-out (Windows, Linux): an Open pressed as it closed arrives within it.
const CLOSE_GRACE: Duration = Duration::from_secs(2);

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
    /// An Open pressed as the timed-out prompt was being closed.
    LateOpen,
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
    /// Open pressed only after the prompt timed out: not opened.
    TimedOut,
}

impl LinkError {
    /// What the window gets.
    pub fn code(self) -> &'static str {
        match self {
            LinkError::Refused(_) => "refused",
            LinkError::Busy => "busy",
            LinkError::NoPrompt => "no_prompt",
            LinkError::NotOpened => "not_opened",
            LinkError::TimedOut => "timed_out",
        }
    }

    /// For the log.
    pub fn reason(self) -> &'static str {
        match self {
            LinkError::Refused(r) => r.as_str(),
            LinkError::Busy => "another link's prompt is shown, or was just declined",
            LinkError::NoPrompt => "the prompt couldn't be shown",
            LinkError::NotOpened => "the system didn't open it",
            LinkError::TimedOut => "Open came after the prompt timed out",
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
        // No quiet time either: the prompt's five minutes were the wait.
        Reply::LateOpen => Err(LinkError::TimedOut),
        Reply::TimedOut | Reply::Answered { open: false, .. } => {
            held.quiet_until = quiet;
            Ok(Outcome::NotConfirmed)
        }
        // No quiet time: the view asks for the link to be clicked again.
        Reply::Answered { open: true, shown }
            if answered.saturating_duration_since(shown) < Duration::from_millis(MIN_CONFIRM_MS) =>
        {
            Ok(Outcome::TooFast)
        }
        Reply::Answered { open: true, .. } => {
            browser.open(link.url()).map_err(|_| LinkError::NotOpened)?;
            Ok(Outcome::Opened)
        }
    }
}

/// How long `wait_reply` waits, and how often it looks.
#[derive(Debug, Clone, Copy)]
pub struct Waits {
    /// For the answer, from when the prompt was asked for.
    pub timeout: Duration,
    /// For the answer of a prompt closed at the time-out.
    pub grace: Duration,
    /// Between looks for the prompt on screen.
    pub poll: Duration,
}

/// The prompt's window, where it can be seen.
pub trait Screen {
    /// Whether the prompt is on screen now.
    fn seen(&self) -> bool;
    /// Closes the prompt (at the time-out); whether that was asked of it.
    fn close(&self) -> bool;
    /// Takes the answer of a prompt still up after the time-out (and the
    /// grace, where it was closed): an Open from it opens nothing, and
    /// the view is told it wasn't opened. Here: the answer is dropped.
    fn left_up(&self, rx: Receiver<MessageDialogResult>) {
        drop(rx);
    }
}

/// Where the prompt can't be seen or closed, and a late answer goes
/// nowhere (tests).
pub struct NoScreen;

impl Screen for NoScreen {
    fn seen(&self) -> bool {
        false
    }
    fn close(&self) -> bool {
        false
    }
}

/// Waits on `rx` for a prompt left up after its time-out, for as long as
/// it is up, and calls `told` once if its answer is Open. Nothing is
/// opened from here.
pub fn watch_late(rx: Receiver<MessageDialogResult>, told: impl FnOnce()) {
    if let Ok(answer) = rx.recv() {
        if confirmed(&answer) {
            told();
        }
    }
}

/// The event the view hears when Open was pressed on a prompt left up
/// after its time-out: nothing opened (it shows LINK_NOT_OPENED).
pub const LATE_OPEN_EVENT: &str = "message-link-late-open";

/// What takes the answer of a prompt left up after its time-out.
pub type Late =Box<dyn Fn(Receiver<MessageDialogResult>)>;

/// Watches a prompt left up after its time-out, on its own thread, and
/// calls `tell` if its answer is Open.
pub fn tell_late(tell: impl Fn() + Clone + Send + 'static) -> Late {
    Box::new(move |rx| {
        let tell = tell.clone();
        let spawned = std::thread::Builder::new().name("link-prompt-late".into()).spawn(move || watch_late(rx, tell));
        if spawned.is_err() {
            log::warn!("message link: a late answer can't be watched");
        }
    })
}

/// `tell_late`, telling `window` (LATE_OPEN_EVENT).
fn tell_window(window: WebviewWindow) -> Late {
    tell_late(move || {
        use tauri::Emitter;
        let _ = window.emit(LATE_OPEN_EVENT, ());
    })
}

/// The prompt on macOS (and any platform other than Windows and Linux):
/// not seen, not closed; a late Open is told.
#[cfg(not(any(windows, target_os = "linux")))]
struct UnseenScreen {
    late: Late,
}

#[cfg(not(any(windows, target_os = "linux")))]
impl Screen for UnseenScreen {
    fn seen(&self) -> bool {
        false
    }
    fn close(&self) -> bool {
        false
    }
    fn left_up(&self, rx: Receiver<MessageDialogResult>) {
        (self.late)(rx);
    }
}

/// Waits for the dialog's answer on `rx`: at most `waits.timeout` from
/// `asked`, looking every `waits.poll` for the prompt on `screen`. The time
/// it was first seen, or `asked` if it never was, goes with the answer.
///
/// At the time-out the prompt is closed if `screen` can, and its answer
/// waited for `waits.grace` more: an Open then is `LateOpen`. Otherwise it
/// is `TimedOut`, and `rx` goes to `screen.left_up`: a later Open opens
/// nothing either.
pub fn wait_reply(
    rx: Receiver<MessageDialogResult>,
    asked: Instant,
    waits: Waits,
    clock: &dyn Clock,
    screen: &dyn Screen,
) -> Reply {
    let mut seen: Option<Instant> = None;
    loop {
        if seen.is_none() && screen.seen() {
            seen = Some(clock.now());
        }
        let left = waits.timeout.saturating_sub(clock.now().saturating_duration_since(asked));
        if left.is_zero() {
            if screen.close() {
                match rx.recv_timeout(waits.grace) {
                    Ok(answer) if confirmed(&answer) => return Reply::LateOpen,
                    Ok(_) | Err(RecvTimeoutError::Disconnected) => return Reply::TimedOut,
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
            screen.left_up(rx);
            return Reply::TimedOut;
        }
        match rx.recv_timeout(left.min(waits.poll)) {
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

/// Whether Cancel goes first: on every platform. rfd's Windows task dialog
/// (`nDefaultButton` 0) and macOS alert make the first button the default
/// (Return or Enter); with rfd's blocking GTK dialog, Enter and Space
/// answer the first button too. Every backend answers a button by its
/// label, so only the Open button opens. In this order GTK's Open button
/// carries GTK_RESPONSE_CANCEL; a dismissed GTK dialog answers
/// GTK_RESPONSE_DELETE_EVENT, which rfd's blocking dialog answers as
/// `Cancel`.
pub fn cancel_first_for(os: Os) -> bool {
    match os {
        Os::Windows | Os::MacOs | Os::Linux => true,
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

/// The first dialog window in `now` that wasn't in `before`: the prompt,
/// not a dialog left from an earlier one.
pub fn new_dialog(before: &[isize], now: &[isize]) -> Option<isize> {
    now.iter().copied().find(|h| !before.contains(h))
}

/// The prompt's task dialog on Windows: the dialog windows there before it
/// was asked for are noted, and only a new one counts.
#[cfg(windows)]
struct TaskDialogWatch {
    before: Vec<isize>,
    found: std::cell::Cell<Option<isize>>,
    late: Late,
}

#[cfg(windows)]
impl TaskDialogWatch {
    /// Notes the dialog windows on screen now: call before asking.
    fn new(late: Late) -> Self {
        TaskDialogWatch { before: win::dialogs(), found: std::cell::Cell::new(None), late }
    }
}

#[cfg(windows)]
impl Screen for TaskDialogWatch {
    fn seen(&self) -> bool {
        if self.found.get().is_none() {
            self.found.set(new_dialog(&self.before, &win::dialogs()));
        }
        self.found.get().is_some()
    }

    fn close(&self) -> bool {
        self.found.get().is_some_and(win::close)
    }

    fn left_up(&self, rx: Receiver<MessageDialogResult>) {
        (self.late)(rx);
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowThreadProcessId, IsWindowVisible, PostMessageW,
        WM_CLOSE,
    };

    /// The dialog class a task dialog's window has.
    const DIALOG_CLASS: [u16; 6] = [b'#' as u16, b'3' as u16, b'2' as u16, b'7' as u16, b'7' as u16, b'0' as u16];

    /// The visible top-level windows of this process of class `#32770`
    /// (dialogs), as handles. No owner is checked: the app makes no dialog
    /// other than the link's prompt, and only a new one counts.
    pub fn dialogs() -> Vec<isize> {
        let mut found: Vec<isize> = Vec::new();
        // SAFETY: `each` only pushes through the pointer to `found`, which
        // outlives the call; EnumWindows calls it on this thread.
        unsafe { EnumWindows(Some(each), &mut found as *mut Vec<isize> as LPARAM) };
        found
    }

    /// Asks the dialog to close (WM_CLOSE): rfd's task dialog then answers
    /// `Cancel`.
    pub fn close(hwnd: isize) -> bool {
        // SAFETY: posting a message to a window handle is safe whatever the
        // handle; a stale one fails.
        unsafe { PostMessageW(hwnd as HWND, WM_CLOSE, 0, 0) != 0 }
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
            (*(data as *mut Vec<isize>)).push(hwnd as isize);
        }
        1
    }
}

/// The prompt on Linux: rfd's blocking GTK dialog. It isn't seen (the wait
/// counts from the request), but it is closed at the time-out; a late Open
/// on one that didn't close is told.
#[cfg(target_os = "linux")]
struct GtkPromptWatch {
    /// The prompt's window title: the app's name.
    title: String,
    late: Late,
}

#[cfg(target_os = "linux")]
impl Screen for GtkPromptWatch {
    fn seen(&self) -> bool {
        false
    }

    fn close(&self) -> bool {
        gtk_prompts::close(&self.title)
    }

    fn left_up(&self, rx: Receiver<MessageDialogResult>) {
        (self.late)(rx);
    }
}

#[cfg(target_os = "linux")]
mod gtk_prompts {
    use gtk::glib;
    use gtk::prelude::*;
    use std::time::{Duration, Instant};

    /// How long the close waits for GTK's main thread to take it.
    const TAKEN: Duration = Duration::from_secs(1);

    /// Closes every link prompt on screen: each GTK message dialog with
    /// the prompt's title. The app makes no other. Only one prompt is asked
    /// at a time, so at its time-out any other one is an earlier prompt
    /// that has timed out too, and its answer opens nothing. Each is given
    /// the response GTK_RESPONSE_DELETE_EVENT, as its close box gives,
    /// which rfd's blocking dialog answers as `Cancel`. That response is
    /// given directly: a close request (`gtk_window_close`) to a dialog
    /// under another one's grab is dropped. Whether one was closed; not if
    /// GTK's main thread didn't take this within `TAKEN`, and then it
    /// closes nothing later either (a new prompt may be up by then).
    pub fn close(title: &str) -> bool {
        let title = title.to_owned();
        let deadline = Instant::now() + TAKEN;
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        // rfd makes the dialog in an idle callback on GTK's default main
        // context, and runs it in a nested loop that holds that context:
        // this runs on the same thread, inside that loop. Where rfd's own
        // GTK thread ran the dialog instead, GTK isn't set up for gtk-rs
        // there: nothing is closed, and the prompt goes to the late watch.
        glib::MainContext::default().invoke(move || {
            if Instant::now() < deadline {
                let _ = tx.send(close_titled(&title));
            }
        });
        matches!(rx.recv_timeout(TAKEN), Ok(n) if n > 0)
    }

    /// On GTK's main thread: closes the message dialogs titled `title`,
    /// and says how many. None where GTK isn't set up on this thread.
    fn close_titled(title: &str) -> usize {
        if !gtk::is_initialized_main_thread() {
            return 0;
        }
        let mut closed = 0;
        for w in gtk::Window::list_toplevels() {
            let Ok(dialog) = w.downcast::<gtk::MessageDialog>() else { continue };
            if dialog.is_visible() && dialog.title().as_deref() == Some(title) {
                dialog.response(gtk::ResponseType::DeleteEvent);
                closed += 1;
            }
        }
        closed
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
        // Before asking: the dialogs already on screen don't count.
        let late = tell_window(self.window.clone());
        #[cfg(windows)]
        let screen = TaskDialogWatch::new(late);
        #[cfg(not(any(windows, target_os = "linux")))]
        let screen = UnseenScreen { late };
        #[cfg(target_os = "linux")]
        let screen = GtkPromptWatch { title: title.clone(), late };
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
            // rfd's GTK dialog ignores `set_parent`: it is made with no
            // parent window.
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
        let waits = Waits {
            timeout: Duration::from_secs(PROMPT_TIMEOUT_SECS),
            grace: CLOSE_GRACE,
            poll: SHOWN_POLL,
        };
        wait_reply(rx, asked, waits, clock, &screen)
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
/// `no_prompt`, `not_opened` or `timed_out`.
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
        // Cancelled or closed (after 2 s), or no answer in time.
        for (yes, timed_out, after, first) in [
            (false, false, 2000, Outcome::NotConfirmed),
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

    /// After a too-fast Open the view asks for the link to be clicked
    /// again: that click asks again at once, not busy.
    #[test]
    fn a_too_fast_open_leaves_no_quiet_time() {
        let c = clock();
        let gate = Gate::new();
        let b = FakeBrowser::default();
        let p = prompt(&c, true, 0);
        assert_eq!(open_link(RAW, &gate, &p, &b, &c), Ok(Outcome::TooFast));
        let again = prompt(&c, true, MIN_CONFIRM_MS);
        assert_eq!(open_link(RAW, &gate, &again, &b, &c), Ok(Outcome::Opened));
        assert_eq!(again.asked.borrow().len(), 1);
        assert_eq!(*b.opened.borrow(), vec![OPENS.to_owned()]);
    }

    #[test]
    fn an_open_after_the_time_out_is_an_error_and_opens_nothing() {
        struct Late;
        impl Prompt for Late {
            fn confirm(&self, _: &str, _: &dyn Clock) -> Reply {
                Reply::LateOpen
            }
        }
        let c = clock();
        let gate = Gate::new();
        let b = FakeBrowser::default();
        assert_eq!(open_link(RAW, &gate, &Late, &b, &c), Err(LinkError::TimedOut));
        assert_eq!(LinkError::TimedOut.code(), "timed_out");
        assert!(b.opened.borrow().is_empty());
        assert!(!gate.showing());
        // No quiet time after it: the next click prompts at once.
        let again = prompt(&c, true, MIN_CONFIRM_MS);
        assert_eq!(open_link(RAW, &gate, &again, &b, &c), Ok(Outcome::Opened));
        assert_eq!(again.asked.borrow().len(), 1);
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

    fn waits(timeout_ms: u64, poll_ms: u64) -> Waits {
        Waits {
            timeout: Duration::from_millis(timeout_ms),
            grace: Duration::from_millis(200),
            poll: Duration::from_millis(poll_ms),
        }
    }

    /// A screen from closures: `seen` is asked at each look, `close` at
    /// the time-out.
    struct FnScreen<'a> {
        seen: &'a dyn Fn() -> bool,
        close: &'a dyn Fn() -> bool,
    }

    impl Screen for FnScreen<'_> {
        fn seen(&self) -> bool {
            (self.seen)()
        }
        fn close(&self) -> bool {
            (self.close)()
        }
    }

    /// The wait itself: no answer within the time-out is `TimedOut` where
    /// the prompt can't be closed, and the answer coming later goes nowhere.
    #[test]
    fn the_wait_times_out_and_ignores_a_late_answer() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let asked = Instant::now();
        let reply = wait_reply(rx, asked, waits(60, 5), &SystemClock, &NoScreen);
        assert_eq!(reply, Reply::TimedOut);
        assert!(asked.elapsed() >= Duration::from_millis(60));
        // The receiver is gone with the reply: a late Open is refused.
        assert!(tx.send(MessageDialogResult::Custom(OPEN_LABEL.to_owned())).is_err());
    }

    /// Where the prompt can be closed (Windows): closed at the time-out;
    /// an Open pressed as it closes is `LateOpen`, its Cancel `TimedOut`.
    #[test]
    fn the_wait_closes_the_prompt_at_the_time_out() {
        for (answer, want) in [
            (Some(MessageDialogResult::Custom(OPEN_LABEL.to_owned())), Reply::LateOpen),
            (Some(MessageDialogResult::Cancel), Reply::TimedOut),
            (Some(MessageDialogResult::Custom(CANCEL_LABEL.to_owned())), Reply::TimedOut),
            (None, Reply::TimedOut),
        ] {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let closed = Cell::new(0);
            let close = || {
                closed.set(closed.get() + 1);
                if let Some(a) = answer.clone() {
                    tx.send(a).expect("send");
                }
                true
            };
            let screen = FnScreen { seen: &|| true, close: &close };
            let reply = wait_reply(rx, Instant::now(), waits(40, 5), &SystemClock, &screen);
            assert_eq!(reply, want, "{answer:?}");
            assert_eq!(closed.get(), 1, "{answer:?}");
        }
        // Not closed (it can't be): an answer already waiting isn't read.
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let close = || {
            tx.send(MessageDialogResult::Custom(OPEN_LABEL.to_owned())).expect("send");
            false
        };
        let screen = FnScreen { seen: &|| false, close: &close };
        assert_eq!(wait_reply(rx, Instant::now(), waits(40, 5), &SystemClock, &screen), Reply::TimedOut);
    }

    /// A screen that keeps what `left_up` is handed.
    struct Keeps<'a> {
        close: bool,
        kept: &'a RefCell<Option<Receiver<MessageDialogResult>>>,
    }

    impl Screen for Keeps<'_> {
        fn seen(&self) -> bool {
            true
        }
        fn close(&self) -> bool {
            self.close
        }
        fn left_up(&self, rx: Receiver<MessageDialogResult>) {
            *self.kept.borrow_mut() = Some(rx);
        }
    }

    /// A prompt still up after the time-out (not closable, or closed with
    /// no answer in the grace) hands its answer to `left_up`; one that
    /// answered in the grace doesn't.
    #[test]
    fn a_prompt_left_up_hands_its_answer_on() {
        for close in [false, true] {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let kept = RefCell::new(None);
            let reply = wait_reply(rx, Instant::now(), waits(40, 5), &SystemClock, &Keeps { close, kept: &kept });
            assert_eq!(reply, Reply::TimedOut, "close {close}");
            let rx = kept.borrow_mut().take().expect("handed on");
            tx.send(MessageDialogResult::Custom(OPEN_LABEL.to_owned())).expect("still heard");
            assert!(confirmed(&rx.recv().expect("answer")));
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        tx.send(MessageDialogResult::Cancel).expect("send");
        let kept = RefCell::new(None);
        // Closed, and its Cancel came in the grace: not handed on.
        let reply = wait_reply(rx, Instant::now(), waits(0, 5), &SystemClock, &Keeps { close: true, kept: &kept });
        assert_eq!(reply, Reply::TimedOut);
        assert!(kept.borrow().is_none());
    }

    /// Closed, and the dialog's sender gone in the grace (its thread
    /// ended): timed out, and nothing handed on.
    #[test]
    fn a_prompt_gone_in_the_grace_is_not_handed_on() {
        struct DropsOnClose<'a> {
            tx: &'a RefCell<Option<std::sync::mpsc::SyncSender<MessageDialogResult>>>,
            kept: &'a RefCell<Option<Receiver<MessageDialogResult>>>,
        }
        impl Screen for DropsOnClose<'_> {
            fn seen(&self) -> bool {
                true
            }
            fn close(&self) -> bool {
                drop(self.tx.borrow_mut().take());
                true
            }
            fn left_up(&self, rx: Receiver<MessageDialogResult>) {
                *self.kept.borrow_mut() = Some(rx);
            }
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let tx = RefCell::new(Some(tx));
        let kept = RefCell::new(None);
        let started = Instant::now();
        let mut w = waits(20, 5);
        w.grace = Duration::from_secs(5);
        let reply = wait_reply(rx, started, w, &SystemClock, &DropsOnClose { tx: &tx, kept: &kept });
        assert_eq!(reply, Reply::TimedOut);
        assert!(kept.borrow().is_none(), "handed on");
        assert!(tx.borrow().is_none(), "not closed");
        // Gone at once, not after the whole grace.
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    /// The hand-off that tells the window: told from its own thread for an
    /// Open, and not for anything else.
    #[test]
    fn tell_late_tells_only_for_an_open() {
        let (told_tx, told_rx) = std::sync::mpsc::channel::<()>();
        let late = tell_late(move || told_tx.send(()).expect("told"));
        for (answer, told) in [
            (Some(MessageDialogResult::Custom(OPEN_LABEL.to_owned())), true),
            (Some(MessageDialogResult::Custom(CANCEL_LABEL.to_owned())), false),
            (Some(MessageDialogResult::Cancel), false),
            (None, false),
        ] {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            // Handed on before the answer: the watch waits for it.
            late(rx);
            match answer.clone() {
                Some(a) => tx.send(a).expect("send"),
                None => drop(tx),
            }
            let heard = told_rx.recv_timeout(Duration::from_millis(if told { 5000 } else { 300 }));
            assert_eq!(heard.is_ok(), told, "{answer:?}");
        }
    }

    /// A `Late` that keeps what it is handed.
    fn keeping(kept: &std::rc::Rc<RefCell<Option<Receiver<MessageDialogResult>>>>) -> Late {
        let kept = kept.clone();
        Box::new(move |rx| *kept.borrow_mut() = Some(rx))
    }

    /// The platform's screen hands a prompt left up to its `Late`.
    #[test]
    fn the_platform_screen_hands_a_prompt_left_up_to_its_late() {
        let kept = std::rc::Rc::new(RefCell::new(None));
        #[cfg(windows)]
        let screen = TaskDialogWatch::new(keeping(&kept));
        #[cfg(not(any(windows, target_os = "linux")))]
        let screen = UnseenScreen { late: keeping(&kept) };
        #[cfg(target_os = "linux")]
        let screen = GtkPromptWatch { title: "VettID".to_owned(), late: keeping(&kept) };
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        screen.left_up(rx);
        let rx = kept.borrow_mut().take().expect("handed to its Late");
        tx.send(MessageDialogResult::Cancel).expect("still heard");
        assert!(matches!(rx.recv(), Ok(MessageDialogResult::Cancel)));
    }

    /// The watch on a prompt left up: told only for Open, and only once.
    #[test]
    fn a_late_open_is_told_and_nothing_else_is() {
        for (answer, told) in [
            (Some(MessageDialogResult::Custom(OPEN_LABEL.to_owned())), 1),
            (Some(MessageDialogResult::Custom(CANCEL_LABEL.to_owned())), 0),
            (Some(MessageDialogResult::Cancel), 0),
            (Some(MessageDialogResult::Ok), 0),
            (None, 0),
        ] {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            match answer.clone() {
                Some(a) => tx.send(a).expect("send"),
                None => drop(tx),
            }
            let n = Cell::new(0);
            watch_late(rx, || n.set(n.get() + 1));
            assert_eq!(n.get(), told, "{answer:?}");
        }
        assert_eq!(LATE_OPEN_EVENT, "message-link-late-open");
    }

    /// Only a dialog window that wasn't there before the prompt was asked
    /// for counts as the prompt.
    #[test]
    fn only_a_new_dialog_window_is_the_prompt() {
        assert_eq!(new_dialog(&[], &[]), None);
        assert_eq!(new_dialog(&[], &[7]), Some(7));
        assert_eq!(new_dialog(&[7], &[7]), None, "a stale dialog counted");
        assert_eq!(new_dialog(&[7], &[7, 9]), Some(9));
        assert_eq!(new_dialog(&[7, 9], &[9, 11, 7]), Some(11));
        assert_eq!(new_dialog(&[7], &[]), None);
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
            let reply = wait_reply(rx, asked, waits(5000, 5), &SystemClock, &NoScreen);
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
        let screen = FnScreen { seen: &shown, close: &|| false };
        let reply = wait_reply(rx, asked, waits(5000, 1), &c, &screen);
        assert_eq!(reply, Reply::Answered { open: true, shown: asked + Duration::from_millis(30) });
        // The dialog's thread gone with no answer: failed.
        let (tx, rx) = std::sync::mpsc::sync_channel::<MessageDialogResult>(1);
        drop(tx);
        assert_eq!(wait_reply(rx, Instant::now(), waits(5000, 5), &SystemClock, &NoScreen), Reply::Failed);
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

    /// Cancel is the first (default) button on every platform; and this
    /// build runs its own platform's choice.
    #[test]
    fn cancel_is_first_where_the_first_button_is_the_default() {
        let first = |os| match buttons_for(cancel_first_for(os)) {
            MessageButtons::OkCancelCustom(first, _) => first,
            _ => panic!("two custom buttons"),
        };
        assert_eq!(first(Os::Windows), CANCEL_LABEL);
        assert_eq!(first(Os::MacOs), CANCEL_LABEL);
        assert_eq!(first(Os::Linux), CANCEL_LABEL);
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

    /// No dialog of this process is on screen in a test, so none is seen
    /// and none can be closed.
    #[cfg(windows)]
    #[test]
    fn no_task_dialog_is_seen_when_there_is_none() {
        assert!(win::dialogs().is_empty());
        let watch = TaskDialogWatch::new(Box::new(drop));
        assert!(!watch.seen());
        assert!(!watch.close());
    }

    /// GTK isn't set up in a test, so no prompt is closed, and nothing
    /// panics: the time-out goes on to the late watch.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_gtk_prompt_is_closed_where_gtk_is_not_set_up() {
        let watch = GtkPromptWatch { title: "VettID".to_owned(), late: Box::new(drop) };
        assert!(!watch.seen());
        assert!(!watch.close());
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
