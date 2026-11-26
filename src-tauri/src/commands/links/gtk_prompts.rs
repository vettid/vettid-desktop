//! Closing a link's prompt on Linux at its time-out (links.rs,
//! `GtkPromptWatch`).

use gtk::glib;
use gtk::prelude::*;
use std::time::{Duration, Instant};

/// How long the close waits for GTK's main thread to take it.
const TAKEN: Duration = Duration::from_secs(1);

/// The response a closed prompt is given: GTK_RESPONSE_DELETE_EVENT, the
/// one its close box gives. rfd's blocking dialog answers it as `Cancel`.
/// Not GTK_RESPONSE_OK or GTK_RESPONSE_CANCEL: rfd gives those to the two
/// buttons, and with Cancel first, the Open button carries
/// GTK_RESPONSE_CANCEL, so that one would answer "Open".
pub const CLOSE_RESPONSE: gtk::ResponseType = gtk::ResponseType::DeleteEvent;

/// Closes every link prompt on screen: each visible GTK message dialog
/// with the prompt's title. The app makes no other message dialog (a test
/// keeps other dialog makers out). Only one prompt is asked at a time, so at
/// its time-out any other one is an earlier prompt that has timed out too,
/// and its answer opens nothing.
///
/// Each is given `CLOSE_RESPONSE` directly: a close request
/// (`gtk_window_close`) to a dialog under another one's grab is dropped.
/// An Open clicked in the same GTK pass, just before the close, is answered
/// after the time-out, so it is `timed_out` and opens nothing; the member
/// clicks the link again.
///
/// Whether one was closed. Not if GTK's main thread didn't take this
/// within `TAKEN`, and then it closes nothing later either (a new prompt
/// may be up by then).
pub fn close(title: &str) -> bool {
    let title = title.to_owned();
    let deadline = Instant::now() + TAKEN;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    // GTK's default main context is held by the thread that set GTK up:
    // gtk-rs's `gtk::init` (tao's, on the main thread) acquires it and
    // never lets it go. rfd makes the dialog in an idle callback on that
    // context, so on that thread, and runs it in a nested loop there; this
    // runs on the same thread, inside that loop. Where nobody holds the
    // context (GTK isn't set up, as in a unit test), it runs here instead,
    // and the guard in `close_titled` closes nothing: the prompt goes to
    // the late watch.
    glib::MainContext::default().invoke(move || {
        if Instant::now() < deadline {
            let _ = tx.send(close_titled(&title));
        }
    });
    matches!(rx.recv_timeout(TAKEN), Ok(n) if n > 0)
}

/// On GTK's main thread: closes the message dialogs titled `title`, and
/// says how many. None where GTK isn't set up on this thread.
fn close_titled(title: &str) -> usize {
    if !gtk::is_initialized_main_thread() {
        return 0;
    }
    let mut closed = 0;
    for w in gtk::Window::list_toplevels() {
        let Ok(dialog) = w.downcast::<gtk::MessageDialog>() else { continue };
        if dialog.is_visible() && dialog.title().as_deref() == Some(title) {
            dialog.response(CLOSE_RESPONSE);
            closed += 1;
        }
    }
    closed
}

#[cfg(test)]
mod tests {
    use super::*;
    use rfd::{MessageButtons, MessageDialog, MessageDialogResult};
    use std::sync::mpsc;

    /// Not the buttons' responses: those would answer as a button.
    #[test]
    fn a_closed_prompt_is_answered_as_its_close_box() {
        assert_eq!(CLOSE_RESPONSE, gtk::ResponseType::DeleteEvent);
        assert_ne!(CLOSE_RESPONSE, gtk::ResponseType::Ok);
        assert_ne!(CLOSE_RESPONSE, gtk::ResponseType::Cancel);
    }

    /// GTK isn't set up in a unit test: nothing is closed, and nothing
    /// panics (no GTK call is made off its thread). Not run in the same
    /// process as the real-dialog test below, which sets GTK up.
    #[test]
    fn nothing_is_closed_where_gtk_is_not_set_up() {
        assert!(!close(TITLE));
    }

    const TITLE: &str = "VettID";

    type Answer = MessageDialogResult;

    /// A link prompt as links.rs asks it: rfd's blocking dialog, Cancel
    /// first, on a thread of its own.
    fn ask(title: &'static str, tx: mpsc::Sender<Answer>) {
        std::thread::spawn(move || {
            let a = MessageDialog::new()
                .set_title(title)
                .set_description("Open this link in your browser? It goes to example.com.")
                .set_buttons(MessageButtons::OkCancelCustom("Cancel".into(), "Open".into()))
                .show();
            let _ = tx.send(a);
        });
    }

    /// Runs `f` on GTK's main thread (which holds the default context
    /// since `gtk::init`) and waits for it.
    fn on_main<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::sync_channel(1);
        glib::MainContext::default().invoke(move || {
            assert!(gtk::is_initialized_main_thread(), "run off GTK's main thread");
            let _ = tx.send(f());
        });
        rx.recv_timeout(Duration::from_secs(5)).expect("GTK's main thread")
    }

    /// The visible message dialogs titled `TITLE`, and whether a grab is on.
    fn state() -> (usize, bool) {
        on_main(|| {
            let n = gtk::Window::list_toplevels()
                .into_iter()
                .filter_map(|w| w.downcast::<gtk::MessageDialog>().ok())
                .filter(|d| d.is_visible() && d.title().as_deref() == Some(TITLE))
                .count();
            (n, gtk::grab_get_current().is_some())
        })
    }

    fn wait_for(n: usize) {
        let until = Instant::now() + Duration::from_secs(5);
        while state().0 != n {
            assert!(Instant::now() < until, "{n} prompts never up");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn cancels(rx: &mpsc::Receiver<Answer>, n: usize) {
        for _ in 0..n {
            let a = rx.recv_timeout(Duration::from_secs(2)).expect("an answer within the grace");
            assert_eq!(a, MessageDialogResult::Cancel);
        }
    }

    /// The checks, from a thread of their own while GTK runs on the
    /// test's thread.
    fn checks() {
        // Nothing up: nothing closed.
        assert!(!close(TITLE));

        // One prompt, with its grab: it answers Cancel and goes, and the
        // grab with it.
        let (tx, rx) = mpsc::channel();
        ask(TITLE, tx.clone());
        wait_for(1);
        assert!(state().1, "the prompt's grab is on");
        assert!(close(TITLE));
        cancels(&rx, 1);
        wait_for(0);
        assert!(!state().1, "no grab left");

        // Two prompts (an earlier one left up, and the current one): both.
        ask(TITLE, tx.clone());
        wait_for(1);
        ask(TITLE, tx.clone());
        wait_for(2);
        assert!(close(TITLE));
        cancels(&rx, 2);
        wait_for(0);
        assert!(!state().1, "no grab left");

        // Left alone: a window with the same title, a hidden message
        // dialog with it, and a message dialog with another title.
        on_main(|| {
            let w = gtk::Window::new(gtk::WindowType::Toplevel);
            w.set_title(TITLE);
            w.show_all();
            let hidden = gtk::MessageDialog::new(
                None::<&gtk::Window>,
                gtk::DialogFlags::empty(),
                gtk::MessageType::Info,
                gtk::ButtonsType::Ok,
                "hidden",
            );
            hidden.set_title(TITLE);
            let other = gtk::MessageDialog::new(
                None::<&gtk::Window>,
                gtk::DialogFlags::empty(),
                gtk::MessageType::Info,
                gtk::ButtonsType::Ok,
                "other",
            );
            other.set_title("Another");
            other.show_all();
            for d in [&hidden, &other] {
                d.connect_response(|_, _| RESPONDED.with(|r| r.set(r.get() + 1)));
            }
            OTHERS.with(|o| o.borrow_mut().extend([w, hidden.upcast(), other.upcast()]));
        });
        assert!(!close(TITLE), "nothing of the others closed");
        assert_eq!(on_main(|| RESPONDED.with(|r| r.get())), 0, "the others were given no response");
        assert!(on_main(|| OTHERS.with(|o| o.borrow()[0].is_visible())), "the same-titled window is still up");
        on_main(|| OTHERS.with(|o| o.borrow_mut().drain(..).for_each(|w| w.close())));

        // A busy main thread: the close gives up after TAKEN, and closes
        // nothing once the thread is free again.
        ask(TITLE, tx.clone());
        wait_for(1);
        glib::MainContext::default().invoke(|| std::thread::sleep(TAKEN + Duration::from_millis(500)));
        let t = Instant::now();
        assert!(!close(TITLE), "a close not taken in time");
        assert!(t.elapsed() < TAKEN + Duration::from_millis(300));
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(state().0, 1, "the late close closed nothing");
        assert!(rx.try_recv().is_err(), "no answer from it");
        assert!(close(TITLE));
        cancels(&rx, 1);
        wait_for(0);
    }

    thread_local! {
        /// On GTK's main thread: the windows the prompt's close must leave
        /// alone, and how many responses they were given.
        static OTHERS: std::cell::RefCell<Vec<gtk::Window>> = const { std::cell::RefCell::new(Vec::new()) };
        static RESPONDED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// On rfd 0.16.1's real blocking GTK dialog, with GTK's loop run one
    /// iteration at a time on this thread, as tao runs it. It needs a
    /// display; headless, under broadway:
    ///
    /// ```text
    /// broadwayd :7 &
    /// GDK_BACKEND=broadway BROADWAY_DISPLAY=:7 cargo test \
    ///   --manifest-path src-tauri/Cargo.toml -p vettid-desktop --lib \
    ///   -- --ignored --exact commands::links::gtk_prompts::tests::the_prompts_close_on_a_real_dialog
    /// ```
    #[test]
    #[ignore = "needs a GTK display (broadway); see the comment"]
    fn the_prompts_close_on_a_real_dialog() {
        gtk::init().expect("a GTK display");
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d = done.clone();
        let checker = std::thread::spawn(move || {
            let r = std::panic::catch_unwind(checks);
            d.store(true, std::sync::atomic::Ordering::SeqCst);
            glib::MainContext::default().wakeup();
            r
        });
        while !done.load(std::sync::atomic::Ordering::SeqCst) {
            gtk::main_iteration_do(true);
        }
        if let Err(e) = checker.join().expect("checker") {
            std::panic::resume_unwind(e);
        }
    }
}
