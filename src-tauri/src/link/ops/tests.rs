use super::*;
use crate::link::fake::FakeVault;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use vettid_device::pairing::SystemClock;

fn any(v: &serde_json::Value) -> Result<serde_json::Value, BadShape> {
    Ok(v.clone())
}

async fn live(dir: &std::path::Path) -> (FakeVault, Link<FakeVault, SystemClock>) {
    let (vault, mut link) = FakeVault::paired(dir);
    vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
    link.read_status().await.unwrap();
    assert!(link.snapshot(Utc::now()).active_at(Utc::now()));
    (vault, link)
}

fn sent(vault: &FakeVault, kind: &str) -> usize {
    vault.deposited().iter().filter(|k| *k == kind).count()
}

fn read(kind: &str) -> (String, serde_json::Value) {
    (kind.to_string(), serde_json::json!({}))
}

#[tokio::test]
async fn an_answer_is_its_body_checked() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer("connection.list", Ok(r#"{"connections":[{"id":"c-1"}]}"#));
    let (k, b) = read("connection.list");
    let v = link.op(&k, &b, any, false).await.unwrap();
    assert_eq!(v["connections"][0]["id"], "c-1");
    // The same answer through the real shape doesn't check out.
    assert_eq!(link.op(&k, &b, crate::link::shape::connection_list, false).await, Err(OpError::Malformed));
}

#[tokio::test]
async fn error_answers_are_said_plainly() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    for (code, want) in [
        ("forbidden", OpError::Vault("forbidden".into())),
        ("not_found", OpError::Vault("not_found".into())),
        ("bad_request", OpError::Vault("bad_request".into())),
    ] {
        vault.answer("connection.get", Err(code));
        assert_eq!(link.op("connection.get", &serde_json::json!({"connection_id": "c-1"}), any, false).await, Err(want.clone()), "{code}");
        assert!(link.snapshot(Utc::now()).active_at(Utc::now()), "{code} ends nothing");
    }
    assert_eq!(OpError::Vault("forbidden".into()).notice(), OP_FORBIDDEN_NOTICE);
    assert_eq!(OpError::BadArgument.code(), "bad_argument");
    assert_eq!(OpError::Unconfirmed.notice(), OP_UNCONFIRMED_NOTICE);
}

/// `session_required`: the screen isn't live after it, a status read is
/// asked for, the queue goes, and the next operation isn't sent.
#[tokio::test]
async fn session_required_ends_the_screens_session() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer("connection.list", Err("session_required"));
    let (k, b) = read("connection.list");
    assert_eq!(link.op(&k, &b, any, false).await, Err(OpError::NoSession));
    assert!(!link.snapshot(Utc::now()).active_at(Utc::now()));
    assert!(link.read_now);
    assert!(link.take_inbound().resync);
    let before = sent(&vault, "connection.list");
    assert_eq!(link.op(&k, &b, any, false).await, Err(OpError::NoSession));
    assert_eq!(sent(&vault, "connection.list"), before, "sent without a session");
}

/// No session, the vault known locked, a refused device, or a sleep just
/// found: nothing is sent.
#[tokio::test]
async fn nothing_is_sent_without_a_live_session() {
    let (k, b) = read("connection.list");
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = FakeVault::paired(dir.path());
    link.read_status().await.unwrap();
    assert_eq!(link.op(&k, &b, any, false).await, Err(OpError::NoSession));
    assert_eq!(sent(&vault, &k), 0);

    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.lock_vault(None);
    let _ = link.read_status().await; // a locked vault answers nothing; its notice is learned
    assert_eq!(link.op(&k, &b, any, false).await, Err(OpError::Locked));
    assert_eq!(sent(&vault, &k), 0);

    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    link.marks().due = Some(Utc::now() - TimeDelta::minutes(10));
    assert_ne!(link.op(&k, &b, any, false).await.err(), None);
    assert_eq!(sent(&vault, &k), 0, "sent across a sleep before the state was checked");

    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer(&k, Ok("{}"));
    vault.revoke(false);
    assert_eq!(link.op(&k, &b, any, false).await, Err(OpError::Refused));
    assert_eq!(link.op(&k, &b, any, false).await, Err(OpError::Refused), "and nothing after");
}

/// A hold answered to an operation is learned: a status read is asked
/// for, the queue goes, and the next operation isn't sent.
#[tokio::test]
async fn a_hold_is_learned_from_the_answer() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    let (k, b) = read("connection.list");
    vault.answer(&k, Ok("{}"));
    vault.hold(true, "");
    assert_eq!(link.op(&k, &b, any, false).await, Err(OpError::Held));
    assert!(link.read_now);
    assert!(link.take_inbound().resync);
    assert!(!link.snapshot(Utc::now()).active_at(Utc::now()));
    vault.hold(false, "");
    assert_eq!(link.op(&k, &b, any, false).await, Err(OpError::Held), "known held: not sent");
    assert_eq!(sent(&vault, &k), 1);
}

/// An unanswered change stays stored and goes with the next exchange:
/// unconfirmed, never "not done"; asked again, it is retried under the
/// same id, so the vault acts once.
#[tokio::test]
async fn an_unconfirmed_change_is_retried_under_its_id() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    let body = serde_json::json!({"pending_id": "p-1"});
    vault.answer("connection.decline", Ok("{}"));
    vault.offline(true);
    assert_eq!(link.op("connection.decline", &body, any, true).await, Err(OpError::Unconfirmed));
    let first = link.unconfirmed.as_ref().map(|p| p.id.clone()).expect("remembered");
    vault.offline(false);
    assert_eq!(link.op("connection.decline", &body, any, true).await, Ok(serde_json::json!({})));
    assert!(link.unconfirmed.is_none(), "confirmed: forgotten");
    // Both deposits carried the same inner id: the stored first, then the
    // retry of it, never a second decline.
    assert!(sent(&vault, "connection.decline") >= 1);
    assert_eq!(link.session.last_request_id(), Some(first.as_str()));
}

/// A read answered in the same exchange as a hold isn't handed on.
#[tokio::test]
async fn a_read_answered_with_a_hold_isnt_handed_on() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    let (k, b) = read("connection.list");
    vault.answer(&k, Ok(r#"{"connections":[]}"#));
    vault.event("vault.held", &crate::link::fake::owner_check("held", true, ""), Utc::now());
    let r = link.op(&k, &b, any, false).await;
    assert!(r.is_err(), "{r:?}");
}

/// A lock learned while the operation waited is said as the lock.
#[tokio::test]
async fn a_lock_during_the_wait_is_said_as_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.lock_vault(None); // the notice waits; nothing is answered after it
    let (k, b) = read("connection.list");
    assert_eq!(link.op(&k, &b, any, false).await, Err(OpError::Locked));
}

fn slot(link: Link<FakeVault, SystemClock>) -> Arc<Mutex<Option<Link<FakeVault, SystemClock>>>> {
    Arc::new(Mutex::new(Some(link)))
}

/// Two operations at once: both answered, each published.
#[tokio::test]
async fn two_operations_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await;
    vault.answer("connection.list", Ok("{}"));
    vault.answer("connection.request.list", Ok("{}"));
    let s = slot(link);
    let published = AtomicUsize::new(0);
    let go = |k: &'static str| link_op_with(&s, || true, || false, |_| { published.fetch_add(1, SeqCst); }, k, serde_json::json!({}), any, false);
    let (a, b) = tokio::join!(go("connection.list"), go("connection.request.list"));
    assert!(a.is_ok() && b.is_ok(), "{a:?} {b:?}");
    assert_eq!(published.load(SeqCst), 2);
}

/// The screen not live, or a reset under way: nothing sent.
#[tokio::test]
async fn link_op_checks_the_screen_and_resets() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await;
    vault.answer("connection.list", Ok("{}"));
    let s = slot(link);
    let r = link_op_with(&s, || false, || false, |_| panic!("published"), "connection.list", serde_json::json!({}), any, false).await;
    assert_eq!(r, Err(OpError::NoSession));
    let r = link_op_with(&s, || true, || true, |_| panic!("published"), "connection.list", serde_json::json!({}), any, false).await;
    assert_eq!(r, Err(OpError::NoSession));
    assert_eq!(sent(&vault, "connection.list"), 0);
}

/// A reset during the wait: a read's answer isn't handed on and nothing
/// is published; a change the vault confirmed is reported done.
#[tokio::test]
async fn a_reset_during_the_wait() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await;
    vault.answer("connection.list", Ok("{}"));
    vault.answer("connection.decline", Ok("{}"));
    let s = slot(link);
    // Not overtaken at the two checks before the send; overtaken after.
    for (kind, change, want) in [("connection.list", false, Err(OpError::NoSession)), ("connection.decline", true, Ok(serde_json::json!({})))] {
        let calls = AtomicUsize::new(0);
        let overtaken = || calls.fetch_add(1, SeqCst) >= 2;
        let r = link_op_with(&s, || true, overtaken, |_| panic!("published over a reset"), kind, serde_json::json!({}), any, change).await;
        assert_eq!(r, want, "{kind}");
    }
}

/// An operation stalled at an unreachable relay holds the link at most
/// OP_HOLD_MAX, so a log-out waiting for the link gets it in time.
#[tokio::test]
async fn a_stalled_operation_lets_go_of_the_link_in_time() {
    let dir = tempfile::tempdir().unwrap();
    let (_vault, link) = live(dir.path()).await; // no answer is scripted: it never comes
    let s = slot(link);
    let done = Arc::new(AtomicBool::new(false));
    let start = std::time::Instant::now();
    let r = link_op_with(&s, || true, || false, |_| {}, "connection.decline", serde_json::json!({"pending_id": "p"}), any, true).await;
    done.store(true, SeqCst);
    assert_eq!(r, Err(OpError::Unconfirmed));
    assert!(start.elapsed() <= OP_HOLD_MAX + std::time::Duration::from_secs(1), "held the link {:?}", start.elapsed());
    assert!(s.try_lock().is_ok(), "the link is free");
}
