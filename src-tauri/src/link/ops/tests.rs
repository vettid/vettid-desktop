use super::*;
use crate::link::fake::FakeVault;
use vettid_device::pairing::SystemClock;

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

#[tokio::test]
async fn an_answer_is_its_body() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer("connection.list", Ok(r#"{"connections":[{"id":"c-1","name":"Ann"}]}"#));
    let v = link.op("connection.list", &serde_json::json!({})).await.unwrap();
    assert_eq!(v["connections"][0]["id"], "c-1");
    assert_eq!(vault.asked(), vec![("connection.list".to_string(), "{}".to_string())]);
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
        assert_eq!(link.op("connection.get", &serde_json::json!({"connection_id": "c-1"})).await, Err(want.clone()), "{code}");
        assert!(link.snapshot(Utc::now()).active_at(Utc::now()), "{code} ends nothing");
    }
    assert_eq!(OpError::Vault("forbidden".into()).notice(), OP_FORBIDDEN_NOTICE);
    assert_eq!(OpError::Vault("not_found".into()).code(), "not_found");
    assert_eq!(OpError::Vault("bad_request".into()).notice(), OP_FAILED_NOTICE);
    assert_eq!(OpError::Unconfirmed.notice(), OP_UNCONFIRMED_NOTICE);
}

// A body that isn't a JSON object can't arrive: the envelope (vettid-vms)
// refuses to carry one. `op` checks anyway.

/// `session_required`: the screen isn't live after it, and the next
/// operation isn't sent until a status read says otherwise.
#[tokio::test]
async fn session_required_ends_the_screens_session() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer("connection.list", Err("session_required"));
    assert_eq!(link.op("connection.list", &serde_json::json!({})).await, Err(OpError::NoSession));
    assert!(!link.snapshot(Utc::now()).active_at(Utc::now()));
    let before = sent(&vault, "connection.list");
    assert_eq!(link.op("connection.list", &serde_json::json!({})).await, Err(OpError::NoSession));
    assert_eq!(sent(&vault, "connection.list"), before, "sent without a session");
}

/// No session, or the vault known locked: nothing is sent.
#[tokio::test]
async fn nothing_is_sent_without_a_live_session() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = FakeVault::paired(dir.path());
    link.read_status().await.unwrap();
    vault.answer("connection.list", Ok("{}"));
    assert_eq!(link.op("connection.list", &serde_json::json!({})).await, Err(OpError::NoSession));
    assert_eq!(sent(&vault, "connection.list"), 0);

    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.lock_vault(None);
    let _ = link.read_status().await; // a locked vault answers nothing; its notice is learned
    assert_eq!(link.op("connection.list", &serde_json::json!({})).await, Err(OpError::Locked));
    assert_eq!(sent(&vault, "connection.list"), 0);
}

/// A hold answered to an operation is learned: the session isn't live
/// after it, and the next operation isn't sent.
#[tokio::test]
async fn a_hold_is_learned_from_the_answer() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer("connection.list", Ok("{}"));
    vault.hold(true, "");
    assert_eq!(link.op("connection.list", &serde_json::json!({})).await, Err(OpError::Held));
    assert_eq!(sent(&vault, "connection.list"), 1);
    assert!(!link.snapshot(Utc::now()).active_at(Utc::now()));
    vault.hold(false, "");
    assert_eq!(link.op("connection.list", &serde_json::json!({})).await, Err(OpError::Held), "known held: not sent");
    assert_eq!(sent(&vault, "connection.list"), 1);
}

/// An unreachable relay: the request stays stored and goes with the next
/// exchange, so it is said to be unconfirmed (it may still happen), never
/// "not done".
#[tokio::test]
async fn an_unanswered_request_is_unconfirmed_and_may_still_happen() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer("connection.decline", Ok("{}"));
    vault.offline(true);
    let r = link.op("connection.decline", &serde_json::json!({"pending_id": "p-1"})).await;
    assert_eq!(r, Err(OpError::Unconfirmed));
    assert_eq!(sent(&vault, "connection.decline"), 0);
    vault.offline(false);
    link.read_status().await.unwrap();
    assert_eq!(sent(&vault, "connection.decline"), 1, "the stored request went later: \"may still happen\" is right");
}

/// A lock learned while the operation waited is said as the lock.
#[tokio::test]
async fn a_lock_during_the_wait_is_said_as_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.lock_vault(None); // the notice waits; nothing is answered after it
    assert_eq!(link.op("connection.list", &serde_json::json!({})).await, Err(OpError::Locked));
}
