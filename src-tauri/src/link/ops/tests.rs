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
        ("session_required", OpError::NoSession),
    ] {
        vault.answer("connection.get", Err(code));
        assert_eq!(link.op("connection.get", &serde_json::json!({"connection_id": "c-1"})).await, Err(want.clone()), "{code}");
    }
    assert_eq!(OpError::Vault("forbidden".into()).notice(), OP_FORBIDDEN_NOTICE);
    assert_eq!(OpError::Vault("not_found".into()).code(), "not_found");
    assert_eq!(OpError::Vault("bad_request".into()).notice(), OP_FAILED_NOTICE);
}

// A body that isn't a JSON object can't arrive: the envelope (vettid-vms)
// refuses to carry one. `op` checks anyway.

/// No session: nothing is sent.
#[tokio::test]
async fn no_session_sends_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = FakeVault::paired(dir.path());
    link.read_status().await.unwrap();
    vault.answer("connection.list", Ok("{}"));
    assert_eq!(link.op("connection.list", &serde_json::json!({})).await, Err(OpError::NoSession));
    assert!(vault.asked().is_empty());
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
    assert!(!link.snapshot(Utc::now()).active_at(Utc::now()));
    vault.hold(false, "");
    assert_eq!(link.op("connection.list", &serde_json::json!({})).await, Err(OpError::Held), "known held: not sent");
    assert!(vault.asked().is_empty());
}

/// An unreachable relay: said so, and never claimed done.
#[tokio::test]
async fn an_unreachable_relay() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.offline(true);
    assert_eq!(link.op("connection.list", &serde_json::json!({})).await, Err(OpError::Unreachable));
}
