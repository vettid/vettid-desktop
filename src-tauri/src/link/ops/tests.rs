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
    // Through the real shape, the entry doesn't check out and is left out.
    let v = link.op(&k, &b, crate::link::shape::connection_list, false).await.unwrap();
    assert_eq!((v["connections"].as_array().unwrap().len(), v["unreadable"].as_u64()), (0, Some(1)));
    // A top level that doesn't check out fails the answer.
    vault.answer(&k, Ok(r#"{"connections":"x"}"#));
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
    let body = serde_json::json!({"n": "p-1"});
    vault.answer("test.change", Ok("{}"));
    vault.offline(true);
    assert_eq!(link.op("test.change", &body, any, true).await, Err(OpError::Unconfirmed));
    let first = link.unconfirmed.as_ref().map(|p| p.id.clone()).expect("remembered");
    vault.offline(false);
    assert_eq!(link.op("test.change", &body, any, true).await, Ok(serde_json::json!({})));
    assert!(link.unconfirmed.is_none(), "confirmed: forgotten");
    // Both deposits carried the same inner id: the stored first, then the
    // retry of it, never a second change.
    assert!(sent(&vault, "test.change") >= 1);
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
    let go = |k: &'static str| link_op_with(&s, || true, || false, |_| { published.fetch_add(1, SeqCst); }, std::future::pending(), k, serde_json::json!({}), any, false);
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
    let r = link_op_with(&s, || false, || false, |_| panic!("published"), std::future::pending(), "connection.list", serde_json::json!({}), any, false).await;
    assert_eq!(r, Err(OpError::NoSession));
    let r = link_op_with(&s, || true, || true, |_| panic!("published"), std::future::pending(), "connection.list", serde_json::json!({}), any, false).await;
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
    vault.answer("test.change", Ok("{}"));
    let s = slot(link);
    // Not overtaken at the two checks before the send; overtaken after.
    for (kind, change, want) in [("connection.list", false, Err(OpError::NoSession)), ("test.change", true, Ok(serde_json::json!({})))] {
        let calls = AtomicUsize::new(0);
        let overtaken = || calls.fetch_add(1, SeqCst) >= 2;
        let r = link_op_with(&s, || true, overtaken, |_| panic!("published over a reset"), std::future::pending(), kind, serde_json::json!({}), any, change).await;
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
    let r = link_op_with(&s, || true, || false, |_| {}, std::future::pending(), "test.change", serde_json::json!({"n": "p"}), any, true).await;
    done.store(true, SeqCst);
    assert_eq!(r, Err(OpError::Unconfirmed));
    assert!(start.elapsed() <= OP_HOLD_MAX + std::time::Duration::from_secs(1), "held the link {:?}", start.elapsed());
    assert!(s.try_lock().is_ok(), "the link is free");
}

/// A reset that starts while an operation waits gets the link at once;
/// a change cut off this way is kept, and retried under its id.
#[tokio::test]
async fn a_reset_stops_a_stalled_operation_and_keeps_the_change() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await; // no answer is scripted: it never comes
    vault.stall(Some(std::time::Duration::from_secs(2))); // and the relay stalls each collect
    let s = slot(link);
    let body = serde_json::json!({"n": "p"});
    let start = std::time::Instant::now();
    let stop = tokio::time::sleep(std::time::Duration::from_millis(300));
    let r = link_op_with(&s, || true, || false, |_| {}, stop, "test.change", body.clone(), any, true).await;
    assert_eq!(r, Err(OpError::Unconfirmed));
    assert!(start.elapsed() < std::time::Duration::from_secs(3), "held the link {:?} past the reset", start.elapsed());
    let mut g = s.lock().await;
    let l = g.as_mut().unwrap();
    let kept = l.unconfirmed.clone().expect("the cut-off change is kept");
    vault.stall(None);
    vault.answer("test.change", Ok("{}"));
    assert_eq!(l.op("test.change", &body, any, true).await, Ok(serde_json::json!({})));
    let ids = vault.asked_ids();
    assert_eq!(ids.last().map(|(i, _)| i.clone()), Some(kept.id.clone()), "retried under its id");
    assert_eq!(ids.last().and_then(|(_, e)| *e).map(|e| e.timestamp_millis()), Some(kept.exp.timestamp_millis()), "with its first exp");
}

/// The bound, too, keeps a cut-off change.
#[tokio::test]
async fn the_hold_bound_keeps_the_change() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await;
    vault.stall(Some(OP_HOLD_MAX + std::time::Duration::from_secs(2))); // past the bound, not the answer wait
    let s = slot(link);
    let r = link_op_with(&s, || true, || false, |_| {}, std::future::pending(), "test.change", serde_json::json!({"n": "p"}), any, true).await;
    assert_eq!(r, Err(OpError::Unconfirmed));
    assert!(s.lock().await.as_ref().unwrap().unconfirmed.is_some());
}

/// A change carries CHANGE_TTL, a read READ_TTL; another body is a new
/// request, never a retry of the pending one.
#[tokio::test]
async fn exps_and_new_ids() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer("test.change", Ok("{}"));
    vault.answer("connection.list", Ok("{}"));
    let t = Utc::now();
    link.op("test.change", &serde_json::json!({"n": "a"}), any, true).await.unwrap();
    link.op("connection.list", &serde_json::json!({}), any, false).await.unwrap();
    let ids = vault.asked_ids();
    let ttl = |i: usize| ids[i].1.unwrap() - t;
    // exp is kept to the millisecond (format_ts): within a few seconds of the TTL.
    let near = |d: TimeDelta, want: TimeDelta| d >= want - TimeDelta::seconds(1) && d <= want + TimeDelta::seconds(5);
    assert!(near(ttl(0), CHANGE_TTL), "{:?}", ttl(0));
    assert!(near(ttl(1), READ_TTL), "{:?}", ttl(1));
    // An unconfirmed change of "b", then a change of "c": a new id.
    vault.offline(true);
    assert_eq!(link.op("test.change", &serde_json::json!({"n": "b"}), any, true).await, Err(OpError::Unconfirmed));
    let pending = link.unconfirmed.clone().unwrap().id;
    vault.offline(false);
    link.op("test.change", &serde_json::json!({"n": "c"}), any, true).await.unwrap();
    assert_ne!(vault.asked_ids().last().unwrap().0, pending, "another change reused the pending one's id");
}

/// A reset 300 ms into a stalled deposit: the change was stored before
/// the deposit, so it is kept, and a second call retries it under its id.
#[tokio::test]
async fn a_change_cut_off_during_its_deposit_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await;
    vault.stall_deposits(Some(std::time::Duration::from_secs(5)));
    let s = slot(link);
    let body = serde_json::json!({"n": "p"});
    let stop = tokio::time::sleep(std::time::Duration::from_millis(300));
    let r = link_op_with(&s, || true, || false, |_| {}, stop, "test.change", body.clone(), any, true).await;
    assert_eq!(r, Err(OpError::Unconfirmed));
    let mut g = s.lock().await;
    let l = g.as_mut().unwrap();
    let kept = l.unconfirmed.clone().expect("the change stored before its deposit is kept");
    vault.stall_deposits(None);
    vault.answer("test.change", Ok("{}"));
    l.op("test.change", &body, any, true).await.unwrap();
    assert_eq!(vault.asked_ids().last().map(|(i, _)| i.clone()), Some(kept.id));
}

/// The outer bound, with no reset: a deposit stalled past OP_HOLD_MAX lets
/// the link go at the bound, and the change is kept.
#[tokio::test]
async fn the_outer_bound_ends_a_stalled_deposit() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await;
    vault.stall_deposits(Some(OP_HOLD_MAX + std::time::Duration::from_secs(5)));
    let s = slot(link);
    let start = std::time::Instant::now();
    let r = link_op_with(&s, || true, || false, |_| {}, std::future::pending(), "test.change", serde_json::json!({"n": "p"}), any, true).await;
    assert_eq!(r, Err(OpError::Unconfirmed));
    assert!(start.elapsed() < OP_HOLD_MAX + std::time::Duration::from_secs(2), "{:?}", start.elapsed());
    assert!(s.lock().await.as_ref().unwrap().unconfirmed.is_some());
}

/// The relay refusing this computer's clock is said as the clock, and a
/// stored change is kept to go once the clock is right.
#[tokio::test]
async fn a_refused_clock_is_said_as_the_clock() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.refuse_clock(true);
    let r = link.op("test.change", &serde_json::json!({"n": "p"}), any, true).await;
    assert_eq!(r, Err(OpError::Clock(Some(0))), "{r:?}");
    assert!(link.unconfirmed.is_some(), "stored: kept for a retry");
    assert!(OpError::Clock(None).notice().contains("clock"));
}

/// A send left unconfirmed, then another message: the kept one is retried
/// first under its id and first exp, then the new one goes under a new id,
/// and what became of the kept one is told.
#[tokio::test]
async fn a_kept_change_is_retried_before_another() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer("test.change", Ok(r#"{"done":true}"#));
    let a = serde_json::json!({"n": "a"});
    vault.offline(true);
    assert_eq!(link.op_kept_first("test.change", &a, any).await, Err(OpError::Unconfirmed));
    assert!(link.earlier.is_none(), "nothing was kept before it");
    let kept = link.unconfirmed.clone().expect("kept");
    vault.offline(false);
    let b = serde_json::json!({"n": "b"});
    assert_eq!(link.op_kept_first("test.change", &b, any).await, Ok(serde_json::json!({"done": true})));
    let ids = vault.asked_ids();
    let last = ids.last().unwrap().clone();
    assert!(ids[..ids.len() - 1].iter().all(|(i, e)| *i == kept.id && e.map(|e| e.timestamp_millis()) == Some(kept.exp.timestamp_millis())), "the kept one first, under its id and first exp: {ids:?}");
    assert_ne!(last.0, kept.id, "the new one under a new id");
    let e = link.earlier.take().expect("told");
    assert_eq!((e.body.as_str(), e.result), (r#"{"n":"a"}"#, Ok(serde_json::json!({"done": true}))));
    assert!(link.unconfirmed.is_none());
}

/// While the kept one stays unconfirmed, the new one isn't sent, and the
/// kept one stays kept.
#[tokio::test]
async fn a_still_unconfirmed_kept_change_stops_another() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer("test.change", Ok("{}"));
    vault.offline(true);
    assert_eq!(link.op_kept_first("test.change", &serde_json::json!({"n": "a"}), any).await, Err(OpError::Unconfirmed));
    let kept = link.unconfirmed.clone().unwrap();
    assert_eq!(link.op_kept_first("test.change", &serde_json::json!({"n": "b"}), any).await, Err(OpError::EarlierUnconfirmed));
    assert_eq!(link.unconfirmed.as_ref().map(|p| p.id.clone()), Some(kept.id.clone()), "still the kept one");
    assert_eq!(link.earlier.as_ref().map(|e| e.result.clone()), Some(Err(OpError::Unconfirmed)));
    // Back online, a read drains the outbox: only the kept one was stored.
    vault.offline(false);
    vault.answer("connection.list", Ok("{}"));
    link.op("connection.list", &serde_json::json!({}), any, false).await.unwrap();
    assert_eq!(vault.asked_ids().iter().filter(|(i, _)| *i != kept.id).count(), 1, "only the read besides the kept one: {:?}", vault.asked_ids());
}

/// A kept change past its exp isn't retried (that would be a new request):
/// it is told as unconfirmed, and the new one goes.
#[tokio::test]
async fn a_kept_change_past_its_exp_isnt_retried() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer("test.change", Ok("{}"));
    vault.offline(true);
    assert_eq!(link.op_kept_first("test.change", &serde_json::json!({"n": "a"}), any).await, Err(OpError::Unconfirmed));
    let kept = link.unconfirmed.clone().unwrap();
    link.unconfirmed.as_mut().unwrap().exp = Utc::now() - TimeDelta::seconds(1);
    vault.offline(false);
    link.op_kept_first("test.change", &serde_json::json!({"n": "b"}), any).await.unwrap();
    assert_eq!(sent(&vault, "test.change"), 2, "retried past its exp (only the stored copy and the new one)");
    assert_ne!(vault.asked_ids().last().unwrap().0, kept.id);
    assert_eq!(link.earlier.take().map(|e| e.result), Some(Err(OpError::Unconfirmed)));
    assert!(link.unconfirmed.is_none());
}

/// The same body again is the retry itself, not a second change.
#[tokio::test]
async fn the_same_change_again_is_its_retry() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.answer("test.change", Ok("{}"));
    let a = serde_json::json!({"n": "a"});
    vault.offline(true);
    assert_eq!(link.op_kept_first("test.change", &a, any).await, Err(OpError::Unconfirmed));
    let kept = link.unconfirmed.clone().unwrap();
    vault.offline(false);
    link.op_kept_first("test.change", &a, any).await.unwrap();
    assert!(link.earlier.is_none());
    assert!(vault.asked_ids().iter().all(|(i, _)| *i == kept.id), "{:?}", vault.asked_ids());
}

/// Through link_run_with: the earlier comes back; a cut-off while the kept
/// one is retried says this one wasn't sent, and keeps the kept one.
#[tokio::test]
async fn kept_first_through_the_link() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await;
    vault.answer("test.change", Ok("{}"));
    let s = slot(link);
    let run = |n: &'static str, stop: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>| {
        link_run_with(&s, || true, || false, |_| {}, stop, "test.change", serde_json::json!({"n": n}), any, How::KeptFirst)
    };
    vault.offline(true);
    let (r, e) = run("a", Box::pin(std::future::pending())).await;
    assert_eq!((r, e), (Err(OpError::Unconfirmed), None));
    let kept = s.lock().await.as_ref().unwrap().unconfirmed.clone().unwrap();
    vault.offline(false);
    vault.stall(Some(std::time::Duration::from_secs(2)));
    // The relay stalls each collect: stopped 300 ms into the kept one's retry.
    let (r, e) = run("b", Box::pin(tokio::time::sleep(std::time::Duration::from_millis(300)))).await;
    assert_eq!(r, Err(OpError::EarlierUnconfirmed));
    assert_eq!(e.map(|e| e.result), Some(Err(OpError::Unconfirmed)));
    assert_eq!(s.lock().await.as_ref().unwrap().unconfirmed.as_ref().map(|p| p.id.clone()), Some(kept.id.clone()), "still kept");
    vault.stall(None);
    vault.answer("test.change", Ok("{}"));
    let (r, e) = run("b", Box::pin(std::future::pending())).await;
    assert_eq!(r, Ok(serde_json::json!({})));
    assert_eq!(e.map(|e| e.result), Some(Ok(serde_json::json!({}))));
}

#[test]
fn pending_and_earlier_leave_the_body_out_of_debug() {
    let body = Zeroizing::new(r#"{"text":"meet at noon"}"#.to_string());
    let p = Pending { kind: "message.send".into(), body: body.clone(), id: "i".into(), exp: Utc::now() };
    let e = Earlier { body, result: Ok(serde_json::json!({"text": "meet at noon"})) };
    let d = format!("{p:?} {e:?}");
    assert!(!d.contains("noon"), "{d}");
}

#[test]
fn the_new_codes() {
    assert_eq!((OpError::PageGone.code(), OpError::PageGone.notice()), ("page_gone", OP_NOT_FOUND_NOTICE.to_string()));
    assert_eq!((OpError::EarlierUnconfirmed.code(), OpError::EarlierUnconfirmed.notice()), ("earlier_unconfirmed", OP_NOT_SENT_NOTICE.to_string()));
    assert_eq!(OpError::Vault("connection_unavailable".into()).code(), "connection_unavailable");
    assert_eq!(OpError::Vault("connection_unavailable".into()).notice(), OP_FAILED_NOTICE);
}
