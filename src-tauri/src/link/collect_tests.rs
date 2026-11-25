//! Phase 5, 5.1: the mailbox is collected while an access session runs,
//! and what the vault sent for the views reaches the frontend.

use super::inbound::{Inbound, InboundBatch};
use super::*;
use fake::FakeVault;

const MSG: &str = r#"{"connection_id":"c-1","message_id":"m-1","direction":"in","text":"hi","sent_at":"2026-11-25T10:00:00.000Z","delivered":true,"read":false}"#;
const RECEIPT: &str = r#"{"kind":"message.receipt","connection_id":"c-1","message_id":"m-0","receipt":"read"}"#;

async fn live(dir: &std::path::Path) -> (FakeVault, Link<FakeVault, SystemClock>) {
    let (vault, mut link) = FakeVault::paired(dir);
    vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
    link.read_status().await.unwrap();
    assert!(link.snapshot(Utc::now()).active_at(Utc::now()));
    (vault, link)
}

#[tokio::test]
async fn a_live_session_collects_messages_for_the_views() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    vault.event("sync.event", RECEIPT, Utc::now());
    vault.event("sync.event", r#"{"kind":"wallet.changed","wallet_id":"w","version":1}"#, Utc::now());
    assert!(link.collect().await);
    let b = link.take_inbound();
    assert!(!b.resync);
    assert_eq!(b.messages.len(), 2, "the wallet kind isn't followed");
    let Inbound::MessageNew(m) = &b.messages[0] else { panic!("{:?}", b.messages[0]) };
    assert_eq!((m.message_id.as_str(), m.text.as_str()), ("m-1", "hi"));
    assert!(matches!(&b.messages[1], Inbound::Sync(e) if e.kind == "message.receipt"));
    assert_eq!(link.take_inbound(), InboundBatch::default(), "taken once");
}

/// No session: nothing is collected (the mailbox isn't read), and nothing
/// is handed on.
#[tokio::test]
async fn no_session_no_collect() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = FakeVault::paired(dir.path());
    link.read_status().await.unwrap();
    vault.event("message.new", MSG, Utc::now());
    let before = vault.collects();
    assert!(!link.collect().await);
    assert_eq!(vault.collects(), before, "the mailbox was collected without a session");
    assert_eq!(link.take_inbound(), InboundBatch::default());
}

/// A message collected by another poll (a status read here) isn't
/// dropped: it waits for the next delivery.
#[tokio::test]
async fn messages_a_status_read_collected_are_kept() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    link.read_status().await.unwrap();
    assert_eq!(link.take_inbound().messages.len(), 1);
}

/// The session ends: what was queued is dropped, and the views are told to
/// read again (nothing read before is shown).
#[tokio::test]
async fn an_ended_session_drops_the_queue() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    link.read_status().await.unwrap();
    vault.set_session(None);
    vault.event("device.session.ended", "{\"reason\":\"ended\"}", Utc::now());
    link.read_status().await.unwrap();
    assert!(!link.snapshot(Utc::now()).active_at(Utc::now()));
    assert!(!link.collect().await);
    assert_eq!(link.take_inbound(), InboundBatch { messages: vec![], resync: true });
}

/// A hold drops the queue (§3.6.5): the hold is learned from the status
/// read, and the next collect finds no session.
#[tokio::test]
async fn a_hold_drops_the_queue() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    assert!(link.collect().await);
    vault.hold(true, "");
    link.read_status().await.unwrap();
    assert!(!link.collect().await);
    assert_eq!(link.take_inbound(), InboundBatch { messages: vec![], resync: true });
}

/// The loop delivers what it collected, skips empty rounds, and ends with
/// the link.
#[tokio::test(start_paused = true)]
async fn the_collect_loop_delivers_and_ends_with_the_link() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await;
    let slot = Arc::new(Mutex::new(Some(link)));
    let got = Arc::new(std::sync::Mutex::new(Vec::<InboundBatch>::new()));
    let task = {
        let (slot, got) = (slot.clone(), got.clone());
        tokio::spawn(async move { collect_loop(&slot, COLLECT_EVERY, |b| got.lock().unwrap().push(b)).await })
    };
    tokio::time::sleep(COLLECT_EVERY * 2 + std::time::Duration::from_millis(10)).await;
    assert!(got.lock().unwrap().is_empty(), "empty rounds deliver nothing");
    vault.event("message.new", MSG, Utc::now());
    tokio::time::sleep(COLLECT_EVERY).await;
    assert_eq!(got.lock().unwrap().len(), 1);
    *slot.lock().await = None;
    tokio::time::sleep(COLLECT_EVERY * 2).await;
    assert!(task.is_finished(), "the loop didn't end with the link");
}

/// The collector doesn't long-poll: it holds the link's lock only for the
/// exchange (wait=0 at the relay).
#[tokio::test]
async fn a_collect_doesnt_wait_at_the_relay() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    let before = vault.waits().len();
    assert!(link.collect().await);
    let waits = vault.waits();
    assert!(waits.len() > before, "no collect");
    assert!(waits[before..].iter().all(|w| *w == 0), "{waits:?}");
}

/// A lock notice collected with a message drops the message (§3.6.5).
#[tokio::test]
async fn a_lock_notice_drops_what_came_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    vault.lock_vault(None);
    link.collect().await;
    assert_eq!(link.take_inbound(), InboundBatch { messages: vec![], resync: true });
}

/// A session replaced (a new grant) drops what was queued under the old
/// one: the views read again under the new one.
#[tokio::test]
async fn a_new_grant_drops_the_old_sessions_queue() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    let until = vettid_vms::envelope::format_ts(Utc::now() + TimeDelta::hours(2));
    vault.event("device.session.granted", &format!("{{\"session_id\":\"s-2\",\"expires_at\":\"{until}\"}}"), Utc::now());
    link.collect().await;
    assert_eq!(link.take_inbound(), InboundBatch { messages: vec![], resync: true });
}
