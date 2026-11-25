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
    assert_eq!(link.collect().await, Collected::Ok);
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
    assert_eq!(link.collect().await, Collected::NoSession);
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
    assert_eq!(link.collect().await, Collected::NoSession);
    assert_eq!(link.take_inbound(), InboundBatch { messages: vec![], resync: true });
}

/// A hold drops the queue (§3.6.5): the hold is learned from the status
/// read, and the next collect finds no session.
#[tokio::test]
async fn a_hold_drops_the_queue() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    assert_eq!(link.collect().await, Collected::Ok);
    vault.hold(true, "");
    link.read_status().await.unwrap();
    assert_eq!(link.collect().await, Collected::NoSession);
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
        tokio::spawn(async move { collect_loop(&slot, COLLECT_EVERY, |b, _| {
            if !b.messages.is_empty() || b.resync {
                got.lock().unwrap().push(b)
            }
        }).await })
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
    assert_eq!(link.collect().await, Collected::Ok);
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

fn msg_batch() -> InboundBatch {
    let mut q = super::inbound::Queue::default();
    let m = vettid_vms::envelope::Inner {
        id: "01J0000000000000000000000A".into(),
        kind: "message.new".into(),
        ts: Utc::now(),
        seq: Some(1),
        response: None,
        exp: None,
        body: zeroize::Zeroizing::new(MSG.into()),
    };
    q.take(&m);
    q.drain()
}

/// The gate: messages reach the window only while both the screen and the
/// link are live; the link finding the session over is published.
#[test]
fn the_gate() {
    let resync = InboundBatch { messages: vec![], resync: true };
    assert_eq!(gate(msg_batch(), true, true), (Some(msg_batch()), false));
    assert_eq!(gate(InboundBatch::default(), true, true), (None, false));
    assert_eq!(gate(msg_batch(), true, false), (Some(resync.clone()), true), "the link found it over: publish");
    assert_eq!(gate(InboundBatch::default(), true, false), (None, true));
    assert_eq!(gate(msg_batch(), false, true), (Some(resync.clone()), false), "the screen isn't live");
    assert_eq!(gate(msg_batch(), false, false), (Some(resync), false));
    assert_eq!(gate(InboundBatch::default(), false, false), (None, false));
}

/// A message of ours dropped while no session is live asks for a resync.
#[tokio::test]
async fn a_dropped_message_asks_for_a_resync() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = FakeVault::paired(dir.path());
    vault.event("message.new", MSG, Utc::now());
    link.read_status().await.unwrap();
    assert!(!link.snapshot(Utc::now()).active_at(Utc::now()));
    assert_eq!(link.take_inbound(), InboundBatch { messages: vec![], resync: true });
}

/// A renewal denied while the session runs on drops what was queued (the
/// session is still live, so only the clear on Denied does it).
#[tokio::test]
async fn a_denial_drops_the_queue_though_the_session_runs_on() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    vault.event("device.session.ended", "{\"reason\":\"denied\"}", Utc::now());
    assert_eq!(link.collect().await, Collected::Ok);
    assert!(link.snapshot(Utc::now()).active_at(Utc::now()), "a denied renewal ends nothing");
    assert_eq!(link.take_inbound(), InboundBatch { messages: vec![], resync: true });
}

/// A session event that doesn't read drops the queue too (fail secure).
#[tokio::test]
async fn an_unreadable_session_event_drops_the_queue() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    vault.event("device.session.ended", "{\"reason\":\"sideways\"}", Utc::now());
    link.collect().await;
    assert_eq!(link.take_inbound(), InboundBatch { messages: vec![], resync: true });
}

/// A collect looks for a sleep first: past a missed round, the vault's
/// state is unconfirmed, so nothing is collected.
#[tokio::test]
async fn a_collect_after_a_sleep_collects_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    link.marks().due = Some(Utc::now() - TimeDelta::minutes(10));
    let before = vault.collects();
    assert_eq!(link.collect().await, Collected::NoSession);
    assert_eq!(link.resumes, 1);
    assert_eq!(vault.collects(), before);
}

/// A round that finds the link busy is skipped, not queued behind the
/// command: when the command ends, nothing is collected until the next
/// round.
#[tokio::test(start_paused = true)]
async fn a_busy_link_skips_the_round() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await;
    let slot = Arc::new(Mutex::new(Some(link)));
    let task = {
        let slot = slot.clone();
        tokio::spawn(async move { collect_loop(&slot, COLLECT_EVERY, |_, _| {}).await })
    };
    let held = slot.lock().await;
    let before = vault.collects();
    tokio::time::sleep(COLLECT_EVERY + COLLECT_EVERY / 2).await;
    drop(held);
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(vault.collects(), before, "a round waited for the lock instead of skipping");
    tokio::time::sleep(COLLECT_EVERY).await;
    assert!(vault.collects() > before, "the next round didn't collect");
    task.abort();
}

/// A message that arrives while a renewal request waits (and lapses) is
/// kept for the views.
#[tokio::test]
async fn a_request_wait_keeps_messages_for_the_views() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.request_window(TimeDelta::seconds(2));
    vault.event("message.new", MSG, Utc::now());
    let r = tokio::time::timeout(std::time::Duration::from_secs(12), link.request_access(|| {}, || false)).await.expect("lapsed");
    assert!(r.is_err(), "{r:?}");
    let b = link.take_inbound();
    assert_eq!(b.messages.len(), 1, "{b:?}");
}

/// Failed collects back off: doubling to a minute, or the relay's
/// retry_after; one that works goes back to every 5 s.
#[test]
fn collects_back_off() {
    let s = std::time::Duration::from_secs;
    assert_eq!(next_collect_wait(s(5), Collected::Ok), COLLECT_EVERY);
    assert_eq!(next_collect_wait(s(40), Collected::NoSession), COLLECT_EVERY);
    assert_eq!(next_collect_wait(s(5), Collected::Failed { retry_after: None }), s(10));
    assert_eq!(next_collect_wait(s(40), Collected::Failed { retry_after: None }), COLLECT_BACKOFF_MAX);
    assert_eq!(next_collect_wait(s(5), Collected::Failed { retry_after: Some(30) }), s(30));
    assert_eq!(next_collect_wait(s(5), Collected::Failed { retry_after: Some(1) }), COLLECT_EVERY);
    assert_eq!(next_collect_wait(s(5), Collected::Failed { retry_after: Some(900) }), s(900), "taken as given");
    assert_eq!(next_collect_wait(s(5), Collected::Failed { retry_after: Some(2000) }), COLLECT_RETRY_AFTER_MAX);
}

/// In the loop: an unreachable relay is collected less and less often.
#[tokio::test(start_paused = true)]
async fn the_loop_backs_off_while_the_relay_is_away() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await;
    let slot = Arc::new(Mutex::new(Some(link)));
    vault.offline(true);
    let rounds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let task = {
        let (slot, rounds) = (slot.clone(), rounds.clone());
        tokio::spawn(async move {
            collect_loop(&slot, COLLECT_EVERY, |_, _| {
                rounds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
            .await
        })
    };
    tokio::time::sleep(std::time::Duration::from_secs(76)).await;
    task.abort();
    // 5, 15, 35, 75 s: four, where a fixed 5 s would make fifteen.
    let n = rounds.load(std::sync::atomic::Ordering::SeqCst);
    assert!((3..=5).contains(&n), "{n} collects in 76 s");
}

/// Each of noted's clears on its own (the after-collect check is a second
/// layer, tested apart below): a queued message goes, and the views read
/// again.
#[tokio::test]
async fn noted_clears_on_every_change() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    let events: Vec<Result<Option<AccessEvent>, AccessError>> = vec![
        Ok(Some(AccessEvent::Held)),
        Ok(Some(AccessEvent::Locked)),
        Ok(Some(AccessEvent::Ended)),
        Ok(Some(AccessEvent::Denied)),
        Ok(Some(AccessEvent::ReadStatus)),
        Err(AccessError::Malformed),
    ];
    for e in events {
        vault.event("message.new", MSG, Utc::now());
        link.read_status().await.unwrap();
        assert_eq!(link.take_inbound().messages.len(), 1, "queued before {e:?}");
        vault.event("message.new", MSG, Utc::now());
        link.read_status().await.unwrap();
        link.noted(&e);
        assert_eq!(link.take_inbound(), InboundBatch { messages: vec![], resync: true }, "{e:?}");
    }
}

/// The after-collect check on its own: no session live as the screen
/// shows it, so the queue goes and the views read again, even when it was
/// empty.
#[tokio::test]
async fn the_after_collect_check_clears_and_asks_for_a_resync() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    link.read_status().await.unwrap();
    link.settle_inbound();
    assert_eq!(link.take_inbound().messages.len(), 1, "live: kept");
    vault.event("message.new", MSG, Utc::now());
    link.read_status().await.unwrap();
    link.resumed(); // the vault's state unconfirmed: not live
    link.settle_inbound();
    assert_eq!(link.take_inbound(), InboundBatch { messages: vec![], resync: true });
    link.settle_inbound();
    assert_eq!(link.take_inbound(), InboundBatch { messages: vec![], resync: true }, "an empty queue too");
}

/// The engine's poll_now returns what a request held first.
#[tokio::test]
async fn poll_now_returns_held_messages_first() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, mut link) = live(dir.path()).await;
    vault.event("message.new", MSG, Utc::now());
    link.session.request(&mut link.store, "vault.status", "{}", TimeDelta::seconds(5)).await.unwrap();
    let before = vault.collects();
    let got = link.session.poll_now(&mut link.store).await.unwrap();
    assert_eq!(vault.collects(), before, "held messages come back without a collect");
    assert!(got.iter().any(|m| m.kind == "message.new"), "{got:?}");
}

/// After a failure, the first collect that works goes back to every 5 s.
#[tokio::test(start_paused = true)]
async fn the_loop_comes_back_to_every_5_s() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, link) = live(dir.path()).await;
    let slot = Arc::new(Mutex::new(Some(link)));
    vault.offline(true);
    let rounds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let task = {
        let (slot, rounds) = (slot.clone(), rounds.clone());
        tokio::spawn(async move {
            collect_loop(&slot, COLLECT_EVERY, |_, _| {
                rounds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
            .await
        })
    };
    // Rounds at 5, 15, 35 s; the next is due at 75 s.
    tokio::time::sleep(std::time::Duration::from_secs(36)).await;
    vault.offline(false);
    tokio::time::sleep(std::time::Duration::from_secs(40)).await; // the round at 75 s works
    let at_76 = rounds.load(std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_secs(21)).await;
    task.abort();
    let more = rounds.load(std::sync::atomic::Ordering::SeqCst) - at_76;
    assert!((3..=5).contains(&more), "{more} rounds in the 21 s after a collect worked");
}

fn live_snap(t: DateTime<Utc>, seq: u64) -> Snapshot {
    Snapshot { link_open: true, live_until: Some(t + TimeDelta::hours(1)), vault: VaultView::open(t), seq, ..Default::default() }
}

/// hand_on, round by round: what reaches the window, what is published.
#[test]
fn hand_on_gates_publishes_and_owes_resyncs() {
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    let t = Utc::now();
    let got = std::sync::Mutex::new(Vec::<InboundBatch>::new());
    let ok = AtomicBool::new(true);
    let deliver = |b: InboundBatch| {
        got.lock().unwrap().push(b);
        ok.load(SeqCst)
    };
    let take = || std::mem::take(&mut *got.lock().unwrap());
    let resync = InboundBatch { messages: vec![], resync: true };
    let owed = AtomicBool::new(false);

    // Both live: the messages go; nothing is published.
    let published = RwLock::new(live_snap(t, 7));
    let mut publishes = Vec::new();
    hand_on(&published, msg_batch(), live_snap(t, 0), || t, |seen, _| publishes.push(seen), Some(&deliver), &owed);
    assert_eq!(take(), vec![msg_batch()]);
    assert!(publishes.is_empty());

    // The link found it over: published (over the snapshot read), and
    // only the resync goes.
    hand_on(&published, msg_batch(), Snapshot::default(), || t, |seen, _| publishes.push(seen), Some(&deliver), &owed);
    assert_eq!(publishes, vec![7]);
    assert_eq!(take(), vec![resync.clone()]);

    // The screen isn't live: only the resync, nothing published.
    let dark = RwLock::new(Snapshot::default());
    hand_on(&dark, msg_batch(), live_snap(t, 0), || t, |_, _| panic!("published"), Some(&deliver), &owed);
    assert_eq!(take(), vec![resync.clone()]);

    // Live at the gate, not by the time it is handed on: the re-check
    // under the read guard sends only the resync.
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let later = || if calls.fetch_add(1, SeqCst) < 2 { t } else { t + TimeDelta::hours(2) };
    hand_on(&published, msg_batch(), live_snap(t, 0), later, |_, _| panic!("published"), Some(&deliver), &owed);
    assert_eq!(take(), vec![resync.clone()]);

    // A batch that didn't reach the window: a resync is owed, and sent on
    // its own next round, though nothing else comes.
    ok.store(false, SeqCst);
    hand_on(&published, msg_batch(), live_snap(t, 0), || t, |_, _| {}, Some(&deliver), &owed);
    assert!(owed.load(SeqCst));
    ok.store(true, SeqCst);
    take();
    hand_on(&published, InboundBatch::default(), live_snap(t, 0), || t, |_, _| {}, Some(&deliver), &owed);
    assert_eq!(take(), vec![resync.clone()]);
    assert!(!owed.load(SeqCst), "paid");
    // With messages, the owed resync rides along.
    owed.store(true, SeqCst);
    hand_on(&published, msg_batch(), live_snap(t, 0), || t, |_, _| {}, Some(&deliver), &owed);
    assert_eq!(take(), vec![InboundBatch { resync: true, ..msg_batch() }]);
    // No window yet: owed.
    hand_on(&published, msg_batch(), live_snap(t, 0), || t, |_, _| {}, None, &owed);
    assert!(owed.load(SeqCst));
}

/// publish_if publishes only over the snapshot it was given.
#[test]
fn publish_if_doesnt_overwrite_a_newer_snapshot() {
    let t = Utc::now();
    let shared = Shared {
        link: Arc::new(Mutex::new(None)),
        snapshot: Arc::new(RwLock::new(live_snap(t, 3))),
        is_registered: Arc::default(),
        notify: Arc::default(),
        changed: Arc::default(),
        deliver: Arc::default(),
    };
    assert!(!shared.publish_if(2, Snapshot::default()), "a newer one was published since");
    assert!(shared.read().active_at(t));
    assert!(shared.publish_if(3, Snapshot::default()));
    assert!(!shared.read().active_at(t));
    assert_eq!(shared.read().seq, 4);
}
