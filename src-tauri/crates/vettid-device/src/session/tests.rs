//! The session engine against the in-memory relay and the test vault,
//! starting from a real pairing.

use std::sync::{Arc, Mutex};

use chrono::{TimeDelta, Utc};
use ed25519_dalek::SigningKey;
use vettid_relay::token::Token;
use vettid_vms::envelope::{new_ulid, Envelope, Inner, Response, Status};
use zeroize::Zeroizing;

use super::*;
use crate::store::{MemStore, Persist, StoreError};
use crate::testutil::*;

const DEVICE_PAIRED: &str = "device.paired";

/// A store whose saves can be made to fail.
#[derive(Default)]
struct Flaky {
    inner: MemStore,
    fail: bool,
}

impl Persist for Flaky {
    fn save(&mut self, data: &[u8]) -> Result<(), StoreError> {
        if self.fail {
            return Err(StoreError::Io);
        }
        self.inner.save(data)
    }
    fn load(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        self.inner.load()
    }
    fn clear(&mut self) -> Result<(), StoreError> {
        self.inner.clear()
    }
}

/// A paired desktop: the relay, the vault, the faults, the store.
async fn paired() -> (Arc<Mutex<Relay>>, Vault, Arc<Mutex<Faults>>, Flaky) {
    let (relay, mut vault, faults) = setup();
    let mut store = Flaky::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    let body = vault.paired_body(&vault.device_relay_key());
    vault.send(DEVICE_PAIRED, body).await;
    pairing.wait_for_approval(&mut store).await.unwrap();
    (relay, vault, faults, store)
}

fn session(relay: &Arc<Mutex<Relay>>, faults: &Arc<Mutex<Faults>>, store: &mut impl Persist, clock: Ticking) -> Session<Mem, Ticking> {
    Session::open(store, mem(relay, faults), clock).unwrap().unwrap()
}

/// The vault's side of the session: open what the desktop sent.
async fn vault_receive(vault: &mut Vault) -> Inner {
    let m = vault.next().await;
    vault.handshake.as_mut().unwrap().1.open(&Envelope::parse(&m.payload).unwrap()).unwrap()
}

fn event(kind: &str, body: &str) -> Inner {
    Inner { id: new_ulid(Utc::now()).unwrap(), kind: kind.into(), ts: Utc::now(), seq: None, response: None, exp: None, body: Zeroizing::new(body.into()) }
}

/// Seal `inner` as the vault, and deposit it from `from` (the vault's own
/// relay key unless given).
async fn vault_deposit(vault: &mut Vault, mut inner: Inner, from: Option<&Mem>) -> Vec<u8> {
    let env = vault.handshake.as_mut().unwrap().1.seal(&mut inner).unwrap();
    let to = vault.device_mailbox();
    let by = from.unwrap_or(&vault.mem);
    by.deposit(URL, &to, &Token::from_received("x".into()), &env).await.unwrap();
    env
}

#[tokio::test]
async fn sends_and_receives() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    assert_eq!(s.device_id(), Some("dev-1"));
    let id = s.send(&mut store, "test.ping", r#"{"n":1}"#, false).await.unwrap();
    let got = vault_receive(&mut vault).await;
    assert_eq!((got.id.as_str(), got.kind.as_str(), got.body.as_str()), (id.as_str(), "test.ping", r#"{"n":1}"#));
    assert_eq!(got.seq, Some(2), "after hs.fin's seq 1");
    assert_eq!(s.outbox_len(), 0);
    vault_deposit(&mut vault, event("test.event", r#"{"x":true}"#), None).await;
    let events = s.poll(&mut store).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "test.event");
    // The stored state carries on: a reopened session continues the seq.
    let mut again = session(&relay, &faults, &mut store, Ticking::new());
    again.send(&mut store, "test.ping", "{}", false).await.unwrap();
    assert_eq!(vault_receive(&mut vault).await.seq, Some(3));
}

#[tokio::test]
async fn a_request_gets_its_response() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let answer = async {
        let req = vault_receive(&mut vault).await;
        // An unrelated event first: kept for the next poll.
        vault_deposit(&mut vault, event("test.event", "{}"), None).await;
        let mut resp = event("test.ask", r#"{"answer":42}"#);
        resp.response = Some(Response { re: req.id.clone(), status: Status::Ok });
        vault_deposit(&mut vault, resp, None).await;
    };
    let (got, ()) = tokio::join!(s.request(&mut store, "test.ask", "{}", TimeDelta::seconds(30)), answer);
    let got = got.unwrap();
    assert_eq!(got.body.as_str(), r#"{"answer":42}"#);
    let later = s.poll(&mut store).await.unwrap();
    assert_eq!(later.iter().map(|i| i.kind.as_str()).collect::<Vec<_>>(), ["test.event"]);
}

/// Both dedupe layers (§8.2), and §8.1's rule for unrequested responses.
#[tokio::test]
async fn duplicates_and_strays_are_dropped() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    // One envelope deposited twice: two msg_ids, one inner id.
    let env = vault_deposit(&mut vault, event("test.event", "{}"), None).await;
    let to = vault.device_mailbox();
    vault.mem.deposit(URL, &to, &Token::from_received("x".into()), &env).await.unwrap();
    // A response to nothing this device asked.
    let mut stray = event("test.ask", "{}");
    stray.response = Some(Response { re: new_ulid(Utc::now()).unwrap(), status: Status::Ok });
    vault_deposit(&mut vault, stray, None).await;
    let events = s.poll(&mut store).await.unwrap();
    assert_eq!(events.len(), 1, "one event, once");
    // The same msg_id delivered again (a lease that ran out): dropped.
    let seen = s.state.seen.keys().next().unwrap().clone();
    relay.lock().unwrap().mailboxes.get_mut(&to).unwrap().push(vettid_relay::client::Message {
        msg_id: seen,
        deposited_at: "t".into(),
        sender: vettid_relay::auth::encode_key(&vault.mem.key.verifying_key()),
        jti: None,
        payload: env,
    });
    assert!(s.poll(&mut store).await.unwrap().is_empty());
}

/// Only the vault's relay key, fresh messages, and ephemeral ones with an
/// exp count.
#[tokio::test]
async fn senders_and_freshness_are_checked() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let stranger = Mem { relay: relay.clone(), key: SigningKey::from_bytes(&[8; 32]), name: "stranger", faults: Default::default() };
    vault_deposit(&mut vault, event("test.event", "{}"), Some(&stranger)).await;
    let mut old = event("test.event", "{}");
    old.ts = Utc::now() - TimeDelta::days(17);
    vault_deposit(&mut vault, old, None).await;
    // An ephemeral type needs exp; without it, it's refused.
    let mut no_exp = event("presence.ping", "{}");
    no_exp.exp = None;
    vault_deposit(&mut vault, no_exp, None).await;
    let mut eph = event("presence.ping", "{}");
    eph.exp = Some(Utc::now() + TimeDelta::minutes(1));
    vault_deposit(&mut vault, eph, None).await;
    let events = s.poll(&mut store).await.unwrap();
    assert_eq!(events.len(), 1, "only the fresh ephemeral one with exp, from the vault");
    assert!(events[0].exp.is_some());
    assert!(!durable("presence.ping") && durable("message.send"));
}

/// §8.3: stored before acked; a failed save acks nothing and rolls back,
/// so the batch comes again and is handled once.
#[tokio::test]
async fn store_then_ack_and_roll_back() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    vault_deposit(&mut vault, event("test.event", "{}"), None).await;
    store.fail = true;
    assert_eq!(s.poll(&mut store).await.unwrap_err(), SessionError::Store(StoreError::Io));
    assert_eq!(relay.lock().unwrap().mailboxes[&vault.device_mailbox()].len(), 1, "not acked");
    store.fail = false;
    relay.lock().unwrap().log.clear();
    let events = s.poll(&mut store).await.unwrap();
    assert_eq!(events.len(), 1, "handled on redelivery");
    assert!(relay.lock().unwrap().mailboxes[&vault.device_mailbox()].is_empty());
}

/// A deposit that fails for now stays in the stored outbox and goes out
/// later, also from a reopened session.
#[tokio::test]
async fn the_outbox_survives_failures_and_restarts() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    faults.lock().unwrap().temporary = 3;
    let id = s.send(&mut store, "test.ping", "{}", false).await.unwrap();
    assert_eq!(s.outbox_len(), 1);
    drop(s); // the app stops
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    assert_eq!(s.outbox_len(), 1, "stored");
    faults.lock().unwrap().temporary = 0;
    s.poll(&mut store).await.unwrap();
    assert_eq!(s.outbox_len(), 0);
    assert_eq!(vault_receive(&mut vault).await.id, id);
}

/// token_revoked: this device was unlinked; nothing more is sent.
#[tokio::test]
async fn a_revoked_device_stops_sending() {
    let (relay, _vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    faults.lock().unwrap().revoked = true;
    assert_eq!(s.send(&mut store, "test.ping", "{}", false).await.unwrap_err(), SessionError::Refused);
    assert!(s.is_refused());
    assert_eq!(s.send(&mut store, "test.ping", "{}", false).await.unwrap_err(), SessionError::Refused);
    let reopened = session(&relay, &faults, &mut store, Ticking::new());
    assert!(reopened.is_refused(), "stored");
    assert_eq!(reopened.outbox_len(), 0);
}

/// §8.6: a refused device still collects, where device.unlinked waits.
#[tokio::test]
async fn a_refused_device_still_collects() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    faults.lock().unwrap().revoked = true;
    assert_eq!(s.send(&mut store, "test.ping", "{}", false).await.unwrap_err(), SessionError::Refused);
    vault_deposit(&mut vault, event("device.unlinked", "{}"), None).await;
    let events = s.poll(&mut store).await.unwrap();
    assert_eq!(events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), ["device.unlinked"]);
    assert!(s.is_refused());
    assert_eq!(s.take_dropped(), ["test.ping"], "the queued message is reported as not sent");
}

/// Messages held from inside request() survive a poll that fails.
#[tokio::test]
async fn held_messages_survive_a_failing_poll() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let answer = async {
        let req = vault_receive(&mut vault).await;
        vault_deposit(&mut vault, event("test.event", "{}"), None).await;
        let mut resp = event("test.ask", "{}");
        resp.response = Some(Response { re: req.id.clone(), status: Status::Ok });
        vault_deposit(&mut vault, resp, None).await;
    };
    let (got, ()) = tokio::join!(s.request(&mut store, "test.ask", "{}", TimeDelta::seconds(30)), answer);
    got.unwrap();
    faults.lock().unwrap().collects = 5;
    let held = s.poll(&mut store).await.unwrap();
    assert_eq!(held.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), ["test.event"], "returned without collecting");
    assert!(s.poll(&mut store).await.is_err(), "now the collect fails");
}

/// Any 429 (a full mailbox too) keeps the entry in the outbox (§8.6), and
/// its retry_after (600 s here) holds: neither another send nor a poll
/// tries it early.
#[tokio::test]
async fn a_quota_429_keeps_the_entry() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    faults.lock().unwrap().quota = 1;
    s.send(&mut store, "test.ping", "{}", false).await.unwrap();
    assert_eq!((s.outbox_len(), s.take_dropped().len()), (1, 0));
    let tried = faults.lock().unwrap().deposits_seen;
    s.send(&mut store, "test.two", "{}", false).await.unwrap();
    s.poll(&mut store).await.unwrap();
    assert_eq!(faults.lock().unwrap().deposits_seen, tried, "held: not tried again yet");
    assert_eq!(s.outbox_len(), 2);
    s.hold_until = Utc::now() - TimeDelta::seconds(1);
    s.poll(&mut store).await.unwrap();
    assert_eq!(s.outbox_len(), 0);
    assert_eq!(vault_receive(&mut vault).await.kind, "test.ping");
    assert_eq!(vault_receive(&mut vault).await.kind, "test.two");
}

/// A response must have its request's type; one of another type is
/// dropped and the request keeps waiting.
#[tokio::test]
async fn a_response_has_its_requests_type() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let id = s.send(&mut store, "test.ask", "{}", true).await.unwrap();
    vault_receive(&mut vault).await;
    let mut wrong = event("test.other", "{}");
    wrong.response = Some(Response { re: id.clone(), status: Status::Ok });
    vault_deposit(&mut vault, wrong, None).await;
    assert!(s.poll(&mut store).await.unwrap().is_empty());
    let mut right = event("test.ask", "{}");
    right.response = Some(Response { re: id.clone(), status: Status::Ok });
    vault_deposit(&mut vault, right, None).await;
    assert_eq!(s.poll(&mut store).await.unwrap().len(), 1);
}

/// Ephemeral types and vault.lock never enter the stored outbox; they go
/// once. An expired outbox entry is dropped and reported.
#[tokio::test]
async fn ephemeral_and_lock_messages_are_sent_once() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    for kind in ["presence.ping", "vault.lock"] {
        assert_eq!(s.send(&mut store, kind, "{}", false).await.unwrap_err(), SessionError::NotQueueable, "{kind}");
    }
    s.send_once(&mut store, "presence.ping", "{}", Some(Utc::now() + TimeDelta::minutes(1))).await.unwrap();
    assert_eq!(vault_receive(&mut vault).await.kind, "presence.ping");
    // The exp rules, before anything is sealed: an ephemeral type needs one
    // in the future, vault.lock one at most 60 s ahead; durable types go
    // through send().
    let soon = Some(Utc::now() + TimeDelta::seconds(30));
    for (kind, exp) in [
        ("presence.ping", None),
        ("presence.ping", Some(Utc::now() - TimeDelta::seconds(1))),
        ("vault.lock", None),
        ("vault.lock", Some(Utc::now() + TimeDelta::minutes(5))),
        ("test.ping", soon),
    ] {
        assert_eq!(s.send_once(&mut store, kind, "{}", exp).await.unwrap_err(), SessionError::BadExp, "{kind} {exp:?}");
    }
    faults.lock().unwrap().temporary = 1;
    assert!(s.send_once(&mut store, "vault.lock", "{}", soon).await.is_err(), "not delivered, and not queued");
    assert_eq!(s.outbox_len(), 0);
    // An entry past its exp is dropped unsent.
    let mut late = s.inner(None, "test.ping", "{}".into(), None, Some(Utc::now() - TimeDelta::seconds(1))).unwrap();
    late.exp = Some(Utc::now() - TimeDelta::seconds(1));
    s.queue("test.ping", late).unwrap();
    s.save(&mut store).unwrap();
    s.poll(&mut store).await.unwrap();
    assert_eq!((s.outbox_len(), s.take_dropped()), (0, vec!["test.ping".to_string()]));
}

/// send() is Ok once stored, even if an older entry is then dropped; a
/// resend keeps the id; a response after a restart still finds its
/// request.
#[tokio::test]
async fn sends_resends_and_answers_after_restart() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let next = faults.lock().unwrap().deposits_seen;
    faults.lock().unwrap().deposit = Some(next);
    let first = s.send(&mut store, "test.one", "{}", false).await.unwrap();
    assert_eq!(s.take_dropped(), ["test.one"]);
    let _ = first;
    let id = s.send(&mut store, "test.ask", "{}", true).await.unwrap();
    let req = vault_receive(&mut vault).await;
    assert_eq!(req.id, id);
    let again = s.resend(&mut store, &id, "test.ask", "{}", true).await.unwrap();
    assert_eq!(again, id, "the same inner id");
    assert_eq!(vault_receive(&mut vault).await.id, id);
    drop(s); // the app stops before the answer
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let mut resp = event("test.ask", r#"{"ok":1}"#);
    resp.response = Some(Response { re: id.clone(), status: Status::Ok });
    let env = vault_deposit(&mut vault, resp, None).await;
    let got = s.poll(&mut store).await.unwrap();
    assert_eq!(got.len(), 1, "the waiting request was stored");
    // A duplicate of an answer to a request armed again is delivered.
    s.resend(&mut store, &id, "test.ask", "{}", true).await.unwrap();
    vault_receive(&mut vault).await;
    let to = vault.device_mailbox();
    vault.mem.deposit(URL, &to, &Token::from_received("x".into()), &env).await.unwrap();
    assert_eq!(s.poll(&mut store).await.unwrap().len(), 1, "the cached answer reaches the resent request");
}

/// Past the cap the oldest entry is evicted and reported; token entries
/// replace a waiting one; the refresh path stores the vault's answer.
#[tokio::test]
async fn the_outbox_cap_and_token_entries() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    faults.lock().unwrap().temporary = 1000;
    for _ in 0..(OUTBOX_CAP + 2) {
        s.send(&mut store, "test.ping", "{}", false).await.unwrap();
    }
    assert_eq!(s.outbox_len(), OUTBOX_CAP);
    assert_eq!(s.take_dropped().len(), 2);
    faults.lock().unwrap().temporary = 0;
    s.state.outbox.clear();
    // The vault's token to us runs low: a refresh request goes out (once
    // per hour), and the answer's token is kept.
    s.state.vault_token_exp = Utc::now() + TimeDelta::days(2);
    s.hold_until = Utc::now() - TimeDelta::seconds(1);
    s.poll(&mut store).await.unwrap();
    let ask = vault_receive(&mut vault).await;
    assert_eq!(ask.kind, "relay.token.refresh");
    assert!(ask.response.is_none());
    let (fresh, exp) = crate::token::mint_for_vault(&vault.mem.key, URL, &vault.device_relay_key(), Utc::now(), 0).unwrap();
    let body = vettid_vms::strict_json::Builder::new().string("kind", "standing").string("token", fresh.as_str()).finish();
    let mut answer = event("relay.token.refresh", &body);
    answer.response = Some(Response { re: ask.id.clone(), status: Status::Ok });
    vault_deposit(&mut vault, answer, None).await;
    s.poll(&mut store).await.unwrap();
    assert_eq!(s.state.vault_token_exp, exp);
    // Two re-issues waiting: only the newest stays.
    faults.lock().unwrap().temporary = 1000;
    s.state.issued_exp = Utc::now() + TimeDelta::days(1);
    s.poll(&mut store).await.unwrap();
    s.state.issued_exp = Utc::now() + TimeDelta::days(1);
    s.poll(&mut store).await.unwrap();
    assert_eq!(s.state.outbox.iter().filter(|o| o.kind == "relay.token.issued").count(), 1);
}

/// §7.2: the vault's refresh request gets a fresh standing token; the
/// vault's issued token replaces a shorter one; and the device re-issues
/// its own when it runs low.
#[tokio::test]
async fn tokens_are_kept_fresh() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let ask = event("relay.token.refresh", "{}");
    let ask_id = ask.id.clone();
    vault_deposit(&mut vault, ask, None).await;
    assert!(s.poll(&mut store).await.unwrap().is_empty(), "handled by the engine");
    let reply = vault_receive(&mut vault).await;
    assert_eq!(reply.response.as_ref().map(|r| r.re.as_str()), Some(ask_id.as_str()));
    let o = vettid_vms::strict_json::parse_object(reply.body.as_bytes()).unwrap();
    let token = o.string("token").unwrap();
    let device_pk = vault.device_relay_key();
    assert!(crate::token::check_from_vault(&token, &device_pk, &vault.mem.key.verifying_key(), Utc::now()).is_ok());

    s.state.vault_token_exp = Utc::now() + TimeDelta::days(20);
    let (fresh, exp) = crate::token::mint_for_vault(&vault.mem.key, URL, &device_pk, Utc::now(), 0).unwrap();
    let body = vettid_vms::strict_json::Builder::new().string("kind", "standing").string("token", fresh.as_str()).finish();
    vault_deposit(&mut vault, event("relay.token.issued", &body), None).await;
    s.poll(&mut store).await.unwrap();
    assert_eq!((s.state.vault_token.as_str(), s.state.vault_token_exp), (fresh.as_str(), exp));

    s.state.issued_exp = Utc::now() + TimeDelta::days(5);
    s.poll(&mut store).await.unwrap();
    let issued = vault_receive(&mut vault).await;
    assert_eq!(issued.kind, "relay.token.issued");
    assert!(s.state.issued_exp > Utc::now() + TimeDelta::days(29));
}

#[tokio::test]
async fn unknown_requests_get_unsupported_type() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    vault_deposit(&mut vault, event("future.thing", "{}"), None).await;
    let events = s.poll(&mut store).await.unwrap();
    s.reply_unsupported(&mut store, &events[0]).await.unwrap();
    let got = vault_receive(&mut vault).await;
    let r = got.response.unwrap();
    assert_eq!(r.re, events[0].id);
    assert_eq!(r.status, Status::Error { code: "unsupported_type".into(), message: None });
}

#[test]
fn a_store_with_nothing_paired_has_no_session() {
    let mut store = MemStore::default();
    let relay = Arc::new(Mutex::new(Relay::default()));
    let faults = Arc::default();
    assert!(Session::open(&mut store, mem(&relay, &faults), Ticking::new()).unwrap().is_none());
}

/// Poll up to `n` times; every event the desktop gets.
async fn poll_all(s: &mut Session<Mem, Ticking>, store: &mut impl Persist, n: usize) -> Vec<Inner> {
    let mut all = Vec::new();
    for _ in 0..n {
        all.extend(s.poll(store).await.unwrap());
    }
    all
}

/// The vault rekeys (§6.5): the desktop answers once; the vault's first
/// message of the new epoch, deposited before hs.fin, stays unacked (and
/// unseen) until hs.fin establishes the epoch, then arrives once. Both
/// sides then use the new epoch, and a late message of the old one still
/// opens.
#[tokio::test]
async fn a_vault_rekey_and_its_early_message() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let old_id = s.keys.current().id();
    vault.start_rekey().await;
    assert!(s.poll(&mut store).await.unwrap().is_empty());
    assert_eq!(vault.waiting(), 1, "one hs.resp");
    assert_eq!(s.awaiting.len(), 1);
    let fin = vault.finish_rekey().await;

    // The early message, before hs.fin.
    vault.send("test.early", r#"{"n":1}"#.into()).await;
    for _ in 0..3 {
        assert!(s.poll(&mut store).await.unwrap().is_empty());
    }
    assert_eq!(vault.device_waiting(), 1, "left unacked");
    let early_id = relay.lock().unwrap().mailboxes[&vault.device_mailbox()][0].msg_id.clone();
    assert!(!s.state.seen.contains_key(&early_id), "not marked seen");
    assert_eq!(s.keys.current().id(), old_id, "not established yet");

    vault.deposit_raw(&fin).await;
    let got = poll_all(&mut s, &mut store, 3).await;
    assert_eq!(got.iter().filter(|e| e.kind == "test.early").count(), 1, "delivered once, after hs.fin");
    assert_eq!(got.len(), 1);
    assert_eq!(vault.device_waiting(), 0);
    assert!(s.awaiting.is_empty());
    assert_ne!(s.keys.current().id(), old_id, "the new epoch is current");
    assert_eq!(s.keys.snapshot().retired.len(), 1);

    // The desktop sends in the new epoch (its first message there).
    s.send(&mut store, "test.after", "{}", false).await.unwrap();
    let m = vault_receive(&mut vault).await;
    assert_eq!((m.kind.as_str(), m.seq), ("test.after", Some(1)));

    // A late message of the old epoch still opens.
    let mut late = event("test.late", "{}");
    let env = vault.old.as_mut().unwrap().seal(&mut late).unwrap();
    vault.deposit_raw(&env).await;
    let got = s.poll(&mut store).await.unwrap();
    assert_eq!(got.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), ["test.late"]);

    // hs.fin deposited again: ignored, and acked.
    vault.deposit_raw(&fin).await;
    assert!(s.poll(&mut store).await.unwrap().is_empty());
    assert_eq!(vault.device_waiting(), 0);
    assert_eq!(s.keys.snapshot().retired.len(), 1, "no second activation");
}

/// A restart between hs.resp and hs.fin: the waiting rekey is stored, and
/// the reopened session takes hs.fin and the new epoch's messages.
#[tokio::test]
async fn a_rekey_survives_a_restart() {
    let (relay, mut vault, faults, mut store) = paired().await;
    {
        let mut s = session(&relay, &faults, &mut store, Ticking::new());
        vault.start_rekey().await;
        s.poll(&mut store).await.unwrap();
    }
    let fin = vault.finish_rekey().await;
    vault.send("test.early", "{}".into()).await;
    vault.deposit_raw(&fin).await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    assert_eq!(s.awaiting.len(), 1, "restored");
    let got = poll_all(&mut s, &mut store, 3).await;
    assert_eq!(got.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), ["test.early"]);
    // The established keyring is stored too.
    drop(s);
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    assert!(s.awaiting.is_empty());
    s.send(&mut store, "test.after", "{}", false).await.unwrap();
    assert_eq!(vault_receive(&mut vault).await.kind, "test.after");
}

/// One hs.resp per hs.init (§6.3): a retransmission is skipped while the
/// answer waits in the outbox, and after it went out.
#[tokio::test]
async fn a_retransmitted_init_is_answered_once() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let init = vault.start_rekey().await;
    faults.lock().unwrap().temporary = 1;
    s.poll(&mut store).await.unwrap();
    assert_eq!(s.outbox_len(), 1, "hs.resp queued");
    let init_id = s.state.outbox[0].re.clone().expect("tagged with its hs.init");
    assert!(!s.state.seen_inner.contains_key(&init_id), "not handled until the relay takes hs.resp");
    vault.deposit_raw(&init).await;
    s.hold_until = Utc::now() - TimeDelta::seconds(1);
    s.poll(&mut store).await.unwrap();
    assert_eq!((s.outbox_len(), vault.waiting(), s.awaiting.len()), (0, 1, 1), "the queued answer went, once");
    assert!(s.state.seen_inner.contains_key(&init_id));
    vault.deposit_raw(&init).await;
    s.poll(&mut store).await.unwrap();
    assert_eq!((vault.waiting(), s.awaiting.len()), (1, 1), "after it went: skipped");
    // And the one answer finishes the rekey.
    let fin = vault.finish_rekey().await;
    vault.deposit_raw(&fin).await;
    s.poll(&mut store).await.unwrap();
    assert!(s.awaiting.is_empty());
}

/// An hs.resp the relay refuses for good leaves its hs.init unhandled, so
/// the vault's retransmission is answered.
#[tokio::test]
async fn a_dropped_resp_lets_the_init_be_answered_again() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let init = vault.start_rekey().await;
    let next = faults.lock().unwrap().deposits_seen;
    faults.lock().unwrap().deposit = Some(next);
    s.poll(&mut store).await.unwrap();
    assert_eq!(s.take_dropped(), ["hs.resp"]);
    assert_eq!((vault.waiting(), s.awaiting.len()), (0, 0), "it can't finish: it stops waiting");
    vault.deposit_raw(&init).await;
    s.poll(&mut store).await.unwrap();
    assert_eq!((vault.waiting(), s.awaiting.len()), (1, 1), "answered this time");
}

/// If the batch can't be stored, nothing of the rekey happens: no ack, no
/// hs.resp, no waiting responder; it's answered when storing works again.
#[tokio::test]
async fn a_rekey_batch_rolls_back() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    vault.start_rekey().await;
    store.fail = true;
    assert!(matches!(s.poll(&mut store).await, Err(SessionError::Store(_))));
    assert_eq!((vault.device_waiting(), vault.waiting(), s.awaiting.len(), s.outbox_len()), (1, 0, 0, 0));
    store.fail = false;
    s.poll(&mut store).await.unwrap();
    assert_eq!((vault.device_waiting(), vault.waiting(), s.awaiting.len()), (0, 1, 1));
}

/// The waiting rekeys are capped; the oldest is aborted. A rekey under a
/// retired epoch isn't answered.
#[tokio::test]
async fn waiting_rekeys_are_capped() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    for _ in 0..MAX_AWAITING + 2 {
        vault.start_rekey().await;
    }
    poll_all(&mut s, &mut store, 2).await;
    assert_eq!(s.awaiting.len(), MAX_AWAITING);
    // The two oldest were aborted in the same batch, before their answers
    // went out: those don't go at all.
    assert_eq!((vault.waiting(), s.outbox_len()), (MAX_AWAITING, 0));
}

/// Finishing one rekey ends the others answered under the old epoch:
/// they stop waiting.
#[tokio::test]
async fn an_established_rekey_ends_the_others() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    vault.start_rekey().await;
    s.poll(&mut store).await.unwrap();
    vault.next().await; // the vault abandons that one
    vault.start_rekey().await;
    s.poll(&mut store).await.unwrap();
    assert_eq!(s.awaiting.len(), 2);
    let fin = vault.finish_rekey().await;
    vault.deposit_raw(&fin).await;
    s.poll(&mut store).await.unwrap();
    assert!(s.awaiting.is_empty());
    s.send(&mut store, "test.after", "{}", false).await.unwrap();
    assert_eq!(vault_receive(&mut vault).await.kind, "test.after");
}

/// A clock that goes back (it was fast at the rekey) leaves the stored
/// state readable; an hs.fin that is ahead of the slow clock stays unacked
/// like the new epoch's messages, and both are handled once the clock is
/// right.
#[tokio::test]
async fn a_clock_that_goes_back() {
    let (relay, mut vault, faults, mut store) = paired().await;
    {
        let mut s = session(&relay, &faults, &mut store, Ticking::new());
        vault.start_rekey().await;
        s.poll(&mut store).await.unwrap();
    }
    let fin = vault.finish_rekey().await;
    vault.send("test.early", "{}".into()).await;
    vault.deposit_raw(&fin).await;
    {
        let mut s = session(&relay, &faults, &mut store, Ticking::offset(-7200));
        assert_eq!(s.awaiting.len(), 1, "opened, not refused");
        assert!(poll_all(&mut s, &mut store, 2).await.is_empty());
        assert_eq!(vault.device_waiting(), 2, "hs.fin and the early message wait");
        assert_eq!(s.awaiting.len(), 1);
    }
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let got = poll_all(&mut s, &mut store, 3).await;
    assert_eq!(got.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), ["test.early"]);
    assert!(s.awaiting.is_empty());
    drop(s);
    // With a retired epoch stored, a slow clock still opens the state.
    let mut s = session(&relay, &faults, &mut store, Ticking::offset(-7200));
    assert_eq!(s.keys.snapshot().retired.len(), 1);
    s.send(&mut store, "test.after", "{}", false).await.unwrap();
}

/// A batch whose hs.fin activated the epoch, but couldn't be stored, rolls
/// back to waiting; hs.fin comes again and establishes it.
#[tokio::test]
async fn an_activation_rolls_back() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let old_id = s.keys.current().id();
    vault.start_rekey().await;
    s.poll(&mut store).await.unwrap();
    let fin = vault.finish_rekey().await;
    vault.deposit_raw(&fin).await;
    store.fail = true;
    assert!(s.poll(&mut store).await.is_err());
    assert_eq!((s.keys.current().id(), s.awaiting.len(), vault.device_waiting()), (old_id, 1, 1));
    store.fail = false;
    s.poll(&mut store).await.unwrap();
    assert_ne!(s.keys.current().id(), old_id);
    assert!(s.awaiting.is_empty());
}

/// Junk addressed to the waiting rekey's keys (a tampered hs.fin) is acked
/// and changes nothing; the real hs.fin still finishes it.
#[tokio::test]
async fn junk_for_a_waiting_rekey() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    vault.start_rekey().await;
    s.poll(&mut store).await.unwrap();
    let fin = vault.finish_rekey().await;
    let mut junk = fin.clone();
    let n = junk.len();
    junk[n - 1] ^= 1;
    vault.deposit_raw(&junk).await;
    s.poll(&mut store).await.unwrap();
    assert_eq!((vault.device_waiting(), s.awaiting.len()), (0, 1));
    vault.deposit_raw(&fin).await;
    s.poll(&mut store).await.unwrap();
    assert!(s.awaiting.is_empty());
}

/// After 16 days a waiting rekey is dropped, and its epoch's message is
/// acked instead of waiting for ever.
#[tokio::test]
async fn a_rekey_that_never_finishes() {
    let (relay, mut vault, faults, mut store) = paired().await;
    {
        let mut s = session(&relay, &faults, &mut store, Ticking::new());
        vault.start_rekey().await;
        s.poll(&mut store).await.unwrap();
    }
    vault.finish_rekey().await;
    vault.send("test.early", "{}".into()).await;
    let mut s = session(&relay, &faults, &mut store, Ticking::offset(17 * 24 * 3600));
    assert!(s.poll(&mut store).await.unwrap().is_empty());
    assert_eq!((vault.device_waiting(), s.awaiting.len()), (0, 0));
}

/// A refused device answers no rekey.
#[tokio::test]
async fn a_refused_device_answers_no_rekey() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    faults.lock().unwrap().revoked = true;
    assert_eq!(s.send(&mut store, "test.ping", "{}", false).await.unwrap_err(), SessionError::Refused);
    vault.start_rekey().await;
    s.poll(&mut store).await.unwrap();
    assert_eq!((vault.waiting(), s.awaiting.len(), s.outbox_len()), (0, 0, 0));
}

/// A state stored before rekeys (no retired epochs, waiting rekeys or
/// outbox `re`) still opens.
#[tokio::test]
async fn a_state_from_before_rekeys_opens() {
    let (relay, mut vault, faults, mut store) = paired().await;
    {
        let mut s = session(&relay, &faults, &mut store, Ticking::new());
        faults.lock().unwrap().temporary = 1;
        s.send(&mut store, "test.ping", "{}", false).await.unwrap();
        assert_eq!(s.outbox_len(), 1);
    }
    let data = store.inner.data.clone().unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&data).unwrap();
    let o = v.as_object_mut().unwrap();
    assert!(o.remove("retired").is_some() && o.remove("awaiting").is_some());
    o["outbox"][0].as_object_mut().unwrap().remove("re");
    store.inner.data = Some(Zeroizing::new(serde_json::to_vec(&v).unwrap()));
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    assert_eq!((s.outbox_len(), s.awaiting.len()), (1, 0));
    s.poll(&mut store).await.unwrap();
    assert_eq!(vault_receive(&mut vault).await.kind, "test.ping");
}

/// A rekey hs.init sealed under the old epoch after the new one is up:
/// not answered (only the current epoch may be rekeyed).
#[tokio::test]
async fn no_rekey_from_a_retired_epoch() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    vault.start_rekey().await;
    s.poll(&mut store).await.unwrap();
    let fin = vault.finish_rekey().await;
    vault.deposit_raw(&fin).await;
    s.poll(&mut store).await.unwrap();
    // The vault's old epoch starts another rekey.
    let current = vault.handshake.as_mut().unwrap().1.snapshot();
    let old = vault.old.take().unwrap();
    vault.handshake.as_mut().unwrap().1 = old;
    vault.start_rekey().await;
    vault.handshake.as_mut().unwrap().1 = vettid_vms::handshake::Epoch::restore(current);
    s.poll(&mut store).await.unwrap();
    assert_eq!((vault.waiting(), s.awaiting.len()), (0, 0));
    assert_eq!(vault.device_waiting(), 0, "acked and dropped");
}

/// An hs.resp evicted from a full outbox ends its rekey (it can't be
/// finished).
#[tokio::test]
async fn an_evicted_resp_ends_its_rekey() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    faults.lock().unwrap().temporary = 1000;
    vault.start_rekey().await;
    s.poll(&mut store).await.unwrap();
    assert_eq!((s.awaiting.len(), s.outbox_len()), (1, 1));
    for _ in 0..OUTBOX_CAP {
        s.send(&mut store, "test.ping", "{}", false).await.unwrap();
    }
    assert_eq!((s.awaiting.len(), s.outbox_len()), (0, OUTBOX_CAP));
    assert_eq!(s.take_dropped(), ["hs.resp"]);
}

/// A stored state with more than MAX_AWAITING waiting rekeys opens with the
/// newest, and the others' queued hs.resp don't go out.
#[tokio::test]
async fn open_trims_the_waiting_rekeys() {
    let (relay, mut vault, faults, mut store) = paired().await;
    {
        let mut s = session(&relay, &faults, &mut store, Ticking::new());
        faults.lock().unwrap().temporary = 1000;
        for _ in 0..MAX_AWAITING {
            vault.start_rekey().await;
        }
        s.poll(&mut store).await.unwrap();
        assert_eq!((s.awaiting.len(), s.outbox_len()), (MAX_AWAITING, MAX_AWAITING));
    }
    // One more, older than the rest, with its queued answer.
    let mut v: serde_json::Value = serde_json::from_slice(&store.inner.data.clone().unwrap()).unwrap();
    let mut extra = v["awaiting"][0].clone();
    extra["init"] = serde_json::json!("01JB2Z6V9K3M4N5P6Q7R8S9T0Z");
    v["awaiting"].as_array_mut().unwrap().insert(0, extra);
    let mut resp = v["outbox"][0].clone();
    resp["re"] = serde_json::json!("01JB2Z6V9K3M4N5P6Q7R8S9T0Z");
    v["outbox"].as_array_mut().unwrap().push(resp);
    store.inner.data = Some(Zeroizing::new(serde_json::to_vec(&v).unwrap()));
    let s = session(&relay, &faults, &mut store, Ticking::new());
    assert_eq!(s.awaiting.len(), MAX_AWAITING);
    assert!(s.awaiting.iter().all(|w| w.init != "01JB2Z6V9K3M4N5P6Q7R8S9T0Z"));
    assert_eq!(s.outbox_len(), MAX_AWAITING, "its answer is out of the outbox");
}

/// `device.unlinked` (§7.4): stored before its ack, returned again after a
/// restart until handled, and the device is refused from then on, with
/// the reason. Nothing is erased by the engine.
#[tokio::test]
async fn unlinked_is_kept_until_handled() {
    let (relay, mut vault, faults, mut store) = paired().await;
    {
        let mut s = session(&relay, &faults, &mut store, Ticking::new());
        faults.lock().unwrap().temporary = 1;
        s.send(&mut store, "test.ping", "{}", false).await.unwrap();
        assert_eq!(s.outbox_len(), 1);
        vault_deposit(&mut vault, event("device.unlinked", r#"{"reason":"removed"}"#), None).await;
        let got = s.poll(&mut store).await.unwrap();
        assert_eq!(got.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), ["device.unlinked"]);
        assert_eq!(vault.device_waiting(), 0, "acked once stored");
        assert!(s.is_refused());
        assert_eq!(s.unlinked(), Some("removed"));
        assert_eq!((s.outbox_len(), s.take_dropped()), (0, vec!["test.ping".to_string()]));
        assert!(s.poll(&mut store).await.unwrap().is_empty(), "returned once per session");
        assert_eq!(s.send(&mut store, "test.ping", "{}", false).await.unwrap_err(), SessionError::Refused);
    }
    // A crash before the app acted: it comes again.
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    assert_eq!(s.unlinked(), Some("removed"));
    let got = s.poll(&mut store).await.unwrap();
    assert_eq!(got.len(), 1);
    s.handled(&mut store, &got[0].id).unwrap();
    assert!(store.inner.data.is_some(), "not erased by the engine");
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    assert!(s.poll(&mut store).await.unwrap().is_empty());
    assert_eq!((s.unlinked(), s.is_refused()), (Some("removed"), true), "still removed");
}

/// If the batch can't be stored, `device.unlinked` isn't acked and nothing
/// changes; a failed `handled` keeps the event.
#[tokio::test]
async fn unlinked_rolls_back() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    vault_deposit(&mut vault, event("device.unlinked", "{}"), None).await;
    store.fail = true;
    assert!(s.poll(&mut store).await.is_err());
    assert_eq!((vault.device_waiting(), s.is_refused(), s.unlinked()), (1, false, None));
    store.fail = false;
    let got = s.poll(&mut store).await.unwrap();
    assert_eq!(s.unlinked(), Some(""), "no reason given");
    store.fail = true;
    assert!(s.handled(&mut store, &got[0].id).is_err());
    store.fail = false;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    assert_eq!(s.poll(&mut store).await.unwrap().len(), 1, "still in the inbox");
}

/// The inbox holds at most INBOX_CAP events: one more is left unacked
/// (not dropped), and taken once the app has handled one.
#[tokio::test]
async fn the_inbox_is_capped() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    for n in 0..INBOX_CAP + 1 {
        vault_deposit(&mut vault, event("identity.rotate", &format!(r#"{{"n":{n}}}"#)), None).await;
    }
    let mut got = Vec::new();
    for _ in 0..4 {
        got.extend(s.poll(&mut store).await.unwrap());
    }
    assert_eq!((got.len(), s.state.inbox.len(), vault.device_waiting()), (INBOX_CAP, INBOX_CAP, 1));
    assert!(!s.is_refused(), "identity.rotate doesn't refuse");
    s.handled(&mut store, &got[0].id).unwrap();
    let more = s.poll(&mut store).await.unwrap();
    assert_eq!((more.len(), vault.device_waiting()), (1, 0));
    assert_eq!(more[0].body.as_str(), format!(r#"{{"n":{}}}"#, INBOX_CAP));
}

/// `device.unlinked` isn't held back by a full inbox; a repeat (the same
/// notice again) and a later one add nothing; one as a response doesn't
/// unlink.
#[tokio::test]
async fn unlinked_edge_cases() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    // As a response to nothing asked: dropped, not an unlink.
    let mut as_response = event("device.unlinked", "{}");
    as_response.response = Some(Response { re: "01JB2Z6V9K3M4N5P6Q7R8S9T0V".into(), status: Status::Ok });
    vault_deposit(&mut vault, as_response, None).await;
    s.poll(&mut store).await.unwrap();
    assert_eq!(s.unlinked(), None);
    for n in 0..INBOX_CAP {
        vault_deposit(&mut vault, event("identity.rotate", &format!(r#"{{"n":{n}}}"#)), None).await;
    }
    poll_all(&mut s, &mut store, 3).await;
    assert_eq!(s.state.inbox.len(), INBOX_CAP);
    let env = vault_deposit(&mut vault, event("device.unlinked", r#"{"reason":"removed"}"#), None).await;
    s.poll(&mut store).await.unwrap();
    assert_eq!((s.unlinked(), vault.device_waiting(), s.state.inbox.len()), (Some("removed"), 0, 1), "the waiting rotations are dropped");
    vault.deposit_raw(&env).await;
    vault_deposit(&mut vault, event("device.unlinked", r#"{"reason":"other"}"#), None).await;
    s.poll(&mut store).await.unwrap();
    assert_eq!((s.unlinked(), vault.device_waiting(), s.state.inbox.len()), (Some("removed"), 0, 1), "the waiting rotations are dropped");
}

/// Unlinking ends a waiting rekey and takes its queued answer out; a
/// request in progress returns Refused, and the notice waits for the next
/// poll.
#[tokio::test]
async fn unlinked_ends_rekeys_and_requests() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    faults.lock().unwrap().temporary = 1;
    vault.start_rekey().await;
    s.poll(&mut store).await.unwrap();
    assert_eq!((s.awaiting.len(), s.outbox_len()), (1, 1));
    s.hold_until = Utc::now() - TimeDelta::seconds(1);
    faults.lock().unwrap().temporary = 1000;
    vault_deposit(&mut vault, event("device.unlinked", "{}"), None).await;
    s.poll(&mut store).await.unwrap();
    assert_eq!((s.awaiting.len(), s.outbox_len()), (0, 0));
    // A request: refused at once now.
    assert_eq!(s.request(&mut store, "test.ask", "{}", REQUEST_TIMEOUT).await.unwrap_err(), SessionError::Refused);
}

#[tokio::test]
async fn a_request_interrupted_by_an_unlink() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    vault_deposit(&mut vault, event("device.unlinked", r#"{"reason":"removed"}"#), None).await;
    assert_eq!(s.request(&mut store, "test.ask", "{}", REQUEST_TIMEOUT).await.unwrap_err(), SessionError::Refused);
    let got = s.poll(&mut store).await.unwrap();
    assert_eq!(got.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), ["device.unlinked"]);
}

/// After a restart with the relay out of reach, the stored inbox is still
/// returned.
#[tokio::test]
async fn the_inbox_without_the_relay() {
    let (relay, mut vault, faults, mut store) = paired().await;
    {
        let mut s = session(&relay, &faults, &mut store, Ticking::new());
        vault_deposit(&mut vault, event("device.unlinked", "{}"), None).await;
        s.poll(&mut store).await.unwrap();
    }
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    faults.lock().unwrap().collects = 2;
    assert_eq!(s.poll(&mut store).await.unwrap().len(), 1);
    assert!(s.poll(&mut store).await.is_err(), "nothing more to return: the relay error");
}

/// Inbox events come first in a poll's result.
#[tokio::test]
async fn inbox_events_come_first() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    vault_deposit(&mut vault, event("test.before", "{}"), None).await;
    vault_deposit(&mut vault, event("identity.rotate", "{}"), None).await;
    let got = s.poll(&mut store).await.unwrap();
    assert_eq!(got.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), ["identity.rotate", "test.before"]);
}

/// A deeply nested inbox body doesn't make the stored state unreadable.
#[tokio::test]
async fn a_deep_inbox_body_still_loads() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let depth = 29;
    let body = format!("{}{}", r#"{"a":"#.repeat(depth), "1".to_string() + &"}".repeat(depth));
    {
        let mut s = session(&relay, &faults, &mut store, Ticking::new());
        vault_deposit(&mut vault, event("identity.rotate", &body), None).await;
        assert_eq!(s.poll(&mut store).await.unwrap().len(), 1);
    }
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let got = s.poll(&mut store).await.unwrap();
    assert_eq!(got[0].body.as_str(), body);
}

/// A state stored before the inbox opens.
#[tokio::test]
async fn a_state_from_before_the_inbox_opens() {
    let (relay, _vault, faults, mut store) = paired().await;
    drop(session(&relay, &faults, &mut store, Ticking::new()));
    let mut v: serde_json::Value = serde_json::from_slice(&store.inner.data.clone().unwrap()).unwrap();
    let o = v.as_object_mut().unwrap();
    assert!(o.remove("inbox").is_some());
    assert!(o.remove("unlinked").is_none(), "absent while linked");
    store.inner.data = Some(Zeroizing::new(serde_json::to_vec(&v).unwrap()));
    let s = session(&relay, &faults, &mut store, Ticking::new());
    assert_eq!((s.unlinked(), s.state.inbox.len()), (None, 0));
}

/// Once unlinked, other inbox events are acked and dropped; a body over
/// INBOX_MAX_BODY is left unacked, except a removal, which unlinks and is
/// kept with its reason only; a raw reason out of bounds is kept empty;
/// pending_inbox lists what waits.
#[tokio::test]
async fn inbox_limits_and_a_removed_device() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    let big = format!(r#"{{"pad":"{}"}}"#, "x".repeat(INBOX_MAX_BODY));
    vault_deposit(&mut vault, event("identity.rotate", &big), None).await;
    vault_deposit(&mut vault, event("identity.rotate", "{}"), None).await;
    let got = s.poll(&mut store).await.unwrap();
    assert_eq!((got.len(), vault.device_waiting()), (1, 1), "the large one waits at the relay");
    assert_eq!(s.pending_inbox().len(), 1);
    // A removal with a large body and an odd reason: unlinks.
    let odd = format!(r#"{{"reason":"{}","pad":"{}"}}"#, "r".repeat(100), "x".repeat(INBOX_MAX_BODY));
    vault_deposit(&mut vault, event("device.unlinked", &odd), None).await;
    s.poll(&mut store).await.unwrap();
    assert_eq!(s.unlinked(), Some(""), "a reason out of bounds is kept empty");
    // It came first in that batch (still linked then); the next takes it.
    s.poll(&mut store).await.unwrap();
    assert_eq!(vault.device_waiting(), 0, "the large rotation is acked and dropped once removed");
    let kinds: Vec<_> = s.pending_inbox().iter().map(|e| (e.kind.as_str(), e.body.as_str())).collect();
    assert_eq!(kinds, [("device.unlinked", r#"{"reason":""}"#)]);
    vault_deposit(&mut vault, event("identity.rotate", "{}"), None).await;
    assert!(s.poll(&mut store).await.unwrap().is_empty());
    assert_eq!((vault.device_waiting(), s.pending_inbox().len()), (0, 1));
}

/// An inbox entry that no longer parses is dropped on load, and the keys
/// are kept.
#[tokio::test]
async fn a_broken_inbox_entry_is_dropped_on_load() {
    let (relay, mut vault, faults, mut store) = paired().await;
    {
        let mut s = session(&relay, &faults, &mut store, Ticking::new());
        vault_deposit(&mut vault, event("identity.rotate", "{}"), None).await;
        vault_deposit(&mut vault, event("identity.rotate", r#"{"n":2}"#), None).await;
        s.poll(&mut store).await.unwrap();
        assert_eq!(s.pending_inbox().len(), 2);
    }
    let mut v: serde_json::Value = serde_json::from_slice(&store.inner.data.clone().unwrap()).unwrap();
    v["inbox"][0]["inner"] = serde_json::json!("not an inner");
    store.inner.data = Some(Zeroizing::new(serde_json::to_vec(&v).unwrap()));
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    assert_eq!(s.pending_inbox().len(), 1);
    assert_eq!(s.pending_inbox()[0].body.as_str(), r#"{"n":2}"#);
    s.send(&mut store, "test.after", "{}", false).await.unwrap();
    assert_eq!(vault_receive(&mut vault).await.kind, "test.after", "the keys survived");
}

/// #81: a failed collect makes the next poll wait (full jitter, doubling
/// to the cap), and a collect that works resets it. Time is paused, so the
/// waits pass at once.
#[tokio::test(start_paused = true)]
async fn failed_collects_back_off_and_a_good_one_resets() {
    let (relay, _vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    faults.lock().unwrap().collects = 6;
    let start = tokio::time::Instant::now();
    for _ in 0..6 {
        assert!(s.poll(&mut store).await.is_err());
    }
    assert_eq!(s.collect_backoff, COLLECT_MAX_BACKOFF, "1, 2, 4, 8, 16, then the 30 s cap");
    assert!(start.elapsed() <= std::time::Duration::from_secs(1 + 2 + 4 + 8 + 16 + 25), "each wait within its cap");
    assert!(start.elapsed() > std::time::Duration::ZERO, "the polls did wait");
    s.poll(&mut store).await.unwrap();
    assert_eq!(s.collect_backoff, COLLECT_BACKOFF, "the relay answers again");
}

/// #86: deposits held only by this session's own backoff after transport
/// failures go out as soon as a collect works again, not minutes later.
#[tokio::test]
async fn an_outbox_held_after_transport_failures_goes_out_when_the_relay_answers() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    s.outbox_backoff = TimeDelta::minutes(5);
    faults.lock().unwrap().temporary = 1;
    let id = s.send(&mut store, "test.ping", "{}", false).await.unwrap();
    assert_eq!(s.outbox_len(), 1, "held for minutes by the backoff");
    s.poll(&mut store).await.unwrap();
    assert_eq!(s.outbox_len(), 0, "the relay answered: sent at once");
    assert_eq!(s.outbox_backoff, OUTBOX_BACKOFF);
    assert_eq!(vault_receive(&mut vault).await.id, id);
}

/// #81 review: a hold from the relay's own answer (a 5xx, a 429 with no
/// retry_after) is kept after a good collect: the outbox backoff still
/// spaces those out; only an unreachable relay's hold is released.
#[tokio::test]
async fn a_hold_from_the_relays_own_answer_survives_a_good_collect() {
    for (server, limited) in [(1, 0), (0, 1)] {
        let (relay, mut vault, faults, mut store) = paired().await;
        let mut s = session(&relay, &faults, &mut store, Ticking::new());
        s.outbox_backoff = TimeDelta::minutes(5);
        {
            let mut f = faults.lock().unwrap();
            f.server_errors = server;
            f.rate_limited = limited;
        }
        s.send(&mut store, "test.ping", "{}", false).await.unwrap();
        let tried = faults.lock().unwrap().deposits_seen;
        s.poll(&mut store).await.unwrap();
        assert_eq!(faults.lock().unwrap().deposits_seen, tried, "held: not tried again on the good collect");
        assert_eq!(s.outbox_len(), 1);
        s.hold_until = Utc::now() - TimeDelta::seconds(1);
        s.poll(&mut store).await.unwrap();
        assert_eq!(s.outbox_len(), 0);
        assert_eq!(vault_receive(&mut vault).await.kind, "test.ping");
    }
}

/// #81 review: the wait after a failed collect stays within its cap, keeps
/// to what the relay asked for, and leaves out the time already spent.
#[test]
fn the_collect_wait_is_bounded() {
    use std::time::Duration as D;
    for _ in 0..200 {
        let w = collect_wait(D::from_secs(8), D::ZERO, D::ZERO);
        assert!(w <= D::from_secs(8));
    }
    assert_eq!(collect_wait(D::from_secs(8), D::from_secs(8), D::ZERO), D::from_secs(8), "the relay's retry_after");
    assert_eq!(collect_wait(D::from_secs(8), D::from_secs(8), D::from_secs(3)), D::from_secs(5), "less the time spent");
    assert_eq!(collect_wait(D::from_secs(8), D::from_secs(8), D::from_secs(20)), D::ZERO);
    let seen: std::collections::HashSet<_> = (0..50).map(|_| collect_wait(D::from_secs(8), D::ZERO, D::ZERO)).collect();
    assert!(seen.len() > 1, "jittered");
}

/// #86 (lead review): after the relay was out of reach, the first collect
/// that works doesn't long-poll, so a held deposit goes out at once, not a
/// long-poll (25 s) later. The fake relay long-polls here, in paused time.
#[tokio::test(start_paused = true)]
async fn after_a_failed_collect_the_next_one_is_a_probe() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store, Ticking::new());
    {
        let mut f = faults.lock().unwrap();
        f.temporary = 1;
        f.collects = 1;
        f.long_poll = true;
    }
    let id = s.send(&mut store, "test.ping", "{}", false).await.unwrap();
    assert_eq!(s.outbox_len(), 1, "held");
    assert!(s.poll(&mut store).await.is_err(), "the relay still out of reach");
    let back = tokio::time::Instant::now();
    s.poll(&mut store).await.unwrap();
    assert!(back.elapsed() < std::time::Duration::from_secs(5), "no long-poll before the deposit");
    assert_eq!(s.outbox_len(), 0, "sent on the first good collect");
    assert_eq!(vault_receive(&mut vault).await.id, id);
    assert!(!s.probe_next, "long-polls again from here");
}
