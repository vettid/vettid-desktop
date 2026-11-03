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
