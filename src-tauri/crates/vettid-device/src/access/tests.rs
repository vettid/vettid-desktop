//! Access sessions against the in-memory relay and the test vault, from a
//! real pairing.

use std::sync::{Arc, Mutex};

use chrono::{TimeDelta, Utc};
use vettid_relay::token::Token;
use vettid_vms::envelope::{format_ts, new_ulid, Envelope, Inner, Response, Status};
use zeroize::Zeroizing;

use super::*;
use crate::store::{DeviceState, MemStore};
use crate::testutil::*;

type S = Session<Mem, Ticking>;

async fn paired() -> (Arc<Mutex<Relay>>, Vault, Arc<Mutex<Faults>>, MemStore) {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    let body = vault.paired_body(&vault.device_relay_key());
    vault.send("device.paired", body).await;
    pairing.wait_for_approval(&mut store).await.unwrap();
    (relay, vault, faults, store)
}

fn session(relay: &Arc<Mutex<Relay>>, faults: &Arc<Mutex<Faults>>, store: &mut MemStore) -> S {
    Session::open(store, mem(relay, faults), Ticking::new()).unwrap().unwrap()
}

fn access() -> Access {
    Access::new()
}

/// What the desktop sent, opened by the vault.
async fn receive(vault: &mut Vault) -> Inner {
    let m = vault.next().await;
    vault.handshake.as_mut().unwrap().1.open(&Envelope::parse(&m.payload).unwrap()).unwrap()
}

fn event(kind: &str, body: &str) -> Inner {
    Inner { id: new_ulid(Utc::now()).unwrap(), kind: kind.into(), ts: Utc::now(), seq: None, response: None, exp: None, body: Zeroizing::new(body.into()) }
}

fn response(to: &Inner, status: Status, body: &str) -> Inner {
    let mut r = event(&to.kind, body);
    r.response = Some(Response { re: to.id.clone(), status });
    r
}

fn error(code: &str) -> Status {
    Status::Error { code: code.into(), message: None }
}

async fn deposit(vault: &mut Vault, mut inner: Inner) {
    let env = vault.handshake.as_mut().unwrap().1.seal(&mut inner).unwrap();
    let to = vault.device_mailbox();
    vault.mem.deposit(URL, &to, &Token::from_received("x".into()), &env).await.unwrap();
}

/// Receive one message of `kind` and answer it.
async fn answer(vault: &mut Vault, kind: &str, status: Status, body: impl AsRef<str>) -> Inner {
    let req = receive(vault).await;
    assert_eq!(req.kind, kind);
    deposit(vault, response(&req, status, body.as_ref())).await;
    req
}

fn session_body(id: &str, exp: DateTime<Utc>) -> String {
    format!(r#"{{"session_id":"{id}","expires_at":"{}"}}"#, format_ts(exp))
}

fn status_body(session: Option<Option<&str>>) -> String {
    let exp = Utc::now() + TimeDelta::minutes(10);
    match session {
        None => r#"{"vault_id":"vault-1","state_seq":3}"#.into(),
        Some(None) => r#"{"vault_id":"vault-1","session":null}"#.into(),
        Some(Some(id)) => format!(r#"{{"vault_id":"vault-1","session":{}}}"#, session_body(id, exp)),
    }
}

fn requested_body() -> String {
    format!(r#"{{"request_id":"r-1","exp":"{}"}}"#, format_ts(Utc::now() + TimeDelta::minutes(10)))
}

#[test]
fn status_session_is_parsed_strictly() {
    let exp = "2026-11-03T12:00:00.000Z";
    assert_eq!(parse_status(r#"{"vault_id":"v"}"#), Ok(StatusSession::Absent));
    assert_eq!(parse_status(r#"{"vault_id":"v","session":null}"#), Ok(StatusSession::None));
    let ok = parse_status(&format!(r#"{{"session":{{"session_id":"s-1","expires_at":"{exp}"}},"other":[1]}}"#)).unwrap();
    assert_eq!(ok, StatusSession::Session(AccessSession { session_id: "s-1".into(), expires_at: parse_ts(exp).unwrap() }));
    for bad in [
        format!(r#"{{"session":{{"session_id":"s-1","expires_at":"{exp}","extra":1}}}}"#),
        format!(r#"{{"session":{{"session_id":"","expires_at":"{exp}"}}}}"#),
        format!(r#"{{"session":{{"session_id":7,"expires_at":"{exp}"}}}}"#),
        r#"{"session":{"session_id":"s-1","expires_at":"2026-11-03T12:00:00Z"}}"#.into(),
        r#"{"session":{"session_id":"s-1"}}"#.into(),
        r#"{"session":"s-1"}"#.into(),
        r#"{"session":false}"#.into(),
        r#"{"session":null,"session":null}"#.into(),
        "[]".into(),
    ] {
        assert_eq!(parse_status(&bad), Err(AccessError::Malformed), "{bad}");
    }
}

#[test]
fn events_and_answers_are_parsed_strictly() {
    let exp = "2026-11-03T12:00:00.000Z";
    let granted = event(TYPE_GRANTED, &format!(r#"{{"session_id":"s-1","expires_at":"{exp}"}}"#));
    assert_eq!(parse_event(&granted), Some(Ok(AccessEvent::Granted(AccessSession { session_id: "s-1".into(), expires_at: parse_ts(exp).unwrap() }))));
    assert_eq!(parse_event(&event(TYPE_ENDED, r#"{"reason":"denied"}"#)), Some(Ok(AccessEvent::Denied)));
    assert_eq!(parse_event(&event(TYPE_ENDED, r#"{"reason":"ended"}"#)), Some(Ok(AccessEvent::Ended)));
    for (kind, body) in [
        (TYPE_GRANTED, format!(r#"{{"session_id":"s-1","expires_at":"{exp}","by":"x"}}"#)),
        (TYPE_GRANTED, r#"{"session_id":"s-1"}"#.into()),
        (TYPE_ENDED, r#"{"reason":"expired"}"#.into()),
        (TYPE_ENDED, r#"{"reason":"ended","extra":true}"#.into()),
        (TYPE_ENDED, "{}".into()),
        (TYPE_ENDED, r#"{"reason":1}"#.into()),
    ] {
        assert_eq!(parse_event(&event(kind, &body)), Some(Err(AccessError::Malformed)), "{body}");
    }
    assert_eq!(parse_event(&event("test.event", "{}")), None);
    // A response of the type is not an event.
    assert_eq!(parse_event(&response(&event(TYPE_ENDED, "{}"), Status::Ok, "{}")), None);

    let req = event(TYPE_REQUEST, "{}");
    let ok = parse_request_answer(&response(&req, Status::Ok, &format!(r#"{{"request_id":"r-1","exp":"{exp}"}}"#)));
    assert_eq!(ok, Ok(RequestOutcome::Requested { request_id: "r-1".into(), exp: parse_ts(exp).unwrap() }));
    let soon = parse_request_answer(&response(&req, error("too_soon"), &format!(r#"{{"allowed_after":"{exp}"}}"#)));
    assert_eq!(soon, Ok(RequestOutcome::TooSoon { allowed_after: parse_ts(exp).unwrap() }));
    assert_eq!(parse_request_answer(&response(&req, error("session_required"), "{}")), Err(AccessError::Vault("session_required".into())));
    for (status, body) in [
        (Status::Ok, format!(r#"{{"request_id":"r-1","exp":"{exp}","seconds":60}}"#)),
        (Status::Ok, format!(r#"{{"request_id":"","exp":"{exp}"}}"#)),
        (Status::Ok, r#"{"request_id":"r-1"}"#.into()),
        (error("too_soon"), "{}".into()),
        (error("too_soon"), r#"{"allowed_after":"soon"}"#.into()),
    ] {
        assert_eq!(parse_request_answer(&response(&req, status, &body)), Err(AccessError::Malformed), "{body}");
    }
    assert_eq!(parse_request_answer(&req), Err(AccessError::Malformed), "not a response");
}

#[tokio::test]
async fn seconds_are_checked_before_sending() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    for bad in [0, 59, 86_401, u32::MAX] {
        assert_eq!(a.request(&mut s, &mut store, Some(bad)).await, Err(AccessError::BadSeconds));
    }
    assert_eq!(vault.waiting(), 0, "nothing sent");
    for (seconds, body) in [(Some(60), r#"{"seconds":60}"#), (Some(86_400), r#"{"seconds":86400}"#), (None, "{}")] {
        let (got, req) = tokio::join!(a.request(&mut s, &mut store, seconds), answer(&mut vault, TYPE_REQUEST, Status::Ok, requested_body()));
        assert_eq!(req.body.as_str(), body);
        assert!(matches!(got, Ok(RequestOutcome::Requested { ref request_id, .. }) if request_id == "r-1"));
    }
}

#[tokio::test]
async fn too_soon_and_errors() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let after = parse_ts("2026-11-03T12:10:00.000Z").unwrap();
    let body = format!(r#"{{"allowed_after":"{}"}}"#, format_ts(after));
    let (got, _) = tokio::join!(a.request(&mut s, &mut store, None), answer(&mut vault, TYPE_REQUEST, error("too_soon"), body.clone()));
    assert_eq!(got, Ok(RequestOutcome::TooSoon { allowed_after: after }));
    let (got, _) = tokio::join!(a.request(&mut s, &mut store, None), answer(&mut vault, TYPE_REQUEST, error("owner_check_required"), "{}"));
    assert_eq!(got, Err(AccessError::Vault("owner_check_required".into())));
}

#[tokio::test]
async fn session_ids_are_checked_before_sending() {
    let (relay, vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    assert_eq!(a.end(&mut s, &mut store, Some("")).await, Err(AccessError::BadSessionId));
    let long = "s".repeat(MAX_SESSION_ID + 1);
    assert_eq!(a.end(&mut s, &mut store, Some(&long)).await, Err(AccessError::BadSessionId));
    assert_eq!(vault.waiting(), 0, "nothing sent");
    assert!(s.access_end().is_none(), "nothing recorded");
    assert!(valid_session_id("s-1") && valid_session_id(&"s".repeat(MAX_SESSION_ID)));
}

/// The vault learns the session from vault.status; an answered end
/// clears it, and only then does the request go.
#[tokio::test]
async fn an_answered_end_lets_the_request_go() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    assert!(!a.active_at(Utc::now()), "nothing known before vault.status");
    let (st, _) = tokio::join!(a.read_status(&mut s, &mut store), answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))));
    assert!(matches!(st, Ok(StatusSession::Session(ref x)) if x.session_id == "s-1"));
    assert!(a.active_at(Utc::now()));
    let (got, end) = tokio::join!(a.end(&mut s, &mut store, Some("s-1")), answer(&mut vault, TYPE_END, Status::Ok, "{}"));
    assert_eq!(got, Ok(EndOutcome::Ended));
    assert_eq!(end.body.as_str(), r#"{"session_id":"s-1"}"#);
    assert!(!a.active_at(Utc::now()));
    assert!(s.access_end().is_none());
    assert!(DeviceState::from_json(store.data.as_ref().unwrap()).unwrap().access_end.is_none(), "cleared in the store");
    let (got, _) = tokio::join!(a.request(&mut s, &mut store, None), answer(&mut vault, TYPE_REQUEST, Status::Ok, requested_body()));
    assert!(got.is_ok());
    assert_eq!(vault.waiting(), 0, "nothing else was sent");
}

/// An end answered with an error is answered: the request may go, but the
/// end is reported as failed, never as done.
#[tokio::test]
async fn an_end_answered_with_an_error() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let (got, end) = tokio::join!(a.end(&mut s, &mut store, None), answer(&mut vault, TYPE_END, error("internal"), "{}"));
    assert_eq!(got, Err(AccessError::Vault("internal".into())));
    assert_eq!(end.body.as_str(), "{}");
    assert!(s.access_end().is_none());
}

/// No answer: the same id three times (§8.6), then vault.status reads
/// `null`, and the request goes.
#[tokio::test]
async fn an_unanswered_end_then_null() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let vault_side = async {
        let mut ids = Vec::new();
        for _ in 0..END_ATTEMPTS {
            let e = receive(&mut vault).await;
            assert_eq!((e.kind.as_str(), e.body.as_str()), (TYPE_END, "{}"));
            ids.push(e.id);
        }
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(None))).await;
        ids
    };
    let (got, ids) = tokio::join!(a.end(&mut s, &mut store, None), vault_side);
    assert_eq!(got, Ok(EndOutcome::Ended), "vault.status shows it gone");
    assert!(ids.iter().all(|i| *i == ids[0]), "retries reuse the id");
    assert!(s.access_end().is_none());
    let (got, _) = tokio::join!(a.request(&mut s, &mut store, None), answer(&mut vault, TYPE_REQUEST, Status::Ok, requested_body()));
    assert!(got.is_ok());
}

/// No answer, and a vault without `session` in vault.status: the request
/// goes once the retries are spent, and the end is not called done.
#[tokio::test]
async fn an_unanswered_end_with_an_old_vault() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let vault_side = async {
        for _ in 0..END_ATTEMPTS {
            assert_eq!(receive(&mut vault).await.kind, TYPE_END);
        }
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(None)).await;
        answer(&mut vault, TYPE_REQUEST, Status::Ok, requested_body()).await;
    };
    let both = async {
        let end = a.end(&mut s, &mut store, None).await;
        let req = a.request(&mut s, &mut store, None).await;
        (end, req)
    };
    let ((end, req), ()) = tokio::join!(both, vault_side);
    assert_eq!(end, Ok(EndOutcome::Unconfirmed));
    assert!(req.is_ok());
}

/// No answer to an end that names a session vault.status still shows: sent
/// again under a new id with the same session_id.
#[tokio::test]
async fn an_unanswered_named_end_is_sent_again() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let vault_side = async {
        let mut first = None;
        for _ in 0..END_ATTEMPTS {
            let e = receive(&mut vault).await;
            assert_eq!(e.body.as_str(), r#"{"session_id":"s-1"}"#);
            first = Some(e.id);
        }
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))).await;
        let again = answer(&mut vault, TYPE_END, Status::Ok, "{}").await;
        assert_eq!(again.body.as_str(), r#"{"session_id":"s-1"}"#);
        assert_ne!(Some(again.id), first, "a new id");
    };
    let (got, ()) = tokio::join!(a.end(&mut s, &mut store, Some("s-1")), vault_side);
    assert_eq!(got, Ok(EndOutcome::Ended));
    assert!(!a.active_at(Utc::now()), "the status's s-1 wasn't taken as current while its end waited");
    assert!(s.access_end().is_none());
}

/// The end named s-1, and vault.status shows s-2: that end changes nothing
/// any more, and s-2 is current.
#[tokio::test]
async fn an_unanswered_named_end_of_a_replaced_session() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let vault_side = async {
        for _ in 0..END_ATTEMPTS {
            receive(&mut vault).await;
        }
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-2")))).await;
    };
    let (got, ()) = tokio::join!(a.settle_after_end(&mut s, &mut store, "s-1"), vault_side);
    assert_eq!(got, Ok(Settled::Moot));
    assert_eq!(a.current().map(|c| c.session_id.as_str()), Some("s-2"));
    assert!(s.access_end().is_none());
}

impl Access {
    /// Record an end of `id` without sending it, then settle.
    async fn settle_after_end(&mut self, s: &mut S, store: &mut MemStore, id: &str) -> Result<Settled, AccessError> {
        let pid = s.new_id().unwrap();
        s.set_access_end(store, Some(PendingEnd { id: pid, session_id: Some(id.into()), attempts: 0 })).unwrap();
        self.settle(s, store).await
    }
}

/// An unanswered end that names no session, while vault.status shows one:
/// the request waits, and nothing is sent for it. After a restart, the
/// stored end still holds it back; once vault.status reads null it goes.
#[tokio::test]
async fn an_unanswered_end_holds_the_request_across_a_restart() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let vault_side = async {
        for _ in 0..END_ATTEMPTS {
            receive(&mut vault).await;
        }
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))).await;
    };
    let (got, ()) = tokio::join!(a.end(&mut s, &mut store, None), vault_side);
    assert_eq!(got, Err(AccessError::EndUnconfirmed));
    assert!(!a.active_at(Utc::now()), "a session its own end will end isn't current");
    // The app asks again: still held back, and no request goes out.
    let (got, _) = tokio::join!(a.request(&mut s, &mut store, None), answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))));
    assert_eq!(got, Err(AccessError::EndUnconfirmed));
    assert_eq!(vault.waiting(), 0, "no request");
    let stored = s.access_end().cloned().unwrap();
    assert_eq!((stored.session_id.as_deref(), stored.attempts), (None, END_ATTEMPTS));

    // The app stops and starts again.
    drop(s);
    let mut s = session(&relay, &faults, &mut store);
    assert_eq!(s.access_end(), Some(&stored), "stored");
    let mut a = access();
    let vault_side = async {
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(None))).await;
        answer(&mut vault, TYPE_REQUEST, Status::Ok, requested_body()).await;
    };
    let (got, ()) = tokio::join!(a.request(&mut s, &mut store, Some(600)), vault_side);
    assert!(got.is_ok());
    assert!(s.access_end().is_none());
}

/// A restart in the middle of the retries carries on with the same id and
/// the attempts left.
#[tokio::test]
async fn a_restart_carries_on_the_retries() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    s.set_access_end(&mut store, Some(PendingEnd { id: "01JB2Z6V9K3M4N5P6Q7R8S9T0Z".into(), session_id: None, attempts: 2 })).unwrap();
    drop(s);
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let (got, end) = tokio::join!(a.settle(&mut s, &mut store), answer(&mut vault, TYPE_END, Status::Ok, "{}"));
    assert_eq!(got, Ok(Settled::Answered));
    assert_eq!(end.id, "01JB2Z6V9K3M4N5P6Q7R8S9T0Z");
}

/// A late answer to the end, collected by a poll, settles it too.
#[tokio::test]
async fn a_late_end_answer_through_poll() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let vault_side = async {
        let mut last = None;
        for _ in 0..END_ATTEMPTS {
            last = Some(receive(&mut vault).await);
        }
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))).await;
        last.unwrap()
    };
    let (got, end) = tokio::join!(a.end(&mut s, &mut store, None), vault_side);
    assert_eq!(got, Err(AccessError::EndUnconfirmed));
    deposit(&mut vault, response(&end, Status::Ok, "{}")).await;
    let msgs = s.poll(&mut store).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(a.observe(&mut s, &mut store, &msgs[0]), Ok(Some(AccessEvent::EndAnswered)));
    assert!(s.access_end().is_none());
}

/// Grants replace the session; a denied renewal leaves it running; an end
/// stops it; and it expires on its own.
#[tokio::test]
async fn grants_denials_ends_and_expiry() {
    let (relay, _vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let now = Utc::now();
    let exp = now + TimeDelta::minutes(10);
    let g = a.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-1", exp))).unwrap();
    assert!(matches!(g, Some(AccessEvent::Granted(ref x)) if x.session_id == "s-1"));
    assert!(a.active_at(now));
    // Expiry: active up to, not at, expires_at.
    assert!(a.active_at(exp - TimeDelta::milliseconds(1)) && !a.active_at(exp));
    // A renewal denied (0.77.0): s-1 runs on.
    assert_eq!(a.observe(&mut s, &mut store, &event(TYPE_ENDED, r#"{"reason":"denied"}"#)), Ok(Some(AccessEvent::Denied)));
    assert!(a.active_at(now));
    // A renewal granted: s-2 replaces it.
    a.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-2", exp + TimeDelta::hours(1)))).unwrap();
    assert_eq!(a.current().unwrap().session_id, "s-2");
    // An app ends it.
    assert_eq!(a.observe(&mut s, &mut store, &event(TYPE_ENDED, r#"{"reason":"ended"}"#)), Ok(Some(AccessEvent::Ended)));
    assert!(!a.active_at(now));
    // Not a session message.
    assert_eq!(a.observe(&mut s, &mut store, &event("test.event", "{}")), Ok(None));
}

/// What the vault said is applied in the vault's order: an older
/// vault.status answer doesn't bring back a session an end stopped.
#[tokio::test]
async fn the_vaults_order_wins() {
    let (relay, _vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let t = Utc::now();
    let mut grant = event(TYPE_GRANTED, &session_body("s-1", t + TimeDelta::hours(1)));
    grant.ts = t;
    a.observe(&mut s, &mut store, &grant).unwrap();
    let mut ended = event(TYPE_ENDED, r#"{"reason":"ended"}"#);
    ended.ts = t + TimeDelta::seconds(2);
    a.observe(&mut s, &mut store, &ended).unwrap();
    let mut stale = response(&event(TYPE_STATUS, "{}"), Status::Ok, &status_body(Some(Some("s-1"))));
    stale.ts = t + TimeDelta::seconds(1);
    assert!(matches!(a.observe(&mut s, &mut store, &stale), Ok(Some(AccessEvent::Status(_)))));
    assert!(!a.active_at(t), "the older answer is ignored");
}

/// A session event that doesn't check out drops the session (fail
/// secure), and so does an unreadable vault.status.
#[tokio::test]
async fn malformed_messages_drop_the_session() {
    let (relay, _vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let exp = Utc::now() + TimeDelta::hours(1);
    a.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-1", exp))).unwrap();
    assert_eq!(a.observe(&mut s, &mut store, &event(TYPE_ENDED, r#"{"reason":"paused"}"#)), Err(AccessError::Malformed));
    assert!(!a.active_at(Utc::now()));
    a.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-2", exp))).unwrap();
    let bad = response(&event(TYPE_STATUS, "{}"), Status::Ok, r#"{"session":{"session_id":"s-2"}}"#);
    assert_eq!(a.observe(&mut s, &mut store, &bad), Err(AccessError::Malformed));
    assert!(!a.active_at(Utc::now()));
}

/// While an end that names no session waits, a grant doesn't make a
/// session current: that end ends it.
#[tokio::test]
async fn a_grant_while_an_end_waits() {
    let (relay, _vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let pid = s.new_id().unwrap();
    s.set_access_end(&mut store, Some(PendingEnd { id: pid, session_id: None, attempts: END_ATTEMPTS })).unwrap();
    a.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-1", Utc::now() + TimeDelta::hours(1)))).unwrap();
    assert!(!a.active_at(Utc::now()));
}
