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
/// any more, and s-2 is current: the request is released (owner decision
/// 2026-11-03; the `// SPEC:` comment in `settle`).
#[tokio::test]
async fn spec_question_named_end_of_a_replaced_session_is_moot() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    record_end(&mut s, &mut store, Some("s-1"), 0);
    let vault_side = async {
        ends(&mut vault, END_ATTEMPTS, r#"{"session_id":"s-1"}"#).await;
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-2")))).await;
    };
    let (got, ()) = tokio::join!(a.settle(&mut s, &mut store), vault_side);
    assert_eq!(got, Ok(Settled::Moot));
    assert_eq!(a.current().map(|c| c.session_id.as_str()), Some("s-2"));
    assert!(a.active_at(Utc::now()));
    assert!(s.access_end().is_none());
    assert_eq!(vault.waiting(), 0, "s-2 isn't ended");
}

/// Store an unanswered end (as if sent `attempts` times); returns its id.
fn record_end(s: &mut S, store: &mut MemStore, session_id: Option<&str>, attempts: u32) -> String {
    let id = s.new_id().unwrap();
    s.set_access_end(store, Some(PendingEnd { id: id.clone(), session_id: session_id.map(str::to_string), attempts })).unwrap();
    id
}

/// Take `n` ends, checking their body; returns them.
async fn ends(vault: &mut Vault, n: u32, body: &str) -> Vec<Inner> {
    let mut out = Vec::new();
    for _ in 0..n {
        let e = receive(vault).await;
        assert_eq!((e.kind.as_str(), e.body.as_str()), (TYPE_END, body));
        out.push(e);
    }
    out
}

/// An unnamed end, unanswered, while vault.status shows s-1: sent again
/// under a new id naming s-1 (§6.8 "If it names a session", read as
/// vault.status's); answered, the end is done.
#[tokio::test]
async fn an_unanswered_unnamed_end_is_sent_again_naming_the_session() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let vault_side = async {
        let first = ends(&mut vault, END_ATTEMPTS, "{}").await;
        assert!(first.iter().all(|e| e.id == first[0].id), "retries reuse the id");
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))).await;
        let again = answer(&mut vault, TYPE_END, Status::Ok, "{}").await;
        assert_eq!(again.body.as_str(), r#"{"session_id":"s-1"}"#);
        assert_ne!(again.id, first[0].id, "a new id");
    };
    let (got, ()) = tokio::join!(a.end(&mut s, &mut store, None), vault_side);
    assert_eq!(got, Ok(EndOutcome::Ended));
    assert!(!a.active_at(Utc::now()), "s-1 wasn't taken as current while its end waited");
    assert!(s.access_end().is_none());
}

/// A second end() finding an unnamed end with its attempts spent doesn't
/// just read vault.status: it sends the end again, naming the session.
#[tokio::test]
async fn a_second_end_after_the_attempts_are_spent() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    record_end(&mut s, &mut store, None, END_ATTEMPTS);
    let vault_side = async {
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))).await;
        answer(&mut vault, TYPE_END, Status::Ok, "{}").await
    };
    let (got, end) = tokio::join!(a.end(&mut s, &mut store, None), vault_side);
    assert_eq!(got, Ok(EndOutcome::Ended));
    assert_eq!(end.body.as_str(), r#"{"session_id":"s-1"}"#);
    assert!(s.access_end().is_none());
}

/// While an unnamed end waits, a new end (named or not) is that end again,
/// under its id.
#[tokio::test]
async fn end_reuses_a_pending_unnamed_end() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let id = record_end(&mut s, &mut store, None, 0);
    let (got, end) = tokio::join!(a.end(&mut s, &mut store, Some("s-1")), answer(&mut vault, TYPE_END, Status::Ok, "{}"));
    assert_eq!(got, Ok(EndOutcome::Ended));
    assert_eq!((end.id.as_str(), end.body.as_str()), (id.as_str(), "{}"));
}

/// An unnamed end replaces a waiting named one, under a new id.
#[tokio::test]
async fn an_unnamed_end_replaces_a_named_one() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let id = record_end(&mut s, &mut store, Some("s-1"), 1);
    let (got, end) = tokio::join!(a.end(&mut s, &mut store, None), answer(&mut vault, TYPE_END, Status::Ok, "{}"));
    assert_eq!(got, Ok(EndOutcome::Ended));
    assert_ne!(end.id, id);
    assert_eq!(end.body.as_str(), "{}");
}

/// An `ok` answer with a body other than `{}`: the end counts as answered
/// (the request may go), and the body is reported malformed.
#[tokio::test]
async fn an_ok_end_answer_with_a_malformed_body() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let (got, _) = tokio::join!(a.end(&mut s, &mut store, None), answer(&mut vault, TYPE_END, Status::Ok, r#"{"ended":true}"#));
    assert_eq!(got, Err(AccessError::Malformed));
    assert!(s.access_end().is_none());
    assert!(!a.active_at(Utc::now()));
}

/// The resent named end gets no answer either, and vault.status still
/// shows the session: EndUnconfirmed, the end still stored. A late answer
/// to the first id is ignored; one to the stored id settles it.
#[tokio::test]
async fn a_resent_end_still_unanswered() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let named = r#"{"session_id":"s-1"}"#;
    let vault_side = async {
        let first = ends(&mut vault, END_ATTEMPTS, named).await;
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))).await;
        let again = ends(&mut vault, END_ATTEMPTS, named).await;
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))).await;
        (first[0].clone(), again[0].clone())
    };
    let (got, (first, again)) = tokio::join!(a.end(&mut s, &mut store, Some("s-1")), vault_side);
    assert_eq!(got, Err(AccessError::EndUnconfirmed));
    assert_ne!(first.id, again.id);
    let stored = s.access_end().cloned().unwrap();
    assert_eq!((stored.id.as_str(), stored.session_id.as_deref(), stored.attempts), (again.id.as_str(), Some("s-1"), END_ATTEMPTS));
    assert_eq!(vault.waiting(), 0, "no request");

    // A late answer to the first id: not the stored end's, ignored.
    deposit(&mut vault, response(&first, Status::Ok, "{}")).await;
    let msgs = s.poll(&mut store).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(a.observe(&mut s, &mut store, &msgs[0]), Ok(None));
    assert_eq!(s.access_end(), Some(&stored), "still waiting");

    // One to the stored id settles it.
    deposit(&mut vault, response(&again, Status::Ok, "{}")).await;
    let msgs = s.poll(&mut store).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(a.observe(&mut s, &mut store, &msgs[0]), Ok(Some(AccessEvent::EndAnswered)));
    assert!(s.access_end().is_none());
}

/// An unanswered end holds the request back, also across a restart; once
/// vault.status reads null, it goes.
#[tokio::test]
async fn an_unanswered_end_holds_the_request_across_a_restart() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let named = r#"{"session_id":"s-1"}"#;
    let vault_side = async {
        ends(&mut vault, END_ATTEMPTS, "{}").await;
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))).await;
        ends(&mut vault, END_ATTEMPTS, named).await;
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))).await;
    };
    let (got, ()) = tokio::join!(a.end(&mut s, &mut store, None), vault_side);
    assert_eq!(got, Err(AccessError::EndUnconfirmed));
    assert!(!a.active_at(Utc::now()), "a session its own end will end isn't current");
    // The app asks again: still held back (the end goes again), and no
    // request goes out.
    let vault_side = async {
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))).await;
        ends(&mut vault, END_ATTEMPTS, named).await;
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))).await;
    };
    let (got, ()) = tokio::join!(a.request(&mut s, &mut store, None), vault_side);
    assert_eq!(got, Err(AccessError::EndUnconfirmed));
    assert_eq!(vault.waiting(), 0, "no request");
    let stored = s.access_end().cloned().unwrap();
    assert_eq!((stored.session_id.as_deref(), stored.attempts), (Some("s-1"), END_ATTEMPTS));

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
    let id = record_end(&mut s, &mut store, None, 2);
    drop(s);
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let (got, end) = tokio::join!(a.settle(&mut s, &mut store), answer(&mut vault, TYPE_END, Status::Ok, "{}"));
    assert_eq!(got, Ok(Settled::Answered));
    assert_eq!(end.id, id);
}

/// A stored end that doesn't read is taken as an unnamed end with its
/// attempts spent, and the session says so; an old state has none.
#[tokio::test]
async fn a_malformed_stored_end() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let id = record_end(&mut s, &mut store, Some("s-1"), 2);
    drop(s);
    let json = String::from_utf8(store.data.as_ref().unwrap().to_vec()).unwrap();
    let member = format!(r#""access_end":{{"id":"{id}","session_id":"s-1","attempts":2}}"#);
    assert_eq!(json.matches(&member).count(), 1);
    let good = DeviceState::from_json(json.as_bytes()).unwrap();
    assert_eq!(good.access_end.as_ref().map(|p| p.attempts), Some(2));
    assert!(!good.access_end_unreadable);

    let old = json.replace(&format!("{member},"), "");
    let old = DeviceState::from_json(old.as_bytes()).unwrap();
    assert!(old.access_end.is_none() && !old.access_end_unreadable, "an old state has none");

    for bad in [
        format!(r#""access_end":{{"id":"{id}","session_id":"s-1","attempts":2,"extra":1}}"#),
        r#""access_end":{"id":"","attempts":2}"#.to_string(),
        format!(r#""access_end":{{"id":"{id}","session_id":"","attempts":2}}"#),
        r#""access_end":null"#.to_string(),
        format!(r#""access_end":{{"id":"{id}","attempts":256}}"#),
        format!(r#""access_end":{{"id":"{id}","session_id":7,"attempts":1}}"#),
        format!(r#""access_end":{{"id":"{id}"}}"#),
    ] {
        let st = DeviceState::from_json(json.replace(&member, &bad).as_bytes()).unwrap();
        let p = st.access_end.as_ref().unwrap();
        assert_eq!((p.session_id.as_deref(), p.attempts), (None, END_ATTEMPTS), "{bad}");
        assert!(!p.id.is_empty() && st.access_end_unreadable, "{bad}");
    }

    // It still holds the request back, and settles through vault.status.
    store.data = Some(Zeroizing::new(json.replace(&member, r#""access_end":null"#).into_bytes()));
    let mut s = session(&relay, &faults, &mut store);
    assert!(s.access_end_unreadable());
    let mut a = access();
    let vault_side = async {
        answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(None))).await;
        answer(&mut vault, TYPE_REQUEST, Status::Ok, requested_body()).await;
    };
    let (got, ()) = tokio::join!(a.request(&mut s, &mut store, None), vault_side);
    assert!(got.is_ok());
    assert!(s.access_end().is_none());
}

/// `read_status`, answered with no session stamped a minute ago (so that
/// what the test sends next is newer): the baseline a grant needs to be
/// reported active.
async fn baseline(a: &mut Access, s: &mut S, store: &mut MemStore, vault: &mut Vault) {
    let vault_side = async {
        let req = receive(vault).await;
        assert_eq!(req.kind, TYPE_STATUS);
        let mut r = response(&req, Status::Ok, r#"{"session":null}"#);
        r.ts = Utc::now() - TimeDelta::minutes(1);
        deposit(vault, r).await;
    };
    let (st, ()) = tokio::join!(a.read_status(s, store), vault_side);
    assert_eq!(st, Ok(StatusSession::None));
}

/// Grants replace the session; a denied renewal leaves it running; an end
/// stops it; and it expires on its own, a margin early.
#[tokio::test]
async fn grants_denials_ends_and_expiry() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    baseline(&mut a, &mut s, &mut store, &mut vault).await;
    let now = Utc::now();
    let exp = now + TimeDelta::minutes(10);
    let g = a.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-1", exp))).unwrap();
    assert!(matches!(g, Some(AccessEvent::Granted(ref x)) if x.session_id == "s-1"));
    assert!(a.active_at(now));
    // Expiry: active until EXPIRY_MARGIN before expires_at (10 minutes left
    // when granted: the full margin).
    let edge = exp - EXPIRY_MARGIN;
    assert!(a.active_at(edge - TimeDelta::milliseconds(1)) && !a.active_at(edge) && !a.active_at(exp));
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

/// The clock margin is at most a quarter of what was left when the vault
/// named the session: a 60 s session is active for 45 s, a 2-minute one
/// for 90 s, a 1-hour one until 60 s before its end; each ends before its
/// `expires_at`. A vault.status re-read recomputes it.
#[tokio::test]
async fn the_margin_fits_the_session() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    for (len, margin) in [(60, 15), (120, 30), (3600, 60)] {
        let mut a = access();
        baseline(&mut a, &mut s, &mut store, &mut vault).await;
        let t0 = parse_ts(&format_ts(Utc::now())).unwrap();
        let exp = t0 + TimeDelta::seconds(len);
        let mut g = event(TYPE_GRANTED, &session_body("s-1", exp));
        g.ts = t0;
        a.observe(&mut s, &mut store, &g).unwrap();
        let edge = exp - TimeDelta::seconds(margin);
        assert!(a.active_at(t0), "{len} s");
        assert!(a.active_at(edge - TimeDelta::milliseconds(1)), "{len} s: active until {margin} s before its end");
        assert!(!a.active_at(edge) && !a.active_at(exp), "{len} s: ended {margin} s early");
        assert_eq!(margin_for(a.current().unwrap(), t0), TimeDelta::seconds(margin));
    }
    // Re-read 40 s into a 60 s session: 20 s left, a 5 s margin.
    let mut a = access();
    let t0 = Utc::now();
    let exp = parse_ts(&format_ts(t0 + TimeDelta::seconds(20))).unwrap();
    let vault_side = async {
        let req = receive(&mut vault).await;
        let mut r = response(&req, Status::Ok, &format!(r#"{{"session":{}}}"#, session_body("s-1", exp)));
        r.ts = exp - TimeDelta::seconds(20);
        deposit(&mut vault, r).await;
    };
    let (st, ()) = tokio::join!(a.read_status(&mut s, &mut store), vault_side);
    assert!(st.is_ok());
    let five = exp - TimeDelta::seconds(5);
    assert!(a.active_at(five - TimeDelta::milliseconds(1)) && !a.active_at(five));
    // A session already past its end when named has no margin, and isn't
    // active.
    let past = AccessSession { session_id: "s".into(), expires_at: t0 };
    assert_eq!(margin_for(&past, t0 + TimeDelta::seconds(1)), TimeDelta::zero());
}

/// The engine keeps a request armed across a restart, so the answer to a
/// vault.status sent before it can arrive after it: it is applied, but it
/// is not the baseline. A later grant isn't reported active until this
/// Access's own read_status answers.
#[tokio::test]
async fn a_pre_restart_status_answer_is_no_baseline() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    s.send(&mut store, TYPE_STATUS, "{}", true).await.unwrap();
    drop(s); // the app stops before the answer
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let req = receive(&mut vault).await;
    deposit(&mut vault, response(&req, Status::Ok, &status_body(Some(None)))).await;
    let msgs = s.poll(&mut store).await.unwrap();
    assert_eq!(msgs.len(), 1, "the armed request's answer comes through");
    assert_eq!(a.observe(&mut s, &mut store, &msgs[0]), Ok(Some(AccessEvent::Status(StatusSession::None))));
    let exp = Utc::now() + TimeDelta::hours(1);
    a.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-1", exp))).unwrap();
    assert!(a.current().is_some());
    assert!(!a.active_at(Utc::now()), "a stale answer is no baseline");
    let (st, _) = tokio::join!(a.read_status(&mut s, &mut store), answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))));
    assert!(st.is_ok());
    assert!(a.active_at(Utc::now()));
}

/// After a start, a grant that comes before any vault.status answer (or
/// answered end) is recorded, not reported active.
#[tokio::test]
async fn a_grant_before_a_baseline_is_not_active() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    let exp = Utc::now() + TimeDelta::hours(1);
    a.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-1", exp))).unwrap();
    assert_eq!(a.current().map(|c| c.session_id.as_str()), Some("s-1"));
    assert!(!a.active_at(Utc::now()), "no baseline yet");
    let (st, _) = tokio::join!(a.read_status(&mut s, &mut store), answer(&mut vault, TYPE_STATUS, Status::Ok, status_body(Some(Some("s-1")))));
    assert!(st.is_ok());
    assert!(a.active_at(Utc::now()));

    // An answered end is a baseline too.
    let mut b = access();
    b.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-2", exp))).unwrap();
    let (got, _) = tokio::join!(b.end(&mut s, &mut store, Some("s-1")), answer(&mut vault, TYPE_END, Status::Ok, "{}"));
    assert_eq!(got, Ok(EndOutcome::Ended));
    assert!(b.active_at(Utc::now()), "s-2 is not the session ended, and the end's answer is a baseline");
}

/// What the vault said is applied in the vault's order: an older
/// vault.status answer doesn't bring back a session an end stopped.
#[tokio::test]
async fn the_vaults_order_wins() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    baseline(&mut a, &mut s, &mut store, &mut vault).await;
    let t = Utc::now();
    let mut grant = event(TYPE_GRANTED, &session_body("s-1", t + TimeDelta::hours(1)));
    grant.ts = t;
    a.observe(&mut s, &mut store, &grant).unwrap();
    assert!(a.active_at(t));
    let mut ended = event(TYPE_ENDED, r#"{"reason":"ended"}"#);
    ended.ts = t + TimeDelta::seconds(2);
    a.observe(&mut s, &mut store, &ended).unwrap();
    let mut stale = response(&event(TYPE_STATUS, "{}"), Status::Ok, &status_body(Some(Some("s-1"))));
    stale.ts = t + TimeDelta::seconds(1);
    assert!(matches!(a.observe(&mut s, &mut store, &stale), Ok(Some(AccessEvent::Status(_)))));
    assert!(!a.active_at(t), "the older answer is ignored");
}

/// At the same `ts`, "no session" wins over a grant, in either order of
/// arrival.
#[tokio::test]
async fn at_the_same_ts_the_end_wins() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let t = Utc::now();
    let mut grant = event(TYPE_GRANTED, &session_body("s-1", t + TimeDelta::hours(1)));
    grant.ts = t;
    let mut ended = event(TYPE_ENDED, r#"{"reason":"ended"}"#);
    ended.ts = t;
    let mut null = response(&event(TYPE_STATUS, "{}"), Status::Ok, &status_body(Some(None)));
    null.ts = t;
    for (first, second) in [(&grant, &ended), (&ended, &grant), (&grant, &null), (&null, &grant)] {
        let mut a = access();
        baseline(&mut a, &mut s, &mut store, &mut vault).await;
        a.observe(&mut s, &mut store, first).unwrap();
        a.observe(&mut s, &mut store, second).unwrap();
        assert!(!a.active_at(t), "{} then {}", first.kind, second.kind);
    }
    // Two grants at the same ts: the later to arrive stands.
    let mut a = access();
    baseline(&mut a, &mut s, &mut store, &mut vault).await;
    let mut other = event(TYPE_GRANTED, &session_body("s-2", t + TimeDelta::hours(1)));
    other.ts = t;
    a.observe(&mut s, &mut store, &grant).unwrap();
    a.observe(&mut s, &mut store, &other).unwrap();
    assert_eq!(a.current().unwrap().session_id, "s-2");
}

/// A session event that doesn't check out drops the session (fail
/// secure), and so does an unreadable vault.status.
#[tokio::test]
async fn malformed_messages_drop_the_session() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    baseline(&mut a, &mut s, &mut store, &mut vault).await;
    let exp = Utc::now() + TimeDelta::hours(1);
    a.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-1", exp))).unwrap();
    assert!(a.active_at(Utc::now()));
    assert_eq!(a.observe(&mut s, &mut store, &event(TYPE_ENDED, r#"{"reason":"paused"}"#)), Err(AccessError::Malformed));
    assert!(!a.active_at(Utc::now()));
    a.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-2", exp))).unwrap();
    assert!(a.active_at(Utc::now()));
    let bad = response(&event(TYPE_STATUS, "{}"), Status::Ok, r#"{"session":{"session_id":"s-2"}}"#);
    assert_eq!(a.observe(&mut s, &mut store, &bad), Err(AccessError::Malformed));
    assert!(!a.active_at(Utc::now()));
}

/// While an end that names no session waits, a grant doesn't make a
/// session current: that end ends it.
#[tokio::test]
async fn a_grant_while_an_end_waits() {
    let (relay, mut vault, faults, mut store) = paired().await;
    let mut s = session(&relay, &faults, &mut store);
    let mut a = access();
    baseline(&mut a, &mut s, &mut store, &mut vault).await;
    record_end(&mut s, &mut store, None, END_ATTEMPTS);
    a.observe(&mut s, &mut store, &event(TYPE_GRANTED, &session_body("s-1", Utc::now() + TimeDelta::hours(1)))).unwrap();
    assert!(!a.active_at(Utc::now()));
}

/// `Debug` shows only the start of ids, and the vault's code filtered.
#[test]
fn debug_hides_ids_and_filters_vault_text() {
    let s = AccessSession { session_id: "01JB2Z6V9K3M4N5P6Q7R8S9T0Z".into(), expires_at: Utc::now() };
    let d = format!("{s:?}");
    assert!(d.contains("01JB2Z..") && !d.contains("01JB2Z6V9K"), "{d}");
    let p = PendingEnd { id: "01JB2Z6V9K3M4N5P6Q7R8S9T0Z".into(), session_id: Some("abcdefghij".into()), attempts: 1 };
    let d = format!("{p:?}");
    assert!(d.contains("abcdef..") && !d.contains("abcdefg") && !d.contains("01JB2Z6V"), "{d}");
    let e = format!("{:?}", AccessError::Vault("bad\ncode\u{1b}[31m".into()));
    assert!(!e.contains('\n') && !e.contains('\u{1b}'), "{e}");
}
