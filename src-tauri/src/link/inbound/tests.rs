use super::*;
use chrono::Utc;
use vettid_vms::envelope::{Response, Status};

fn inner(kind: &str, body: &str) -> Inner {
    Inner {
        id: "01J0000000000000000000000A".into(),
        kind: kind.into(),
        ts: Utc::now(),
        seq: Some(1),
        response: None,
        exp: None,
        body: Zeroizing::new(body.into()),
    }
}

const MSG: &str = r#"{"connection_id":"c-1","message_id":"m-1","direction":"in","text":"hello there","sent_at":"2026-11-25T10:00:00.000Z","delivered":true,"read":false}"#;

#[test]
fn a_message_reads_as_the_spec_says() {
    let Some(Ok(Inbound::MessageNew(m))) = parse(&inner(TYPE_MESSAGE_NEW, MSG)) else { panic!("not read") };
    assert_eq!((m.connection_id.as_str(), m.message_id.as_str(), m.direction), ("c-1", "m-1", Direction::In));
    assert_eq!((m.text.as_str(), m.delivered, m.read, m.attachment.is_none()), ("hello there", true, false, true));
}

/// §10.5.1: a desktop's device view has no `thumb` and no `name`; they
/// are never passed on, even if a vault sends them.
#[test]
fn an_attachment_loses_thumb_and_name() {
    let body = r#"{"connection_id":"c-1","message_id":"m-2","direction":"in","text":"","sent_at":"2026-11-25T10:00:00Z","delivered":true,"read":false,
        "attachment":{"att_id":"a-1","kind":"photo","mime":"image/jpeg","size":1000,"width":10,"height":20,"state":"stored","thumb":"AAAA","name":"beach.jpg"}}"#;
    let Some(Ok(i)) = parse(&inner(TYPE_MESSAGE_NEW, body)) else { panic!("not read") };
    let json = serde_json::to_string(&i).unwrap();
    assert!(json.contains("\"att_id\":\"a-1\"") && json.contains("\"state\":\"stored\""));
    assert!(!json.contains("thumb") && !json.contains("beach") && !json.contains("AAAA"), "{json}");
}

#[test]
fn a_bad_message_is_unreadable() {
    for body in [
        "not json",
        "[]",
        r#"{"connection_id":"c-1","message_id":"m-1","direction":"sideways","text":"x","sent_at":"2026-11-25T10:00:00Z","delivered":true,"read":false}"#,
        r#"{"connection_id":"c-1","message_id":"m-1","direction":"in","sent_at":"2026-11-25T10:00:00Z","delivered":true,"read":false}"#,
        r#"{"connection_id":"","message_id":"m-1","direction":"in","text":"x","sent_at":"2026-11-25T10:00:00Z","delivered":true,"read":false}"#,
        r#"{"connection_id":"c-1","message_id":"m-1","direction":"in","text":"x","sent_at":"yesterday","delivered":true,"read":false}"#,
        r#"{"connection_id":"c-1","message_id":"m-1","direction":"in","text":"x","sent_at":"2026-11-25T10:00:00Z","delivered":"yes","read":false}"#,
        r#"{"connection_id":"c-1","message_id":"m-1","direction":"in","text":"x","sent_at":"2026-11-25T10:00:00Z","delivered":true,"read":false,"attachment":{"att_id":"a"}}"#,
        // Empty text is an attachment without a caption, never alone.
        r#"{"connection_id":"c-1","message_id":"m-1","direction":"in","text":"","sent_at":"2026-11-25T10:00:00Z","delivered":true,"read":false}"#,
        r#"{"connection_id":"c-1","message_id":"m-1","direction":"in","text":"","sent_at":"2026-11-25T10:00:00Z","delivered":true,"read":false,"attachment":null}"#,
    ] {
        assert_eq!(parse(&inner(TYPE_MESSAGE_NEW, body)), Some(Err(Unreadable)), "{body}");
    }
}

#[test]
fn sync_events_of_the_followed_kinds_pass_others_dont() {
    let Some(Ok(Inbound::Sync(e))) = parse(&inner(TYPE_SYNC_EVENT, r#"{"kind":"message.receipt","connection_id":"c-1","message_id":"m-1","receipt":"read"}"#)) else {
        panic!("not read")
    };
    assert_eq!(e.kind, "message.receipt");
    assert_eq!(e.members.get("receipt").and_then(|v| v.as_str()), Some("read"));
    assert!(!e.members.contains_key("kind"));
    assert_eq!(parse(&inner(TYPE_SYNC_EVENT, r#"{"kind":"wallet.changed","wallet_id":"w","version":2}"#)), None);
    assert_eq!(parse(&inner(TYPE_SYNC_EVENT, r#"{"connection_id":"c-1"}"#)), Some(Err(Unreadable)));
    assert_eq!(parse(&inner(TYPE_SYNC_EVENT, "{")), Some(Err(Unreadable)));
}

#[test]
fn responses_and_other_types_are_not_ours() {
    let mut r = inner(TYPE_MESSAGE_NEW, MSG);
    r.response = Some(Response { re: "x".into(), status: Status::Ok });
    assert_eq!(parse(&r), None);
    assert_eq!(parse(&inner("vault.held", "{}")), None);
}

/// Plaintext never reaches Debug (and so no log line).
#[test]
fn debug_leaves_the_text_out() {
    let Some(Ok(i)) = parse(&inner(TYPE_MESSAGE_NEW, MSG)) else { panic!("not read") };
    let d = format!("{i:?} {:?}", InboundBatch { messages: vec![i.clone()], resync: false });
    assert!(!d.contains("hello there"), "{d}");
    assert!(d.contains("text_len: 11"), "{d}");
}

#[test]
fn the_queue_keeps_order_caps_and_asks_for_a_resync() {
    let mut q = Queue::default();
    assert!(q.is_empty());
    q.take(&inner(TYPE_MESSAGE_NEW, MSG));
    q.take(&inner("vault.status", "{}"));
    q.take(&inner(TYPE_SYNC_EVENT, r#"{"kind":"message.read","connection_id":"c-1","message_id":"m-1"}"#));
    let b = q.drain();
    assert_eq!(b.messages.len(), 2);
    assert!(matches!(b.messages[0], Inbound::MessageNew(_)) && matches!(b.messages[1], Inbound::Sync(_)));
    assert!(!b.resync && q.is_empty());
    // An unreadable one asks for a resync.
    q.take(&inner(TYPE_MESSAGE_NEW, "{"));
    assert_eq!(q.drain(), InboundBatch { messages: vec![], resync: true });
    // Past the cap the oldest go.
    for i in 0..MAX_QUEUED + 3 {
        let body = MSG.replace("m-1", &format!("m-{i}"));
        q.take(&inner(TYPE_MESSAGE_NEW, &body));
    }
    let b = q.drain();
    assert_eq!(b.messages.len(), MAX_QUEUED);
    assert!(b.resync);
    let Inbound::MessageNew(first) = &b.messages[0] else { panic!() };
    assert_eq!(first.message_id, "m-3");
    // Cleared: nothing kept, and the views read again.
    q.take(&inner(TYPE_MESSAGE_NEW, MSG));
    q.clear();
    assert_eq!(q.drain(), InboundBatch { messages: vec![], resync: true });
}

/// The frontend gets the spec's shapes: `type` and `body`.
#[test]
fn the_wire_shape_for_the_frontend() {
    let Some(Ok(i)) = parse(&inner(TYPE_MESSAGE_NEW, MSG)) else { panic!() };
    let v: serde_json::Value = serde_json::to_value(InboundBatch { messages: vec![i], resync: false }).unwrap();
    assert_eq!(v["messages"][0]["type"], "message.new");
    assert_eq!(v["messages"][0]["body"]["direction"], "in");
    assert_eq!(v["messages"][0]["body"]["text"], "hello there");
    assert_eq!(v["resync"], false);
}

/// Only each kind's members pass, and a string member is bounded.
#[test]
fn sync_members_are_the_kinds_own() {
    let body = r#"{"kind":"connection.changed","connection_id":"c-1","version":3,"extra":"x","note":{"a":1}}"#;
    let Some(Ok(Inbound::Sync(e))) = parse(&inner(TYPE_SYNC_EVENT, body)) else { panic!() };
    assert_eq!(e.members.len(), 2, "{:?}", e.members);
    assert!(e.members.contains_key("connection_id") && e.members.contains_key("version"));
    let long = format!(r#"{{"kind":"message.read","connection_id":"{}","message_id":"m"}}"#, "c".repeat(MAX_MEMBER_LEN + 1));
    assert_eq!(parse(&inner(TYPE_SYNC_EVENT, &long)), Some(Err(Unreadable)));
    let nested = r#"{"kind":"message.read","connection_id":{"x":1},"message_id":"m"}"#;
    assert_eq!(parse(&inner(TYPE_SYNC_EVENT, nested)), Some(Err(Unreadable)));
}

/// Bounds and types: text up to 16 KiB, ids and fields bounded; a sync
/// member of the wrong type is unreadable, a null one absent.
#[test]
fn bounds_and_types() {
    let with_text = |t: &str| MSG.replace("hello there", t);
    assert!(matches!(parse(&inner(TYPE_MESSAGE_NEW, &with_text(&"x".repeat(MAX_TEXT_LEN)))), Some(Ok(_))));
    assert_eq!(parse(&inner(TYPE_MESSAGE_NEW, &with_text(&"x".repeat(MAX_TEXT_LEN + 1)))), Some(Err(Unreadable)));
    assert_eq!(parse(&inner(TYPE_MESSAGE_NEW, &MSG.replace("m-1", &"m".repeat(MAX_ID_LEN + 1)))), Some(Err(Unreadable)));
    let att = |extra: &str| {
        format!(
            r#"{{"connection_id":"c","message_id":"m","direction":"in","text":"","sent_at":"2026-11-25T10:00:00Z","delivered":true,"read":false,"attachment":{{"att_id":"a","kind":"photo","size":1,"width":1,"height":1,"state":"stored"{extra}}}}}"#
        )
    };
    assert!(matches!(parse(&inner(TYPE_MESSAGE_NEW, &att(r#","mime":null"#))), Some(Ok(_))));
    assert_eq!(parse(&inner(TYPE_MESSAGE_NEW, &att(r#","mime":7"#))), Some(Err(Unreadable)));
    let long_reason = format!(r#","reason":"{}""#, "r".repeat(MAX_FIELD_LEN + 1));
    assert_eq!(parse(&inner(TYPE_MESSAGE_NEW, &att(&long_reason))), Some(Err(Unreadable)));
    assert_eq!(parse(&inner(TYPE_SYNC_EVENT, r#"{"kind":"connection.changed","connection_id":"c","version":"3"}"#)), Some(Err(Unreadable)));
    assert_eq!(parse(&inner(TYPE_SYNC_EVENT, r#"{"kind":"connection.changed","connection_id":7}"#)), Some(Err(Unreadable)));
    let null_reason = r#"{"kind":"message.attachment","connection_id":"c","message_id":"m","state":"failed","reason":null}"#;
    let Some(Ok(Inbound::Sync(e))) = parse(&inner(TYPE_SYNC_EVENT, null_reason)) else { panic!() };
    assert!(!e.members.contains_key("reason"));
    assert_eq!(parse(&inner(TYPE_SYNC_EVENT, r#"{"kind":"owner_check","deadline":"x"}"#)), None, "not followed");
}
