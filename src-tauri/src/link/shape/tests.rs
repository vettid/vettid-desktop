use super::*;
use serde_json::json;

const IK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn prof() -> Value {
    json!({"version": 1, "first_name": "Ann", "last_name": "Lee", "ik": IK, "items": []})
}

fn conn() -> Value {
    json!({"id": "c-1", "kind": "connection", "state": "active", "name": "Ann", "ik": IK, "profile": prof(),
        "created_at": "2026-11-25T10:00:00Z", "last_active_at": "2026-11-25T10:00:00Z", "version": 3,
        "alias": "", "note": "", "tags": [], "favorite": false, "archived": false,
        "asks": {"muted": false, "paused": false, "cooldowns": {}}, "extra": "dropped"})
}

#[test]
fn a_connection_passes_with_known_members_only() {
    let v = connection(&conn()).unwrap();
    assert_eq!(v["id"], "c-1");
    assert!(v.get("extra").is_none(), "unknown members are dropped");
    assert!(v["asks"].get("cooldowns").is_none());
    let l = connection_list(&json!({"connections": [conn()]})).unwrap();
    assert_eq!(l["connections"].as_array().unwrap().len(), 1);
}

#[test]
fn bad_connections_are_refused() {
    let cases: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        ("kind", Box::new(|v| v["kind"] = json!("other"))),
        ("state", Box::new(|v| v["state"] = json!("pending"))),
        ("ik", Box::new(|v| v["ik"] = json!("short"))),
        ("id type", Box::new(|v| v["id"] = json!(7))),
        ("id long", Box::new(|v| v["id"] = json!("c".repeat(ID_MAX + 1)))),
        ("version", Box::new(|v| v["version"] = json!(-1))),
        ("tags", Box::new(|v| v["tags"] = json!([1]))),
        ("first_name", Box::new(|v| v["profile"]["first_name"] = json!("x".repeat(NAME_MAX + 1)))),
        ("display name", Box::new(|v| v["profile"]["name"] = json!("x".repeat(DISPLAY_MAX + 1)))),
        ("photo not an image", Box::new(|v| v["profile"]["photo"] = json!("aGVsbG8="))),
        ("items", Box::new(|v| v["profile"]["items"] = json!(vec![json!({}); ITEMS_MAX + 1]))),
        ("relay_held", Box::new(|v| v["relay_held"] = json!({"since": 1}))),
    ];
    for (name, f) in cases {
        let mut c = conn();
        f(&mut c);
        assert_eq!(connection(&c), Err(BadShape), "{name}");
    }
    assert_eq!(connection_list(&json!({"connections": "x"})), Err(BadShape));
}

#[test]
fn a_photo_is_a_small_jpeg_or_png() {
    use base64::Engine;
    let enc = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0];
    jpeg.resize(100, 0);
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    png.resize(100, 0);
    for ok in [&jpeg, &png] {
        let mut p = prof();
        p["photo"] = json!(enc(ok));
        assert!(profile(&p).is_ok());
    }
    let mut big = jpeg.clone();
    big.resize(PHOTO_MAX + 1, 0);
    let mut p = prof();
    p["photo"] = json!(enc(&big));
    assert_eq!(profile(&p), Err(BadShape));
}

#[test]
fn requests_are_checked_too() {
    let inc = json!({"pending_id": "p-1", "invite_id": "i-1", "sas": "1234", "remote": "r", "state": "pending",
        "peer_approved": false, "created_at": "t", "exp": "t", "profile": prof()});
    let out = json!({"connection_id": "c-2", "remote": "r", "state": "waiting", "peer_approved": false,
        "created_at": "t", "exp": "t", "name": "Bob"});
    let v = request_list(&json!({"incoming": [inc.clone()], "outgoing": [out]})).unwrap();
    assert_eq!(v["incoming"][0]["pending_id"], "p-1");
    let mut bad = inc;
    bad["profile"]["ik"] = json!("x");
    let v = request_list(&json!({"incoming": [bad], "outgoing": []})).unwrap();
    assert_eq!(v["incoming"][0], json!({"pending_id": "p-1", "unreadable": true}), "a stranger's profile is checked, and not passed on");
    assert_eq!(request_list(&json!({"incoming": []})), Err(BadShape));
}

/// One bad entry doesn't blank the list: a connection is left out and
/// counted; a request is kept by its id, marked, and still listed read-only.
#[test]
fn a_bad_entry_doesnt_blank_the_list() {
    let mut bad = conn();
    bad["ik"] = json!("short");
    let l = connection_list(&json!({"connections": [conn(), bad]})).unwrap();
    assert_eq!(l["connections"].as_array().unwrap().len(), 1);
    assert_eq!(l["unreadable"], 1);
    let good = json!({"pending_id": "p-1", "invite_id": "i", "sas": "1", "remote": "r", "state": "pending",
        "peer_approved": false, "created_at": "t", "exp": "t"});
    let mut stranger = good.clone();
    stranger["pending_id"] = json!("p-2");
    stranger["profile"] = json!({"first_name": 7});
    let v = request_list(&json!({"incoming": [good, stranger, {"no": "id"}], "outgoing": []})).unwrap();
    let inc = v["incoming"].as_array().unwrap();
    assert_eq!(inc.len(), 2, "the one without an id is dropped");
    assert_eq!(inc[1], json!({"pending_id": "p-2", "unreadable": true}));
}

/// An ik of 44 characters that isn't 32 bytes is refused.
#[test]
fn an_ik_of_the_wrong_length() {
    let mut c = conn();
    c["ik"] = json!("A".repeat(44)); // 33 bytes
    assert_eq!(connection(&c), Err(BadShape));
}

fn msg(id: &str) -> Value {
    json!({"connection_id": "c-1", "message_id": id, "direction": "in", "text": "hi", "sent_at": "2026-11-25T10:00:00Z",
        "delivered": true, "read": false})
}

/// A page passes with its known members, oldest first as sent; a message
/// that doesn't check out is left out and counted, and doesn't blank the
/// page.
#[test]
fn a_page_of_messages_drops_and_counts_a_bad_one() {
    let mut bad = msg("m-2");
    bad["direction"] = json!("sideways");
    let mut long = msg("m-3");
    long["text"] = json!("x".repeat(crate::link::inbound::MAX_TEXT_LEN + 1));
    let mut other = msg("m-4");
    other["connection_id"] = json!("c-2");
    let mut unnamed = msg("m-5");
    unnamed.as_object_mut().unwrap().remove("connection_id");
    let mut extra = msg("m-6");
    extra["extra"] = json!("dropped");
    let mut empty_text = msg("m-7");
    empty_text["text"] = json!("");
    let v = message_list(&json!({"messages": [msg("m-1"), bad, long, other, unnamed, extra, empty_text], "next_before": "m-1"}), "c-1").unwrap();
    let ids: Vec<&str> = v["messages"].as_array().unwrap().iter().map(|m| m["message_id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["m-1", "m-5", "m-6"], "the bad, the too long, another connection's and an empty one are left out");
    assert_eq!(v["unreadable"], 4);
    assert_eq!(v["next_before"], "m-1");
    assert_eq!(v["messages"][1]["connection_id"], "c-1", "a listed message may leave its connection out");
    assert!(v["messages"][2].get("extra").is_none());
    assert_eq!(message_list(&json!({"messages": []}), "c-1").unwrap(), json!({"messages": [], "unreadable": 0}));
}

/// A photo without its caption: kept, as the desktop's view (no thumb, no
/// name), so the view can show a placeholder.
#[test]
fn an_attachment_is_kept_without_thumb_or_name() {
    let mut m = msg("m-1");
    m["text"] = json!("");
    m["attachment"] = json!({"att_id": "a-1", "kind": "photo", "size": 1000, "width": 10, "height": 20, "state": "stored", "thumb": "AAAA", "name": "beach.jpg"});
    let v = message_list(&json!({"messages": [m]}), "c-1").unwrap();
    assert_eq!(v["unreadable"], 0);
    let a = &v["messages"][0]["attachment"];
    assert_eq!((a["att_id"].as_str(), a["state"].as_str(), v["messages"][0]["text"].as_str()), (Some("a-1"), Some("stored"), Some("")));
    assert!(a.get("thumb").is_none() && a.get("name").is_none(), "{a}");
    let mut no_att = msg("m-2");
    no_att["attachment"] = json!(null);
    assert!(message_list(&json!({"messages": [no_att]}), "c-1").unwrap()["messages"][0]["attachment"].is_null());
}

#[test]
fn a_page_that_doesnt_check_out_is_refused() {
    for v in [
        json!({}),
        json!({"messages": "x"}),
        json!({"messages": [], "next_before": 7}),
        json!({"messages": [], "next_before": ""}),
        json!({"messages": [], "next_before": "m".repeat(crate::link::inbound::MAX_ID_LEN + 1)}),
        json!({"messages": vec![msg("m-1"); MESSAGES_MAX + 1]}),
    ] {
        assert_eq!(message_list(&v, "c-1"), Err(BadShape), "{v}");
    }
}

#[test]
fn a_sent_message_is_its_id_and_time() {
    let v = message_sent(&json!({"message_id": "m-9", "sent_at": "2026-11-25T10:00:00.123Z", "att_id": "a-1", "x": 1})).unwrap();
    assert_eq!(v, json!({"message_id": "m-9", "sent_at": "2026-11-25T10:00:00.123Z"}));
    for bad in [json!({"sent_at": "2026-11-25T10:00:00Z"}), json!({"message_id": "", "sent_at": "2026-11-25T10:00:00Z"}), json!({"message_id": "m", "sent_at": "yesterday"}), json!({"message_id": 1, "sent_at": "2026-11-25T10:00:00Z"})] {
        assert_eq!(message_sent(&bad), Err(BadShape), "{bad}");
    }
    assert_eq!(empty(&json!({"x": 1})), Ok(json!({})));
    assert_eq!(empty(&json!([])), Err(BadShape));
}

/// As the vault sends it (vettid-vault `peerJSON`): empty metadata, the
/// display name, the profile and the times left out. It is read, with
/// empty metadata; a partial profile (the inviter's side before the first
/// `profile.update`) is read too.
#[test]
fn a_connection_with_its_empty_parts_left_out() {
    let v = json!({"id": "c-1", "kind": "connection", "state": "active", "ik": IK, "version": 0,
        "favorite": false, "archived": false, "asks": {"muted": false, "paused": false}});
    let c = connection(&v).unwrap();
    assert_eq!(c["alias"], "");
    assert_eq!(c["note"], "");
    assert_eq!(c["tags"], json!([]));
    assert!(c.get("profile").is_none() && c.get("name").is_none() && c.get("last_active_at").is_none());
    let mut w = v.clone();
    w["profile"] = json!({"first_name": "Ann", "last_name": "Lee"});
    assert_eq!(connection(&w).unwrap()["profile"]["first_name"], "Ann");
    let l = connection_list(&json!({"connections": [v, w]})).unwrap();
    assert_eq!(l["unreadable"], 0);
    // Present but wrong is still refused.
    for (k, bad) in [("alias", json!(7)), ("tags", json!("x")), ("profile", json!({"first_name": 1, "last_name": "L"})), ("last_active_at", json!(1))] {
        let mut x = json!({"id": "c-1", "kind": "connection", "state": "active", "ik": IK, "version": 0,
            "favorite": false, "archived": false, "asks": {"muted": false, "paused": false}});
        x[k] = bad;
        assert_eq!(connection(&x), Err(BadShape), "{k}");
    }
    let mut p = prof();
    p["ik"] = json!("short");
    assert_eq!(profile(&p), Err(BadShape), "a present ik is still checked");
}
