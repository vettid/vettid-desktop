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
    assert_eq!(request_list(&json!({"incoming": [bad], "outgoing": []})), Err(BadShape), "a stranger's profile is checked");
    assert_eq!(request_list(&json!({"incoming": []})), Err(BadShape));
}
