//! The shape of what the vault answers for the connection views
//! (VAULT-MESSAGING 0.94.1 §10.4, §10.8), checked before it reaches the
//! window: known members only (others are ignored, §10.1), of their types,
//! within their bounds. An incoming request's profile comes from someone
//! the member hasn't accepted yet: nothing of it is passed on unchecked.

use base64::Engine;
use serde_json::{Map, Value};

/// Something in an answer that isn't what the spec says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadShape;

type R<T> = Result<T, BadShape>;

const ID_MAX: usize = 128;
const NAME_MAX: usize = 160; // first_name, last_name (§11.13)
const DISPLAY_MAX: usize = 128; // the display name (§10.8)
const PHOTO_MAX: usize = 65_536; // decoded bytes (§10.8)
const TEXT_MAX: usize = 4096; // alias, note, other free text (§10.1)
const TIME_MAX: usize = 64;
const IK_LEN: usize = 44; // base64 of 32 bytes
const ITEMS_MAX: usize = 32; // @profile items (§10.8)
const LIST_MAX: usize = 10_000;

fn obj(v: &Value) -> R<&Map<String, Value>> {
    v.as_object().ok_or(BadShape)
}

/// Copy string member `k` (required) of at most `max` bytes.
fn s(o: &Map<String, Value>, out: &mut Map<String, Value>, k: &str, max: usize) -> R<()> {
    match o.get(k) {
        Some(Value::String(t)) if t.len() <= max => {
            out.insert(k.into(), Value::String(t.clone()));
            Ok(())
        }
        _ => Err(BadShape),
    }
}

/// The same, optional: absent or null is left out.
fn s_opt(o: &Map<String, Value>, out: &mut Map<String, Value>, k: &str, max: usize) -> R<()> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(()),
        _ => s(o, out, k, max),
    }
}

fn b(o: &Map<String, Value>, out: &mut Map<String, Value>, k: &str) -> R<()> {
    match o.get(k) {
        Some(v @ Value::Bool(_)) => {
            out.insert(k.into(), v.clone());
            Ok(())
        }
        _ => Err(BadShape),
    }
}

fn n(o: &Map<String, Value>, out: &mut Map<String, Value>, k: &str) -> R<()> {
    match o.get(k) {
        Some(v @ Value::Number(x)) if x.is_u64() => {
            out.insert(k.into(), v.clone());
            Ok(())
        }
        _ => Err(BadShape),
    }
}

fn exact(o: &Map<String, Value>, out: &mut Map<String, Value>, k: &str, want: &str) -> R<()> {
    match o.get(k) {
        Some(Value::String(t)) if t == want => {
            out.insert(k.into(), Value::String(t.clone()));
            Ok(())
        }
        _ => Err(BadShape),
    }
}

fn ik(o: &Map<String, Value>, out: &mut Map<String, Value>, k: &str) -> R<()> {
    match o.get(k) {
        Some(Value::String(t)) if t.len() == IK_LEN && base64::engine::general_purpose::STANDARD.decode(t).is_ok_and(|d| d.len() == 32) => {
            out.insert(k.into(), Value::String(t.clone()));
            Ok(())
        }
        _ => Err(BadShape),
    }
}

/// A photo: base64 of a JPEG or a PNG of at most 64 KiB.
fn photo(o: &Map<String, Value>, out: &mut Map<String, Value>) -> R<()> {
    match o.get("photo") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(t)) => {
            if t.len() > PHOTO_MAX.div_ceil(3) * 4 {
                return Err(BadShape);
            }
            let d = base64::engine::general_purpose::STANDARD.decode(t).map_err(|_| BadShape)?;
            let jpeg = d.starts_with(&[0xFF, 0xD8, 0xFF]);
            let png = d.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
            if d.len() > PHOTO_MAX || !(jpeg || png) {
                return Err(BadShape);
            }
            out.insert("photo".into(), Value::String(t.clone()));
            Ok(())
        }
        _ => Err(BadShape),
    }
}

/// A shared profile (§10.8): the core, the display name, the photo and up
/// to 32 items (passed on as objects; they are the member's own data).
pub fn profile(v: &Value) -> R<Value> {
    let o = obj(v)?;
    let mut out = Map::new();
    n(o, &mut out, "version")?;
    s(o, &mut out, "first_name", NAME_MAX)?;
    s(o, &mut out, "last_name", NAME_MAX)?;
    ik(o, &mut out, "ik")?;
    s_opt(o, &mut out, "name", DISPLAY_MAX)?;
    photo(o, &mut out)?;
    match o.get("items") {
        None | Some(Value::Null) => {
            out.insert("items".into(), Value::Array(Vec::new()));
        }
        Some(Value::Array(a)) if a.len() <= ITEMS_MAX && a.iter().all(Value::is_object) => {
            out.insert("items".into(), Value::Array(a.clone()));
        }
        _ => return Err(BadShape),
    }
    Ok(Value::Object(out))
}

/// `<connection>` (§10.4).
pub fn connection(v: &Value) -> R<Value> {
    let o = obj(v)?;
    let mut out = Map::new();
    s(o, &mut out, "id", ID_MAX)?;
    exact(o, &mut out, "kind", "connection")?;
    exact(o, &mut out, "state", "active")?;
    s(o, &mut out, "name", TEXT_MAX)?;
    ik(o, &mut out, "ik")?;
    out.insert("profile".into(), profile(o.get("profile").ok_or(BadShape)?)?);
    s(o, &mut out, "created_at", TIME_MAX)?;
    s(o, &mut out, "last_active_at", TIME_MAX)?;
    n(o, &mut out, "version")?;
    s(o, &mut out, "alias", TEXT_MAX)?;
    s(o, &mut out, "note", TEXT_MAX)?;
    match o.get("tags") {
        Some(Value::Array(a)) if a.len() <= LIST_MAX && a.iter().all(|t| t.as_str().is_some_and(|t| t.len() <= TEXT_MAX)) => {
            out.insert("tags".into(), Value::Array(a.clone()));
        }
        _ => return Err(BadShape),
    }
    b(o, &mut out, "favorite")?;
    b(o, &mut out, "archived")?;
    s_opt(o, &mut out, "peer_kind", ID_MAX)?;
    let asks = obj(o.get("asks").ok_or(BadShape)?)?;
    let mut a = Map::new();
    b(asks, &mut a, "muted")?;
    b(asks, &mut a, "paused")?;
    out.insert("asks".into(), Value::Object(a));
    match o.get("relay_held") {
        None | Some(Value::Null) => {}
        Some(h) => {
            let mut r = Map::new();
            s(obj(h)?, &mut r, "since", TIME_MAX)?;
            out.insert("relay_held".into(), Value::Object(r));
        }
    }
    Ok(Value::Object(out))
}

/// `connection.list`'s answer. A connection that doesn't check out is
/// left out, and counted in `unreadable`; only a malformed top level
/// fails the list.
pub fn connection_list(v: &Value) -> R<Value> {
    let a = obj(v)?.get("connections").and_then(Value::as_array).ok_or(BadShape)?;
    if a.len() > LIST_MAX {
        return Err(BadShape);
    }
    let ok: Vec<Value> = a.iter().filter_map(|c| connection(c).ok()).collect();
    let mut out = Map::new();
    out.insert("unreadable".into(), Value::from(a.len() - ok.len()));
    out.insert("connections".into(), Value::Array(ok));
    Ok(Value::Object(out))
}

/// A request that doesn't check out, kept with its id (so it can still be
/// declined) and marked `unreadable`; dropped if even its id doesn't.
fn unreadable(v: &Value, id_key: &str) -> Option<Value> {
    let o = v.as_object()?;
    let mut out = Map::new();
    s(o, &mut out, id_key, ID_MAX).ok()?;
    out.insert("unreadable".into(), Value::Bool(true));
    Some(Value::Object(out))
}

fn request_common(o: &Map<String, Value>, out: &mut Map<String, Value>) -> R<()> {
    s(o, out, "remote", TEXT_MAX)?;
    s(o, out, "state", ID_MAX)?;
    b(o, out, "peer_approved")?;
    s(o, out, "created_at", TIME_MAX)?;
    s(o, out, "exp", TIME_MAX)?;
    s_opt(o, out, "introduced_by", ID_MAX)
}

fn incoming(v: &Value) -> R<Value> {
    let o = obj(v)?;
    let mut out = Map::new();
    s(o, &mut out, "pending_id", ID_MAX)?;
    s(o, &mut out, "invite_id", ID_MAX)?;
    s(o, &mut out, "sas", ID_MAX)?;
    request_common(o, &mut out)?;
    if let Some(p) = o.get("profile").filter(|p| !p.is_null()) {
        out.insert("profile".into(), profile(p)?);
    }
    Ok(Value::Object(out))
}

fn outgoing(v: &Value) -> R<Value> {
    let o = obj(v)?;
    let mut out = Map::new();
    s(o, &mut out, "connection_id", ID_MAX)?;
    s_opt(o, &mut out, "sas", ID_MAX)?;
    if o.get("ik").is_some_and(|v| !v.is_null()) {
        ik(o, &mut out, "ik")?;
    }
    request_common(o, &mut out)?;
    s_opt(o, &mut out, "name", TEXT_MAX)?;
    s_opt(o, &mut out, "peer_kind", ID_MAX)?;
    Ok(Value::Object(out))
}

/// `connection.request.list`'s answer: a request that doesn't check out
/// (a stranger's profile, say) is kept by its id, marked `unreadable`.
pub fn request_list(v: &Value) -> R<Value> {
    let o = obj(v)?;
    let mut out = Map::new();
    for (k, f, id) in [("incoming", incoming as fn(&Value) -> R<Value>, "pending_id"), ("outgoing", outgoing, "connection_id")] {
        let a = o.get(k).and_then(Value::as_array).ok_or(BadShape)?;
        if a.len() > LIST_MAX {
            return Err(BadShape);
        }
        out.insert(k.into(), Value::Array(a.iter().filter_map(|r| f(r).ok().or_else(|| unreadable(r, id))).collect()));
    }
    Ok(Value::Object(out))
}

/// An empty answer (`connection.decline`): `{}`, whatever it carries.
pub fn empty(v: &Value) -> R<Value> {
    obj(v)?;
    Ok(Value::Object(Map::new()))
}

#[cfg(test)]
mod tests;
