//! What the vault sends this desktop besides its access session's events
//! (DESKTOP-REWORK-PLAN Phase 5, 5.1): `message.new` and the `sync.event`
//! kinds the connection and message views follow (VAULT-MESSAGING §9.1,
//! §10.1, §10.5). They reach the frontend as [`INBOUND_EVENT`].
//!
//! Message text is plaintext: it is kept in memory only, for the views,
//! wiped when dropped, never written to disk and never logged (`Debug`
//! leaves it out; logs carry types and sizes).

use std::collections::VecDeque;

use serde::Serialize;
use serde::ser::SerializeStruct;
use vettid_vms::envelope::Inner;
use zeroize::Zeroizing;

/// The Tauri event that carries an [`InboundBatch`] to the frontend.
pub const INBOUND_EVENT: &str = "vault:inbound";

/// At most this many are queued between two deliveries; past it the oldest
/// go and the batch says `resync`, so the views read again.
pub const MAX_QUEUED: usize = 256;

pub const TYPE_MESSAGE_NEW: &str = "message.new";
pub const TYPE_SYNC_EVENT: &str = "sync.event";

/// A `sync.event` member's type (§10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Member {
    Str,
    Num,
}

/// The `sync.event` kinds the Phase 5 views follow, with their members and
/// their types (§10.1); other kinds are not this desktop's to show yet and
/// are dropped, and other members are ignored. Besides the plan's message,
/// connection and block kinds: `message.attachment` (a placeholder's state)
/// and the feed kinds (delivery failures are feed items).
pub const SYNC_KINDS: &[(&str, &[(&str, Member)])] = &[
    ("message.receipt", &[("connection_id", Member::Str), ("message_id", Member::Str), ("receipt", Member::Str)]),
    ("message.read", &[("connection_id", Member::Str), ("message_id", Member::Str)]),
    ("message.attachment", &[("connection_id", Member::Str), ("message_id", Member::Str), ("state", Member::Str), ("reason", Member::Str)]),
    ("connection.changed", &[("connection_id", Member::Str), ("version", Member::Num)]),
    ("connection.request", &[("pending_id", Member::Str), ("connection_id", Member::Str), ("state", Member::Str)]),
    ("block.added", &[("block_id", Member::Str)]),
    ("block.removed", &[("block_id", Member::Str)]),
    ("feed.updated", &[("item_id", Member::Str), ("seq", Member::Num)]),
    ("feed.deleted", &[("item_id", Member::Str), ("seq", Member::Num)]),
];

/// The longest string member passed on (§10.1's bound on strings).
pub const MAX_MEMBER_LEN: usize = 4096;

/// The longest message text (§10.5: 1 B to 16 KiB).
pub const MAX_TEXT_LEN: usize = 16 * 1024;

/// The longest id this desktop takes (connection, message, attachment).
pub const MAX_ID_LEN: usize = 128;

/// The longest other string in a message (time, attachment kind, mime,
/// state, reason).
pub const MAX_FIELD_LEN: usize = 256;

/// `message.new` (§10.5): an incoming message, or one another of the
/// owner's devices sent.
#[derive(Clone, PartialEq, Eq)]
pub struct MessageNew {
    pub connection_id: String,
    pub message_id: String,
    /// `in` or `out`.
    pub direction: Direction,
    /// Plaintext. `""` for an attachment without a caption.
    pub text: Zeroizing<String>,
    /// As the vault wrote it (RFC 3339).
    pub sent_at: String,
    pub delivered: bool,
    pub read: bool,
    pub attachment: Option<Attachment>,
}

impl std::fmt::Debug for MessageNew {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageNew")
            .field("connection_id", &self.connection_id)
            .field("message_id", &self.message_id)
            .field("direction", &self.direction)
            .field("text_len", &self.text.len())
            .field("delivered", &self.delivered)
            .field("read", &self.read)
            .field("attachment", &self.attachment.is_some())
            .finish_non_exhaustive()
    }
}

impl Serialize for MessageNew {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("MessageNew", 8)?;
        st.serialize_field("connection_id", &self.connection_id)?;
        st.serialize_field("message_id", &self.message_id)?;
        st.serialize_field("direction", &self.direction)?;
        st.serialize_field("text", self.text.as_str())?;
        st.serialize_field("sent_at", &self.sent_at)?;
        st.serialize_field("delivered", &self.delivered)?;
        st.serialize_field("read", &self.read)?;
        st.serialize_field("attachment", &self.attachment)?;
        st.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

/// An attachment as a desktop sees it (§10.5.1, "Desktops"): the device
/// view without `thumb` and `name`. Those are dropped here even if a vault
/// sends them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attachment {
    pub att_id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    pub size: u64,
    pub width: u64,
    pub height: u64,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A `sync.event` of one of [`SYNC_KINDS`]: its `kind` and its other
/// members as sent (they carry ids and states, never secret values,
/// §10.1).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SyncEvent {
    pub kind: String,
    pub members: serde_json::Map<String, serde_json::Value>,
}

/// One message for the frontend.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", content = "body")]
pub enum Inbound {
    #[serde(rename = "message.new")]
    MessageNew(MessageNew),
    #[serde(rename = "sync.event")]
    Sync(SyncEvent),
}

/// What one delivery carries: the messages in arrival order, and whether
/// some were lost (dropped past [`MAX_QUEUED`], or unreadable), in which
/// case the views read again (Phase 5 "Catching up").
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct InboundBatch {
    pub messages: Vec<Inbound>,
    pub resync: bool,
}

/// Why a message of ours couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable;

/// Read `m` if it is one of ours: `None` if it isn't (a response, or
/// another type, or a `sync.event` of a kind not followed here).
pub fn parse(m: &Inner) -> Option<Result<Inbound, Unreadable>> {
    if m.response.is_some() {
        return None;
    }
    match m.kind.as_str() {
        TYPE_MESSAGE_NEW => Some(parse_message(&m.body).map(Inbound::MessageNew)),
        TYPE_SYNC_EVENT => parse_sync(&m.body).map(|r| r.map(Inbound::Sync)),
        _ => None,
    }
}

// SECURITY: the text passes through serde_json's own strings here, and
// through Tauri's serialization on its way to the window; those copies are
// freed without wiping. What this module keeps is wiped (Zeroizing), and
// none of it reaches disk or a log.
fn parse_message(body: &str) -> Result<MessageNew, Unreadable> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|_| Unreadable)?;
    message(&v, None)
}

/// A `<message.new body>` (§10.5), as `message.new` carries it and
/// `message.list` and `message.get` list it: the same checks for each.
/// `listed`: the connection a list was asked for; a message there may
/// leave `connection_id` out, and one naming another connection is
/// unreadable.
pub fn message(v: &serde_json::Value, listed: Option<&str>) -> Result<MessageNew, Unreadable> {
    let o = v.as_object().ok_or(Unreadable)?;
    let s = |k: &str, max: usize| o.get(k).and_then(|v| v.as_str()).filter(|t| t.len() <= max).map(str::to_string).ok_or(Unreadable);
    let b = |k: &str| o.get(k).and_then(|v| v.as_bool()).ok_or(Unreadable);
    let direction = match o.get("direction").and_then(|v| v.as_str()) {
        Some("in") => Direction::In,
        Some("out") => Direction::Out,
        _ => return Err(Unreadable),
    };
    let connection_id = match (listed, o.get("connection_id")) {
        (Some(c), None | Some(serde_json::Value::Null)) => c.to_string(),
        (Some(c), Some(_)) => Some(s("connection_id", MAX_ID_LEN)?).filter(|id| id == c).ok_or(Unreadable)?,
        (None, _) => s("connection_id", MAX_ID_LEN)?,
    };
    let (message_id, sent_at) = (s("message_id", MAX_ID_LEN)?, s("sent_at", MAX_FIELD_LEN)?);
    if connection_id.is_empty() || message_id.is_empty() || chrono::DateTime::parse_from_rfc3339(&sent_at).is_err() {
        return Err(Unreadable);
    }
    let text = o.get("text").and_then(|v| v.as_str()).ok_or(Unreadable)?;
    if text.len() > MAX_TEXT_LEN {
        return Err(Unreadable);
    }
    let text = Zeroizing::new(text.to_string());
    let attachment = match o.get("attachment") {
        None | Some(serde_json::Value::Null) => None,
        Some(a) => Some(parse_attachment(a)?),
    };
    Ok(MessageNew { connection_id, message_id, direction, text, sent_at, delivered: b("delivered")?, read: b("read")?, attachment })
}

fn parse_attachment(v: &serde_json::Value) -> Result<Attachment, Unreadable> {
    let o = v.as_object().ok_or(Unreadable)?;
    // Absent or null: `None`; a string over `max`, or not a string: unreadable.
    let opt = |k: &str, max: usize| -> Result<Option<String>, Unreadable> {
        match o.get(k) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(t)) if t.len() <= max => Ok(Some(t.clone())),
            Some(_) => Err(Unreadable),
        }
    };
    let req = |k: &str, max: usize| opt(k, max)?.ok_or(Unreadable);
    let n = |k: &str| o.get(k).and_then(|v| v.as_u64()).ok_or(Unreadable);
    Ok(Attachment {
        att_id: req("att_id", MAX_ID_LEN)?,
        kind: req("kind", MAX_FIELD_LEN)?,
        mime: opt("mime", MAX_FIELD_LEN)?,
        size: n("size")?,
        width: n("width")?,
        height: n("height")?,
        state: req("state", MAX_FIELD_LEN)?,
        reason: opt("reason", MAX_FIELD_LEN)?,
    })
}

fn parse_sync(body: &str) -> Option<Result<SyncEvent, Unreadable>> {
    let Ok(serde_json::Value::Object(mut o)) = serde_json::from_str::<serde_json::Value>(body) else {
        return Some(Err(Unreadable));
    };
    let kind = match o.remove("kind") {
        Some(serde_json::Value::String(k)) => k,
        _ => return Some(Err(Unreadable)),
    };
    let (_, allowed) = SYNC_KINDS.iter().find(|(k, _)| *k == kind)?;
    let mut members = serde_json::Map::new();
    for (name, ty) in *allowed {
        match (o.remove(*name), ty) {
            // Absent, or null (§10.1): not there.
            (None | Some(serde_json::Value::Null), _) => {}
            (Some(v @ serde_json::Value::Number(_)), Member::Num) => {
                members.insert((*name).to_string(), v);
            }
            (Some(serde_json::Value::String(t)), Member::Str) if t.len() <= MAX_MEMBER_LEN => {
                members.insert((*name).to_string(), serde_json::Value::String(t));
            }
            _ => return Some(Err(Unreadable)),
        }
    }
    Some(Ok(SyncEvent { kind, members }))
}

/// The messages waiting for the next delivery.
#[derive(Debug, Default)]
pub struct Queue {
    q: VecDeque<Inbound>,
    resync: bool,
}

impl Queue {
    /// Keep `m` if it is one of ours. An unreadable one is dropped (its
    /// type and size logged, never its body) and asks for a resync.
    pub fn take(&mut self, m: &Inner) {
        match parse(m) {
            None => {}
            Some(Ok(i)) => {
                if self.q.len() == MAX_QUEUED {
                    self.q.pop_front();
                    self.resync = true;
                }
                self.q.push_back(i);
            }
            Some(Err(Unreadable)) => {
                log::warn!("link: a {} from the vault didn't read ({} bytes); the views read again", m.kind, m.body.len());
                self.resync = true;
            }
        }
    }

    /// Everything queued, and whether to resync; the queue is then empty.
    pub fn drain(&mut self) -> InboundBatch {
        InboundBatch { messages: self.q.drain(..).collect(), resync: std::mem::take(&mut self.resync) }
    }

    /// Drop everything queued; the views read again if anything was.
    pub fn clear(&mut self) {
        if !self.q.is_empty() {
            self.resync = true;
        }
        self.q.clear();
    }

    /// Drop everything queued because the session or the vault changed
    /// (held, locked, ended, replaced, unreadable): nothing read before is
    /// shown, and the views read again in any case.
    pub fn clear_changed(&mut self) {
        self.q.clear();
        self.resync = true;
    }

    /// A message for the views was dropped (no live session): they read
    /// again once live.
    pub fn lose(&mut self) {
        self.resync = true;
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.q.is_empty() && !self.resync
    }
}

#[cfg(test)]
mod tests;
