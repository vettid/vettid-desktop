use serde::Serialize;
use tauri::State;

// The vault operations not carried over yet answer one plain "not
// available" error: see `unavailable`. The connection operations go over the
// link (DESKTOP-REWORK-PLAN Phase 5, 5.2; `link::ops`).
use crate::commands::unavailable as operations;
use crate::link::inbound::{MAX_ID_LEN, MAX_TEXT_LEN};
use crate::link::ops::{link_run_with, How, OpError, Ran};
use crate::link::shape::{self, BadShape};
use crate::state::AppState;

/// `Debug` leaves `data` out: it can carry message plaintext and personal
/// data (names, profiles).
#[derive(Serialize)]
pub struct VaultOpResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    /// A stable code for errors the frontend words for itself, so it
    /// doesn't match on `error`'s text (#42). `"stopped_waiting"`: the
    /// desktop stopped waiting, and the phone may still carry it out.
    pub error_code: Option<&'static str>,
    pub pending_approval: bool,
}

impl std::fmt::Debug for VaultOpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultOpResponse")
            .field("success", &self.success)
            .field("data", &self.data.is_some())
            .field("error_code", &self.error_code)
            .field("pending_approval", &self.pending_approval)
            .finish_non_exhaustive()
    }
}

impl VaultOpResponse {
    fn from_op(result: Result<operations::OpResponse, operations::OperationError>) -> Self {
        match result {
            Ok(resp) => Self {
                success: resp.success,
                data: resp.data,
                error: resp.error,
                error_code: None,
                pending_approval: resp.pending_phone_approval,
            },
            Err(e) => Self {
                success: false,
                data: None,
                error_code: e.code(),
                error: Some(e.to_string()),
                pending_approval: false,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Independent operations (no phone approval)
// ---------------------------------------------------------------------------

impl VaultOpResponse {
    /// What a vault operation over the link answers: its body, or why it
    /// failed (with a stable code for the frontend).
    fn from_link(result: Result<serde_json::Value, OpError>) -> Self {
        match result {
            Ok(v) => Self { success: true, data: Some(v), error: None, error_code: None, pending_approval: false },
            Err(e) => Self { success: false, data: None, error: Some(e.notice().to_string()), error_code: Some(e.code()), pending_approval: false },
        }
    }
}

/// Run `kind` with `body` over the link ([`link_op_with`]): only while
/// the screen shows a live session and no End session, lock or log-out is
/// under way; its answer checked by `shape`. The connection commands are
/// reads; `send_message` is a change, sent after the kept one
/// ([`How::KeptFirst`]).
async fn link_op(
    state: &AppState,
    kind: &str,
    body: serde_json::Value,
    shape: fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>,
    change: bool,
) -> VaultOpResponse {
    let how = if change { How::Change } else { How::Read };
    VaultOpResponse::from_link(link_run(state, kind, body, shape, how).await.result)
}

/// [`link_op`]'s run, with the [`Earlier`] of [`How::KeptFirst`] and the
/// kept request's id ([`Ran`]).
async fn link_run(
    state: &AppState,
    kind: &str,
    body: serde_json::Value,
    shape: impl Fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>,
    how: How,
) -> Ran {
    // Registered before the reset mark is read, so a reset that starts any
    // time after it wakes the operation.
    let stop = state.reset_notify.notified();
    tokio::pin!(stop);
    stop.as_mut().enable();
    let mark = crate::commands::auth::reset_mark(state);
    link_run_with(
        &state.link,
        || state.snapshot().active_at(chrono::Utc::now()),
        || crate::commands::auth::overtaken_by_reset(state, mark),
        |s| state.publish(s),
        stop,
        kind,
        body,
        shape,
        how,
    )
    .await
}

/// List connections (`connection.list`, VAULT-MESSAGING §10.4): read-only.
#[tauri::command]
pub async fn list_connections(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    Ok(link_op(&state, "connection.list", serde_json::json!({}), shape::connection_list, false).await)
}

/// Get a specific connection (`connection.get`, §10.4).
#[tauri::command]
pub async fn get_connection(state: State<'_, AppState>, connection_id: String) -> Result<VaultOpResponse, String> {
    if connection_id.is_empty() {
        return Ok(VaultOpResponse::from_link(Err(OpError::BadArgument)));
    }
    Ok(link_op(&state, "connection.get", serde_json::json!({ "connection_id": connection_id }), shape::connection, false).await)
}

/// The connection requests waiting (`connection.request.list`, §10.4):
/// incoming and outgoing. A desktop shows them read-only; they are answered
/// on the phone (§3.1).
#[tauri::command]
pub async fn list_connection_requests(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    Ok(link_op(&state, "connection.request.list", serde_json::json!({}), shape::request_list, false).await)
}

/// List paired agents with their Contract (scope / approval mode /
/// rate limit) — independent op. The History tab for an agent uses
/// this to surface "what is this agent allowed to do" alongside the
/// audit log. See docs/AGENT-PAIRED-CONTRACT-MODEL.md.
#[tauri::command]
pub async fn list_agents(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "agent.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List feed events.
#[tauri::command]
pub async fn list_feed(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "feed.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Query audit log.
#[tauri::command]
pub async fn query_audit(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "audit.query", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List audit entries for one connection (independent). Used by the
/// simplified system/device-connection workspace to show history
/// without the messaging / sharing / profile surface a peer would
/// have. Newest entries first; pages via cursor_created_at / cursor_entry_id.
#[tauri::command]
pub async fn list_connection_audit(
    state: State<'_, AppState>,
    connection_id: String,
    limit: Option<i32>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({ "connection_id": connection_id });
    if let Some(l) = limit {
        params["limit"] = serde_json::json!(l);
    }
    let result = operations::execute(&state, "connection.audit.list", params).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List the user's secrets (metadata only — names, types, categories,
/// discoverability). Values stay on the phone. Calls `secret.list`
/// (singular form is the modern dispatch in the vault; the older
/// `secrets.catalog` referenced an op that never existed).
#[tauri::command]
pub async fn list_secrets_catalog(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "secret.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

// ---------------------------------------------------------------------------
// Phone-approval-required operations
// ---------------------------------------------------------------------------

/// Request a secret value (phone-required).
#[tauri::command]
pub async fn request_secret(state: State<'_, AppState>, secret_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "secrets.retrieve",
        serde_json::json!({ "secret_id": secret_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

// ---------------------------------------------------------------------------
// New feature operations
// ---------------------------------------------------------------------------

/// List proposals (independent).
#[tauri::command]
pub async fn list_proposals(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "proposal.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Cast a vote (phone-required).
#[tauri::command]
pub async fn cast_vote(state: State<'_, AppState>, proposal_id: String, choice: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "vote.cast",
        serde_json::json!({ "proposal_id": proposal_id, "choice": choice }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List personal data (independent). The vault exposes this as
/// `personal-data.get` with an empty `namespaces` payload — passing
/// no filter returns every field in the user's data index.
#[tauri::command]
pub async fn list_personal_data(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "personal-data.get", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List wallets (independent).
#[tauri::command]
pub async fn list_wallets(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "wallet.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get wallet balance (independent).
#[tauri::command]
pub async fn get_wallet_balance(state: State<'_, AppState>, wallet_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "wallet.get-balance",
        serde_json::json!({ "wallet_id": wallet_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Send BTC (phone-required — signing in enclave gated on phone approval).
#[tauri::command]
pub async fn send_btc(
    state: State<'_, AppState>,
    wallet_id: String,
    to_address: String,
    amount_sats: i64,
    fee_rate: Option<i32>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({
        "wallet_id": wallet_id,
        "to_address": to_address,
        "amount_sats": amount_sats,
    });
    if let Some(rate) = fee_rate {
        params["fee_rate"] = serde_json::json!(rate);
    }
    let result = operations::execute_phone_required(&state, "wallet.send", params).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List connected devices (independent).
#[tauri::command]
pub async fn list_devices(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "device.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get own profile (independent). Vault routes this as `profile.get`
/// (the older `.view` name doesn't resolve in the current handler).
#[tauri::command]
pub async fn get_profile(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "profile.get", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get the user's profile photo (base64). Independent op — kept
/// separate from `profile.get` server-side because photos can be
/// hundreds of KB and most callers don't need them on every read.
#[tauri::command]
pub async fn get_profile_photo(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "profile.photo.get", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Retrieve a specific secret value. Phone-required by default;
/// becomes independent once this session has been unlocked via
/// `request_secrets_unlock` (and until the grant expires).
#[tauri::command]
pub async fn get_secret(state: State<'_, AppState>, id: String) -> Result<VaultOpResponse, String> {
    // Phone-required if the session hasn't been unlocked yet —
    // independent once SecretsUnlockedUntil is set. Use the
    // phone-required helper so a non-unlocked call doesn't trip the
    // short ack window mid-approval.
    let result = operations::execute_phone_required(&state, "secret.get", serde_json::json!({ "id": id })).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Request a once-per-session unlock for viewing secret values.
/// Routes through the phone-required approval flow; on phone
/// approval, the vault sets DeviceSession.SecretsUnlockedUntil so
/// subsequent `get_secret` calls within the session don't re-prompt.
#[tauri::command]
pub async fn request_secrets_unlock(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(&state, "secret.unlock-session", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Stop waiting for a pending phone-approval operation by request_id. The
/// awaiter wakes with a stopped-waiting error. The vault is not told,
/// and the legacy vault can't cancel a pending request (#42): the prompt
/// stays on the phone, and approving it there still carries it out.
#[tauri::command]
pub async fn cancel_pending_operation(state: State<'_, AppState>, request_id: String) -> Result<bool, String> {
    Ok(operations::cancel(&state, &request_id).await)
}

/// Get a wallet's transaction history. Independent op — same data
/// the Android wallet detail screen pulls. Sibling to the existing
/// get_wallet_balance + get_wallet_address commands below.
#[tauri::command]
pub async fn get_wallet_transactions(state: State<'_, AppState>, wallet_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "wallet.get-history",
        serde_json::json!({ "wallet_id": wallet_id, "limit": 50 }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// One-round-trip screen-load: profile + photo + personal-data
/// bundled into a single vault op. Eliminates 3 separate vsock
/// round-trips on the Vault home; per-op overhead (queue
/// serialization, ChaCha20, JSON encode/decode, response routing)
/// dominates the work for tiny read ops, so bundling cuts the
/// wall-clock load time substantially.
#[tauri::command]
pub async fn get_vault_snapshot(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "vault.snapshot", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Update fields in the user's published profile (phone-required).
///
/// `fields` is a JSON object whose keys are field IDs and whose values are
/// `{ display_name, value, visibility }` triples — same shape Android sends to
/// `profile.update`. The vault validates the schema and the phone confirms.
#[tauri::command]
pub async fn update_profile(
    state: State<'_, AppState>,
    fields: serde_json::Value,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "profile.update",
        serde_json::json!({ "fields": fields }),
    )
    .await;
    Ok(VaultOpResponse::from_op(result))
}

/// Upsert one or more personal-data fields (phone-required).
///
/// `fields` is a `{namespace: value}` map and `aliases` is an optional
/// `{namespace: alias}` map for grouping related entries in the catalog.
/// Matches the vault's PersonalDataUpdateRequest shape exactly — the
/// earlier `{section, entries}` shape was a frontend invention and never
/// reached the handler intact.
#[tauri::command]
pub async fn update_personal_data(
    state: State<'_, AppState>,
    fields: serde_json::Value,
    aliases: Option<serde_json::Value>,
) -> Result<VaultOpResponse, String> {
    let mut payload = serde_json::json!({ "fields": fields });
    if let Some(a) = aliases {
        payload["aliases"] = a;
    }
    let result = operations::execute_phone_required(
        &state,
        "personal-data.update",
        payload,
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Add a minor (catalog-visible) secret. Phone-required.
/// Matches the vault's SecretAddRequest shape. `discoverability`
/// defaults to "cataloged" — same default the Android client uses.
#[tauri::command]
pub async fn add_secret(
    state: State<'_, AppState>,
    name: String,
    value: String,
    category: String,
    alias: Option<String>,
    description: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut payload = serde_json::json!({
        "name": name,
        "value": value,
        "category": category,
        "discoverability": "cataloged",
    });
    if let Some(a) = alias.filter(|s| !s.trim().is_empty()) {
        payload["alias"] = serde_json::Value::String(a);
    }
    if let Some(d) = description.filter(|s| !s.trim().is_empty()) {
        payload["description"] = serde_json::Value::String(d);
    }
    let result = operations::execute_phone_required(&state, "secret.add", payload).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Revoke a connection (phone-required — irreversible).
#[tauri::command]
pub async fn revoke_connection(
    state: State<'_, AppState>,
    connection_id: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "connection.revoke",
        serde_json::json!({ "connection_id": connection_id }),
    )
    .await;
    Ok(VaultOpResponse::from_op(result))
}

/// Mark an incoming message read (`message.read`, §10.5): the vault sends
/// the read receipt. Answers `{}`.
///
/// Sent as a read (`change: false`), not as a change: marking twice is
/// harmless (the vault answers `{}` again), so it needs no retry under its
/// id, and the link keeps one change at a time, which belongs to an
/// unconfirmed `send_message`. As a change, a mark that went unanswered
/// would take a kept send's place. The view marks again the next time the
/// message is seen. `not_found` (an unknown or outgoing message) is
/// passed on as such.
#[tauri::command]
pub async fn mark_message_read(state: State<'_, AppState>, connection_id: String, message_id: String) -> Result<VaultOpResponse, String> {
    match read_body(&connection_id, &message_id) {
        Ok(body) => Ok(link_op(&state, "message.read", body, shape::empty, false).await),
        Err(e) => Ok(VaultOpResponse::from_link(Err(e))),
    }
}

/// Send a text message (`message.send`, §10.5): `text` of 1 B to 16 KiB
/// of UTF-8. Answers `{message_id, sent_at}`, all the view needs besides
/// what it sent, since the vault sends no `message.new` back to the
/// desktop that sent it; and `earlier` when a send left unconfirmed was
/// retried first (see [`sent_response`]).
///
/// A change: one left unanswered is kept, in memory only (the text never
/// reaches the store or `device.enc`), and retried under its id, with its
/// first `exp`, when the same text is sent again, so the vault sends it
/// once (§8.2), at most twice (§8.6). After that, the same text gets
/// `unconfirmed` again with nothing sent until its `exp` plus a margin
/// for the vault's clock (`ops::KEPT_MARGIN`, 5 minutes), then
/// `unconfirmed_expired` once: the view reads the conversation before it
/// offers the text again (a new request). A retry that doesn't reach the
/// vault stays `unconfirmed`. A first send with the relay out of reach
/// isn't kept to go later: it is `not_sent`, and stays the view's draft.
/// Another message while one is kept retries the kept one first
/// ([`How::KeptFirst`]); while that stays unconfirmed, the new one isn't
/// sent (`earlier_unconfirmed`). `answer_unreadable`: the vault did it,
/// but its answer couldn't be read; the view reads the conversation
/// before it offers another send.
///
/// The view's rule for a message that holds a `pending_id` (5.3b): it
/// stays unconfirmed on every answer except success (it is sent),
/// `unconfirmed_expired` and `answer_unreadable` (read the conversation
/// again before offering it), or an `earlier` with its `pending_id` that
/// settles it. In particular `no_session`, `locked`, `held`, `not_sent`,
/// `clock` and `earlier_unconfirmed` never turn it back into a draft: it
/// may still be carried out.
///
/// A service connection takes no messages: the vault answers `forbidden`,
/// passed on as such (the view shows no conversation for one).
#[tauri::command]
pub async fn send_message(state: State<'_, AppState>, connection_id: String, text: String) -> Result<VaultOpResponse, String> {
    // SECURITY: plaintext; this copy is wiped. The JSON body's copies are
    // freed without wiping (as inbound's), and none is logged.
    let text = zeroize::Zeroizing::new(text);
    let body = match send_body(&connection_id, &text) {
        Ok(b) => b,
        Err(e) => return Ok(VaultOpResponse::from_link(Err(e))),
    };
    Ok(sent_response(link_run(&state, "message.send", body, shape::message_sent, How::KeptFirst).await))
}

/// `message.send`'s body, once its arguments check out: a connection id,
/// and text of 1 B to [`MAX_TEXT_LEN`] bytes of UTF-8 (§10.5). Otherwise
/// nothing is sent.
fn send_body(connection_id: &str, text: &str) -> Result<serde_json::Value, OpError> {
    if connection_id.is_empty() || connection_id.len() > MAX_ID_LEN || text.is_empty() || text.len() > MAX_TEXT_LEN {
        return Err(OpError::BadArgument);
    }
    Ok(serde_json::json!({ "connection_id": connection_id, "text": text }))
}

/// `message.read`'s body, once its ids check out.
fn read_body(connection_id: &str, message_id: &str) -> Result<serde_json::Value, OpError> {
    if [connection_id, message_id].iter().any(|i| i.is_empty() || i.len() > MAX_ID_LEN) {
        return Err(OpError::BadArgument);
    }
    Ok(serde_json::json!({ "connection_id": connection_id, "message_id": message_id }))
}

/// What `send_message` answers. `data` may be there when `success` is
/// false:
/// - `data.pending_id` with `error_code` `unconfirmed`: the request id this
///   send is kept under, an opaque token the view keeps with its message;
/// - `data.earlier`, when a kept send was retried first (also on an
///   error): `{pending_id, connection_id, success, data?: {message_id,
///   sent_at}, error?, error_code?}`. `pending_id` is the one an earlier
///   `unconfirmed` answer gave, so the view finds its message by it.
///   `error_code` `unconfirmed`: still not confirmed; `unconfirmed_expired`:
///   past its `exp`, forgotten, and only the next `get_conversation` tells
///   whether it was sent.
fn sent_response(ran: Ran) -> VaultOpResponse {
    let unconfirmed = ran.result.as_ref().err().is_some_and(OpError::is_unconfirmed);
    let mut resp = VaultOpResponse::from_link(ran.result);
    if let (true, Some(id)) = (unconfirmed, ran.pending_id) {
        resp.data.get_or_insert_with(|| serde_json::json!({}))["pending_id"] = id.into();
    }
    if let Some(e) = ran.earlier {
        // Only the id is read out of the kept body; its text is skipped.
        #[derive(serde::Deserialize)]
        struct Named {
            connection_id: String,
        }
        let named = serde_json::from_str::<Named>(&e.body).map(|n| n.connection_id).ok();
        let mut o = serde_json::json!({ "pending_id": e.id, "connection_id": named, "success": e.result.is_ok() });
        match &e.result {
            Ok(v) => o["data"] = v.clone(),
            Err(err) => {
                o["error"] = err.notice().into();
                o["error_code"] = err.code().into();
            }
        }
        resp.data.get_or_insert_with(|| serde_json::json!({}))["earlier"] = o;
    }
    resp
}

/// Send a chat message to an agent connection.
///
/// Routes through the vault's `agent.message-reply` op (same handler
/// the phone uses) instead of `message.send`. The two paths can't be
/// unified because peer messages encrypt under a SharedSecret that
/// agent connections lack — they have an AgentSession key instead,
/// and the vault dispatches to a different encryption codepath
/// based on which op was called. Front-end branches on
/// `connection.connection_type === 'agent'` before deciding which
/// command to invoke. See vettid-dev/enclave/vault-manager/
/// agent_handler.go HandleAgentMessageReply (live as of v5).
#[tauri::command]
pub async fn send_agent_message(
    state: State<'_, AppState>,
    connection_id: String,
    content: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "agent.message-reply",
        serde_json::json!({
            "connection_id": connection_id,
            "content": content,
        }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// A page of a conversation (`message.list`, §10.5, §10.5.2), a read:
/// without `before` the newest page, with it the page before that
/// message. `limit` 1 to 500 (the vault's default is 100). Answers
/// `{messages, next_before?, unreadable}` ([`shape::message_list`]),
/// oldest first; `next_before` is there only when older messages remain.
/// Volatile at the vault and kept in memory only here.
///
/// A `before` the vault no longer holds is `page_gone`: the view starts
/// again from the newest page.
#[tauri::command]
pub async fn get_conversation(state: State<'_, AppState>, connection_id: String, before: Option<String>, limit: Option<u32>) -> Result<VaultOpResponse, String> {
    let body = match conversation_body(&connection_id, before.as_deref(), limit) {
        Ok(b) => b,
        Err(e) => return Ok(VaultOpResponse::from_link(Err(e))),
    };
    let paged = body.get("before").is_some();
    let r = link_run(&state, "message.list", body, |v| shape::message_list(v, &connection_id), How::Read).await.result;
    Ok(VaultOpResponse::from_link(page_gone(r, paged)))
}

/// `message.list`'s body, once its arguments check out. An empty `before`
/// is no `before` (the newest page).
fn conversation_body(connection_id: &str, before: Option<&str>, limit: Option<u32>) -> Result<serde_json::Value, OpError> {
    let before = before.filter(|b| !b.is_empty());
    if connection_id.is_empty() || connection_id.len() > MAX_ID_LEN || before.is_some_and(|b| b.len() > MAX_ID_LEN) || limit.is_some_and(|l| l == 0 || l as usize > shape::MESSAGES_MAX) {
        return Err(OpError::BadArgument);
    }
    let mut body = serde_json::json!({ "connection_id": connection_id });
    if let Some(l) = limit {
        body["limit"] = l.into();
    }
    if let Some(b) = before {
        body["before"] = b.into();
    }
    Ok(body)
}

/// `not_found` to a page asked for with `before`: that message is gone
/// (§10.5.2), said as [`OpError::PageGone`].
fn page_gone(r: Result<serde_json::Value, OpError>, paged: bool) -> Result<serde_json::Value, OpError> {
    match r {
        Err(OpError::Vault(c)) if paged && c == "not_found" => Err(OpError::PageGone),
        r => r,
    }
}

/// List call history (independent).
#[tauri::command]
pub async fn list_call_history(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "call.history", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Fetch short-lived Cloudflare TURN credentials for WebRTC NAT
/// traversal. Returns `{ice_servers: [...], expires_at: "..."}`. The
/// vault proxies to the AWS Lambda + caches the HMAC pair for the
/// session — the desktop calls this once per call (or when the cached
/// creds are near expiry).
#[tauri::command]
pub async fn get_turn_credentials(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "call.turn-credentials", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Mark a set of call records as seen (clears the bold "Missed call"
/// badge on connection cards). `call_ids` is the list of records to
/// acknowledge; vault stamps SeenAt = now on each.
#[tauri::command]
pub async fn mark_calls_seen(
    state: State<'_, AppState>,
    call_ids: Vec<String>,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "call.mark-seen",
        serde_json::json!({ "call_ids": call_ids }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

// ---------------------------------------------------------------------------
// Missing wallet commands (parity with iOS WalletClient)
// ---------------------------------------------------------------------------

/// Create a new wallet (phone-required — key generation in enclave).
#[tauri::command]
pub async fn create_wallet(state: State<'_, AppState>, label: String, network: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "wallet.create",
        serde_json::json!({ "label": label, "network": network }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get receive address for a wallet.
#[tauri::command]
pub async fn get_wallet_address(state: State<'_, AppState>, wallet_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "wallet.get-address",
        serde_json::json!({ "wallet_id": wallet_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get fee estimates from mempool.
#[tauri::command]
pub async fn get_fee_estimates(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "wallet.get-fees", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Delete a wallet (phone-required).
#[tauri::command]
pub async fn delete_wallet(state: State<'_, AppState>, wallet_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "wallet.delete",
        serde_json::json!({ "wallet_id": wallet_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Set wallet visibility (phone-required — making public is irreversible).
#[tauri::command]
pub async fn set_wallet_visibility(state: State<'_, AppState>, wallet_id: String, is_public: bool) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "wallet.set-visibility",
        serde_json::json!({ "wallet_id": wallet_id, "is_public": is_public }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Update a minor secret in place (phone-required). Any field passed
/// as Some(...) replaces the existing value; None leaves it alone.
#[tauri::command]
pub async fn update_secret(
    state: State<'_, AppState>,
    id: String,
    name: Option<String>,
    value: Option<String>,
    category: Option<String>,
    alias: Option<String>,
    description: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut payload = serde_json::json!({ "id": id });
    if let Some(n) = name { payload["name"] = serde_json::Value::String(n); }
    if let Some(v) = value { payload["value"] = serde_json::Value::String(v); }
    if let Some(c) = category { payload["category"] = serde_json::Value::String(c); }
    if let Some(a) = alias { payload["alias"] = serde_json::Value::String(a); }
    if let Some(d) = description { payload["description"] = serde_json::Value::String(d); }
    let result = operations::execute_phone_required(&state, "secret.update", payload).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Delete a minor secret (phone-required).
#[tauri::command]
pub async fn delete_secret(state: State<'_, AppState>, id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "secret.delete",
        serde_json::json!({ "id": id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Rotate the E2E keys for a connection. Phone-required.
#[tauri::command]
pub async fn rotate_connection_keys(
    state: State<'_, AppState>,
    connection_id: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "connection.rotate",
        serde_json::json!({ "connection_id": connection_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Challenge a peer's identity (proves they still hold the private key
/// that bound the connection). Phone-required to authorize the
/// challenge — the verification result arrives asynchronously via the
/// vault's verify-state push and is read with `connection.list`.
#[tauri::command]
pub async fn authenticate_connection(
    state: State<'_, AppState>,
    connection_id: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "connection.authenticate",
        serde_json::json!({ "connection_id": connection_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Read cached verify-identity state for one connection. Returns the
/// last outbound + inbound outcomes (timestamps, ok/failed, reason) so
/// the Detail screen can render "Verified 3 minutes ago" without a
/// fresh challenge. Vault is the source of truth — survives PIN-lock
/// and re-seal.
#[tauri::command]
pub async fn get_connection_verify_state(
    state: State<'_, AppState>,
    connection_id: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "connection-authenticate.get",
        serde_json::json!({ "connection_id": connection_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Delete personal-data fields by namespace (phone-required). The vault
/// keys storage as `personal-data/<namespace>`, so for aliased fields
/// the composite key (e.g. `contact.phone.mobile::Wife`) is passed
/// verbatim to delete just that variant.
#[tauri::command]
pub async fn delete_personal_data_fields(
    state: State<'_, AppState>,
    namespaces: Vec<String>,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "personal-data.delete",
        serde_json::json!({ "namespaces": namespaces }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Request payment from a connection.
#[tauri::command]
pub async fn request_payment(
    state: State<'_, AppState>,
    connection_id: String,
    wallet_id: String,
    amount_sats: i64,
    memo: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({
        "connection_id": connection_id,
        "wallet_id": wallet_id,
        "amount_sats": amount_sats,
    });
    if let Some(m) = memo {
        params["memo"] = serde_json::json!(m);
    }
    let result = operations::execute(&state, "wallet.request-payment", params).await;
    Ok(VaultOpResponse::from_op(result))
}

// ---------------------------------------------------------------------------
// Data-sharing — grants, share policies, presence overrides, location
// sharing. All ops in DeviceIndependentCapabilities (no phone approval
// gate — they're metadata operations or already require an out-of-band
// approval flow on top).
// ---------------------------------------------------------------------------

/// Request access to a single item on a peer's published catalog.
/// `mode` ∈ {"one-shot","renewable","agent-renewable"}.
#[tauri::command]
pub async fn grant_request(
    state: State<'_, AppState>,
    connection_id: String,
    item_kind: String,
    item_ref: String,
    item_label: String,
    mode: String,
    requested_expires_at: Option<i64>,
    requested_max_uses: Option<i32>,
    reason: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({
        "connection_id": connection_id,
        "item_kind": item_kind,
        "item_ref": item_ref,
        "item_label": item_label,
        "mode": mode,
        "deliver_to": "self",
    });
    if let Some(v) = requested_expires_at { params["requested_expires_at"] = serde_json::json!(v); }
    if let Some(v) = requested_max_uses { params["requested_max_uses"] = serde_json::json!(v); }
    if let Some(v) = reason { params["reason"] = serde_json::json!(v); }
    let result = operations::execute(&state, "grant.request", params).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Request a group of items in one approval bundle. `items` is an array
/// of `{item_kind, item_ref, item_label}` objects.
#[tauri::command]
pub async fn grant_request_group(
    state: State<'_, AppState>,
    connection_id: String,
    items: Vec<serde_json::Value>,
    mode: String,
    requested_expires_at: Option<i64>,
    requested_max_uses: Option<i32>,
    reason: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({
        "connection_id": connection_id,
        "items": items,
        "mode": mode,
        "deliver_to": "self",
    });
    if let Some(v) = requested_expires_at { params["requested_expires_at"] = serde_json::json!(v); }
    if let Some(v) = requested_max_uses { params["requested_max_uses"] = serde_json::json!(v); }
    if let Some(v) = reason { params["reason"] = serde_json::json!(v); }
    let result = operations::execute(&state, "grant.request", params).await;
    Ok(VaultOpResponse::from_op(result))
}

#[tauri::command]
pub async fn grant_approve(
    state: State<'_, AppState>,
    request_id: String,
    expires_at: Option<i64>,
    max_uses: Option<i32>,
    mode: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({ "request_id": request_id });
    if let Some(v) = expires_at { params["expires_at"] = serde_json::json!(v); }
    if let Some(v) = max_uses { params["max_uses"] = serde_json::json!(v); }
    if let Some(v) = mode { params["mode"] = serde_json::json!(v); }
    let result = operations::execute(&state, "grant.approve", params).await;
    Ok(VaultOpResponse::from_op(result))
}

#[tauri::command]
pub async fn grant_deny(
    state: State<'_, AppState>,
    request_id: String,
    reason: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({ "request_id": request_id });
    if let Some(v) = reason { params["reason"] = serde_json::json!(v); }
    let result = operations::execute(&state, "grant.deny", params).await;
    Ok(VaultOpResponse::from_op(result))
}

#[tauri::command]
pub async fn grant_revoke(
    state: State<'_, AppState>,
    grant_id: String,
    reason: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({ "grant_id": grant_id });
    if let Some(v) = reason { params["reason"] = serde_json::json!(v); }
    let result = operations::execute(&state, "grant.revoke", params).await;
    Ok(VaultOpResponse::from_op(result))
}

#[tauri::command]
pub async fn grant_list_pending(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "grant.list-pending", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

#[tauri::command]
pub async fn grant_list_inbound(
    state: State<'_, AppState>,
    connection_id: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({});
    if let Some(c) = connection_id { params["connection_id"] = serde_json::json!(c); }
    let result = operations::execute(&state, "grant.list-inbound", params).await;
    Ok(VaultOpResponse::from_op(result))
}

#[tauri::command]
pub async fn grant_list_outbound(
    state: State<'_, AppState>,
    connection_id: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({});
    if let Some(c) = connection_id { params["connection_id"] = serde_json::json!(c); }
    let result = operations::execute(&state, "grant.list-outbound", params).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List requests *I* sent to peers — both pending and resolved.
#[tauri::command]
pub async fn grant_list_my_requests(
    state: State<'_, AppState>,
    connection_id: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({});
    if let Some(c) = connection_id { params["connection_id"] = serde_json::json!(c); }
    let result = operations::execute(&state, "grant.list-my-requests", params).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Fetch the actual referenced value for an approved grant (one use
/// against `max_uses`). Returns the decrypted value the peer authorized.
#[tauri::command]
pub async fn grant_fetch_remote(
    state: State<'_, AppState>,
    grant_id: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "grant.fetch-remote",
        serde_json::json!({ "grant_id": grant_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Read the per-connection share policy (which catalog items this peer
/// is allowed to fetch and under what limits).
#[tauri::command]
pub async fn share_policy_get(
    state: State<'_, AppState>,
    connection_id: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "connection.share-policy.get",
        serde_json::json!({ "connection_id": connection_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Replace the per-connection share policy. `items` is a map from
/// `"<kind>:<id>"` keys to `{allowed, tier?, retention?,
/// rate_limit_per_hour?, expires_at?}` objects.
#[tauri::command]
pub async fn share_policy_set(
    state: State<'_, AppState>,
    connection_id: String,
    items: serde_json::Value,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "connection.share-policy.set",
        serde_json::json!({ "connection_id": connection_id, "items": items }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Override the user's default presence visibility for one connection.
/// `override` of `null` clears (back to default), `true` shows online,
/// `false` hides.
#[tauri::command]
pub async fn presence_override_set(
    state: State<'_, AppState>,
    connection_id: String,
    r#override: Option<bool>,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "presence.override.set",
        serde_json::json!({ "connection_id": connection_id, "override": r#override }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The conversation commands as they run: their arguments, then the link
    // (against the fake vault), then what the window gets.
    use crate::link::fake::FakeVault;
    use crate::link::ops::OP_FORBIDDEN_NOTICE;
    use crate::link::Link;
    use chrono::{TimeDelta, Utc};
    use serde_json::json;
    use tokio::sync::Mutex;
    use vettid_device::pairing::SystemClock;

    type Slot = Mutex<Option<Link<FakeVault, SystemClock>>>;

    async fn live(dir: &std::path::Path) -> (FakeVault, Slot) {
        let (vault, mut link) = FakeVault::paired(dir);
        vault.set_session(Some(("s-1", Utc::now() + TimeDelta::hours(1))));
        link.read_status().await.unwrap();
        (vault, Mutex::new(Some(link)))
    }

    async fn run(s: &Slot, kind: &str, body: serde_json::Value, shape: impl Fn(&serde_json::Value) -> Result<serde_json::Value, BadShape>, how: How) -> Ran {
        link_run_with(s, || true, || false, |_| {}, std::future::pending(), kind, body, shape, how).await
    }

    /// get_conversation as the command runs it.
    async fn conversation(s: &Slot, id: &str, before: Option<&str>, limit: Option<u32>) -> VaultOpResponse {
        let body = match conversation_body(id, before, limit) {
            Ok(b) => b,
            Err(e) => return VaultOpResponse::from_link(Err(e)),
        };
        let paged = body.get("before").is_some();
        let r = run(s, "message.list", body, |v| shape::message_list(v, id), How::Read).await.result;
        VaultOpResponse::from_link(page_gone(r, paged))
    }

    async fn send(s: &Slot, id: &str, text: &str) -> VaultOpResponse {
        match send_body(id, text) {
            Ok(b) => {
                let ran = run(s, "message.send", b, shape::message_sent, How::KeptFirst).await;
                sent_response(ran)
            }
            Err(e) => VaultOpResponse::from_link(Err(e)),
        }
    }

    const PAGE: &str = r#"{"messages":[{"message_id":"m-1","direction":"out","text":"first","sent_at":"2026-11-25T10:00:00Z","delivered":true,"read":true},
        {"message_id":"m-2","direction":"in","text":"second","sent_at":"2026-11-25T10:01:00Z","delivered":true,"read":false},
        {"message_id":"m-3","direction":"up","text":"bad","sent_at":"2026-11-25T10:02:00Z","delivered":true,"read":false}],"next_before":"m-1"}"#;

    #[tokio::test]
    async fn a_conversation_page() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, s) = live(dir.path()).await;
        vault.answer("message.list", Ok(PAGE));
        let r = conversation(&s, "c-1", None, Some(20)).await;
        assert!(r.success, "{r:?}");
        let d = r.data.unwrap();
        assert_eq!((d["messages"].as_array().unwrap().len(), d["unreadable"].as_u64(), d["next_before"].as_str()), (2, Some(1), Some("m-1")));
        assert_eq!((d["messages"][0]["connection_id"].as_str(), d["messages"][1]["text"].as_str()), (Some("c-1"), Some("second")));
        // A page the vault no longer has: page_gone, said with no new text.
        vault.answer("message.list", Err("not_found"));
        let r = conversation(&s, "c-1", Some("m-1"), None).await;
        assert_eq!((r.success, r.error_code, r.error.as_deref()), (false, Some("page_gone"), Some(crate::link::ops::OP_NOT_FOUND_NOTICE)));
        // Without before it stays not_found.
        assert_eq!(conversation(&s, "c-1", None, None).await.error_code, Some("not_found"));
        // An unknown connection is an empty page.
        vault.answer("message.list", Ok(r#"{"messages":[]}"#));
        assert_eq!(conversation(&s, "c-9", Some(""), None).await.data, Some(json!({"messages": [], "unreadable": 0})));
    }

    #[test]
    fn conversation_arguments() {
        assert_eq!(conversation_body("c-1", Some("m-1"), Some(500)), Ok(json!({"connection_id": "c-1", "before": "m-1", "limit": 500})));
        assert_eq!(conversation_body("c-1", Some(""), None), Ok(json!({"connection_id": "c-1"})), "an empty before is the newest page");
        for (id, before, limit) in [("", None, None), ("c-1", None, Some(0)), ("c-1", None, Some(501))] {
            assert_eq!(conversation_body(id, before, limit), Err(OpError::BadArgument), "{id} {limit:?}");
        }
        let long = "m".repeat(MAX_ID_LEN + 1);
        assert_eq!(conversation_body("c-1", Some(&long), None), Err(OpError::BadArgument));
        assert_eq!(read_body("c-1", ""), Err(OpError::BadArgument));
        assert_eq!(read_body("", "m-1"), Err(OpError::BadArgument));
    }

    /// 1 B to 16 KiB of UTF-8, counted in bytes; nothing is sent otherwise.
    #[tokio::test]
    async fn send_arguments_are_checked_before_anything_is_sent() {
        assert!(send_body("c-1", &"x".repeat(MAX_TEXT_LEN)).is_ok());
        assert!(send_body("c-1", "x").is_ok());
        for (id, text) in [("", "hi".to_string()), ("c-1", String::new()), ("c-1", "x".repeat(MAX_TEXT_LEN + 1)), ("c-1", "é".repeat(MAX_TEXT_LEN / 2 + 1)), (&"c".repeat(MAX_ID_LEN + 1), "hi".to_string())] {
            assert_eq!(send_body(id, &text), Err(OpError::BadArgument), "{} {}", id.len(), text.len());
        }
        let dir = tempfile::tempdir().unwrap();
        let (vault, s) = live(dir.path()).await;
        vault.answer("message.send", Ok(r#"{"message_id":"m-9","sent_at":"2026-11-25T10:00:00Z"}"#));
        let r = send(&s, "c-1", "").await;
        assert_eq!(r.error_code, Some("bad_argument"));
        assert!(vault.deposited().iter().all(|k| k != "message.send"), "sent");
    }

    #[tokio::test]
    async fn a_message_is_sent_and_read_marked() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, s) = live(dir.path()).await;
        vault.answer("message.send", Ok(r#"{"message_id":"m-9","sent_at":"2026-11-25T10:00:00Z"}"#));
        let r = send(&s, "c-1", "hello").await;
        assert!(r.success, "{r:?}");
        assert_eq!(r.data, Some(json!({"message_id": "m-9", "sent_at": "2026-11-25T10:00:00Z"})));
        vault.answer("message.read", Ok("{}"));
        let r = run(&s, "message.read", read_body("c-1", "m-2").unwrap(), shape::empty, How::Read).await.result;
        assert_eq!(r, Ok(json!({})));
        vault.answer("message.read", Err("not_found"));
        let r = run(&s, "message.read", read_body("c-1", "m-9").unwrap(), shape::empty, How::Read).await.result;
        assert_eq!(VaultOpResponse::from_link(r).error_code, Some("not_found"));
    }

    /// A service connection takes no messages: the vault's `forbidden`
    /// reaches the view as `forbidden`, with the existing text.
    #[tokio::test]
    async fn forbidden_is_passed_on() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, s) = live(dir.path()).await;
        vault.answer("message.send", Err("forbidden"));
        let r = send(&s, "svc-1", "hello").await;
        assert_eq!((r.success, r.error_code, r.error.as_deref()), (false, Some("forbidden"), Some(OP_FORBIDDEN_NOTICE)));
        assert!(r.data.is_none());
        vault.answer("message.send", Err("connection_unavailable"));
        assert_eq!(send(&s, "c-1", "hello").await.error_code, Some("connection_unavailable"));
    }

    const SENT: &str = r#"{"message_id":"m-9","sent_at":"2026-11-25T10:00:00Z"}"#;

    /// A send the relay took but the vault didn't answer in time is kept in
    /// memory (never in the stored outbox): the same text again goes under
    /// its id, so the vault sees one message; another text first retries
    /// it, and the answer says what became of it.
    #[tokio::test]
    async fn an_unanswered_send_is_kept_and_retried_under_its_id() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, s) = live(dir.path()).await; // message.send taken, not answered
        let r = send(&s, "c-1", "first").await;
        assert_eq!((r.success, r.error_code), (false, Some("unconfirmed")));
        // The token the view keeps with its message.
        let token = r.data.as_ref().and_then(|d| d["pending_id"].as_str()).expect("a pending_id").to_string();
        assert_eq!(vault.deposited_ids("message.send"), std::slice::from_ref(&token), "the request id");
        // Still unanswered: another message isn't sent behind it.
        let r = send(&s, "c-2", "second").await;
        assert_eq!(r.error_code, Some("earlier_unconfirmed"));
        assert_eq!(r.data.as_ref().map(|d| d["earlier"].clone()), Some(json!({"pending_id": token, "connection_id": "c-1", "success": false, "error_code": "unconfirmed", "error": crate::link::ops::OP_UNCONFIRMED_NOTICE})));
        assert!(r.data.as_ref().unwrap().get("pending_id").is_none(), "the second one isn't kept");
        vault.answer("message.send", Ok(SENT));
        let r = send(&s, "c-1", "first").await;
        assert!(r.success && r.data.as_ref().unwrap().get("earlier").is_none(), "{r:?}");
        assert_eq!(vault.deposited_ids("message.send").len(), 1, "one message to the vault, under the kept id: {:?}", vault.deposited());
        // Kept again, then another text: the kept one first, then the new one.
        vault.unanswer("message.send");
        let third = send(&s, "c-1", "third").await.data.unwrap()["pending_id"].clone();
        vault.answer("message.send", Ok(SENT));
        let r = send(&s, "c-1", "fourth").await;
        assert!(r.success, "{r:?}");
        let d = r.data.unwrap();
        assert_eq!(d["earlier"], json!({"pending_id": third, "connection_id": "c-1", "success": true, "data": {"message_id": "m-9", "sent_at": "2026-11-25T10:00:00Z"}}));
        assert_eq!(d["message_id"], "m-9");
        assert_eq!(vault.deposited_ids("message.send").len(), 3, "the first, the kept third, the fourth");
        assert!(!serde_json::to_string(&d).unwrap().contains("third"), "the kept text isn't echoed");
    }

    /// A send taken but unanswered, then the relay out of reach: the same
    /// text again is still `unconfirmed` (never `not_sent`), and kept.
    #[tokio::test]
    async fn a_retry_with_the_relay_out_of_reach_stays_unconfirmed() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, s) = live(dir.path()).await; // taken, not answered
        let first = send(&s, "c-1", "first").await;
        assert_eq!(first.error_code, Some("unconfirmed"));
        vault.offline(true);
        let r = send(&s, "c-1", "first").await;
        assert_eq!((r.success, r.error_code), (false, Some("unconfirmed")), "{r:?}");
        assert_eq!(r.data.as_ref().map(|d| d["pending_id"].clone()), first.data.as_ref().map(|d| d["pending_id"].clone()), "the same token");
        // Locked, known before the retry: still unconfirmed.
        vault.offline(false);
        vault.lock_vault(None);
        let _ = s.lock().await.as_mut().unwrap().read_status().await;
        let locked = send(&s, "c-1", "first").await;
        assert_eq!((locked.success, locked.error_code), (false, Some("unconfirmed")), "{locked:?}");
        // No unconfirmed answer says the opposite.
        for a in [&first, &r, &locked] {
            let n = a.error.as_deref().unwrap_or("");
            assert!(n.contains("may still happen") && !n.contains("Try again") && !n.contains("couldn't send"), "{n}");
        }
        assert_eq!(r.error.as_deref(), Some(crate::link::ops::OP_UNCONFIRMED_UNREACHABLE_NOTICE));
        assert!(locked.error.as_deref().unwrap_or("").starts_with(crate::link::VAULT_LOCKED_NOTICE));
    }

    /// The vault answered ok, but its answer doesn't read: never a "try
    /// again" code, and nothing goes again on its own (the view reads the
    /// conversation before it offers another send).
    #[tokio::test]
    async fn an_unreadable_send_answer_isnt_try_again() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, s) = live(dir.path()).await;
        vault.answer("message.send", Ok(r#"{"message_id":"m-9","sent_at":"not a time"}"#));
        let r = send(&s, "c-1", "hello").await;
        assert_eq!((r.success, r.error_code), (false, Some("answer_unreadable")));
        assert!(!r.error.as_deref().unwrap_or("").contains("Try again"), "{r:?}");
        assert!(r.data.is_none(), "nothing kept: no pending_id");
        assert_eq!(vault.deposited_ids("message.send").len(), 1);
    }

    /// With the relay out of reach a send isn't stored to go later: it is
    /// `not_sent`, nothing is kept, and the vault never sees it. Sent again
    /// once the relay is back, the vault sees one message.
    #[tokio::test]
    async fn a_send_the_relay_never_took_is_not_sent() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, s) = live(dir.path()).await;
        vault.answer("message.send", Ok(SENT));
        vault.offline(true);
        let r = send(&s, "c-1", "first").await;
        assert_eq!((r.success, r.error_code), (false, Some("not_sent")));
        vault.offline(false);
        let r = send(&s, "c-1", "first").await;
        assert!(r.success && r.data.as_ref().unwrap().get("earlier").is_none(), "{r:?}");
        assert_eq!(vault.deposited_ids("message.send").len(), 1);
    }

    /// Plaintext never reaches Debug, with a send kept unconfirmed.
    #[tokio::test]
    async fn plaintext_isnt_in_debug() {
        let r = VaultOpResponse::from_link(Ok(json!({"messages": [{"text": "meet at noon"}]})));
        let d = format!("{r:?}");
        assert!(!d.contains("noon"), "{d}");
        let dir = tempfile::tempdir().unwrap();
        let (_vault, s) = live(dir.path()).await; // taken, not answered: kept
        assert_eq!(send(&s, "c-1", "meet at noon").await.error_code, Some("unconfirmed"));
        let g = s.lock().await;
        let d = format!("{:?}", g.as_ref().unwrap());
        assert!(!d.contains("noon"), "{d}");
    }

    /// Every vault operation reaches the frontend as one plain error, with
    /// nothing claimed: no success, no data, no pending approval.
    #[test]
    fn an_unavailable_operation_claims_nothing() {
        let json = serde_json::to_value(VaultOpResponse::from_op(Err(operations::OperationError::NotAvailable))).unwrap();
        assert_eq!(json["success"], false);
        assert_eq!(json["error"], operations::NOT_AVAILABLE);
        assert!(json["error_code"].is_null());
        assert!(json["data"].is_null());
        assert_eq!(json["pending_approval"], false);
    }
}
