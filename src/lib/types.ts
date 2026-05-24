// ---------------------------------------------------------------------------
// Shared TypeScript types for the desktop app
//
// SCOPE: every interface in this file is a wire-format contract — it
// must match exactly what the vault emits over NATS. If the vault
// renames a field or removes one, fix it here in the same change.
//
// We deliberately do NOT keep "view convenience" or "future scaffold"
// types here — those drift silently and have already bitten us four
// times (params/payload, peer_alias/label, message_id/id, sender_guid/
// sender_id). View-local response shapes belong in the view file.
// ---------------------------------------------------------------------------

export interface Connection {
    connection_id: string;
    /**
     * Peer's global identity. Absent (`omitempty` server-side) for the
     * system connection, device pairings, and agent connections —
     * always guard before dereferencing.
     */
    peer_guid?: string;
    /** The vault's `peer_alias` — the user-facing name for this connection. */
    peer_alias?: string;
    /** Kind of connection — "peer" by default, plus "agent", "device",
     *  and "system" (the auto-created VettID system connection). */
    connection_type?: 'peer' | 'agent' | 'device' | 'system';
    status: 'pending' | 'active' | 'revoked' | 'expired';
    created_at: string;
    e2e_public_key?: string;
    peer_profile?: PeerProfile;

    // --- Card-display fields — connection.list already returns these. ---
    unread_count?: number;
    last_message_preview?: string;
    last_message_at?: string;
    last_message_direction?: 'incoming' | 'outgoing';
    last_activity_type?: 'activity' | 'call';
    last_activity_at?: string;
    last_activity_title?: string;
    last_activity_direction?: 'incoming' | 'outgoing';
    last_activity_subtype?: 'voice' | 'video';
    last_activity_outcome?: 'completed' | 'missed' | 'rejected';
    missed_call_count?: number;
    is_favorite?: boolean;
    is_archived?: boolean;
    needs_attention?: boolean;
    peer_verifications?: string[];

    // --- Other ConnectionInfo fields — used by the detail screen. ---
    last_active_at?: string;
    last_rotated_at?: string;
    key_exchange_at?: string;
    key_rotation_count?: number;
    activity_count?: number;
    credentials_type?: string;
    e2e_ready?: boolean;
    credentials_expire_at?: string;
}

export interface PeerProfile {
    first_name?: string;
    last_name?: string;
    full_name?: string;
    email?: string;
    photo?: string;
    fields?: Record<string, { display_name: string; value: string }>;
    /** Items the peer has published in their data catalog — metadata
     *  only, no values. Used by the peer-catalog surface to offer
     *  "Request access" actions. */
    data_catalog?: PublishedCatalogItem[];
    /** Items the peer has published in their secret catalog — metadata
     *  only, values never travel here. */
    secret_catalog?: PublishedCatalogItem[];
}

export interface PublishedCatalogItem {
    name: string;
    display_name?: string;
    field_type?: string;
    type?: string;
    category?: string;
    alias?: string;
}

/**
 * One row from `message.list`. Field names mirror the vault's response
 * struct in enclave/vault-manager/messaging.go (HandleList's messageItem)
 * — when the two drift, the bug is silent until something assumes a
 * field is present (e.g. Svelte's keyed each on `message_id`). Keep this
 * in lockstep with the Go struct.
 *
 * Note: the vault does NOT echo `connection_id` in each row — the list
 * response carries one top-level `connection_id` and the messages
 * inherit it. So no per-message `connection_id` field here.
 */
export interface Message {
    message_id: string;
    /** "incoming" (peer → us) or "outgoing" (us → peer). Authoritative
     *  for sent-vs-received attribution; prefer over inferring from
     *  sender_guid. */
    direction: 'incoming' | 'outgoing';
    /** Sender's GUID — the peer's GUID for incoming, our ownerSpace
     *  for outgoing. Kept for downstream attribution (e.g. multi-party
     *  rooms one day) but not used for the sent/received decision. */
    sender_guid: string;
    content: string;
    content_type: 'text' | 'image' | 'file' | 'btc_address' | 'payment_request' | 'btc_payment_receipt' | 'btc_payment_decline';
    sent_at: string;
    status: 'sending' | 'sent' | 'delivered' | 'read' | 'failed';
}

/**
 * One row from `call.history`. Mirrors `CallRecord` in
 * enclave/vault-manager/calls.go — keep these in lockstep when the Go
 * struct changes.
 */
export interface CallHistoryEntry {
    call_id: string;
    caller_id?: string;
    callee_id?: string;
    /** Set when the vault has a matching local connection. */
    connection_id?: string;
    call_type?: 'voice' | 'video';
    direction: 'incoming' | 'outgoing';
    status?: 'initiated' | 'answered' | 'missed' | 'rejected' | 'blocked';
    /** Unix-epoch seconds (vault emits int64). */
    started_at?: number;
    answered_at?: number;
    ended_at?: number;
    duration_secs?: number;
    block_reason?: string;
    /** Unix-epoch seconds — set when the user has acknowledged this
     *  call (opened Call History, or completed a follow-up call with
     *  the same peer). Used to clear the "Missed" badge. */
    seen_at?: number;
}

// Vault operation response from Tauri
export interface VaultOpResponse {
    success: boolean;
    data?: unknown;
    error?: string;
    pending_approval: boolean;
}
