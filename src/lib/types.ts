// ---------------------------------------------------------------------------
// Shared TypeScript types for the desktop app
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
    /** @deprecated `connection.list` sends `peer_alias`; this is never populated. */
    label?: string;
    /** Kind of connection — "peer" by default, also "agent" or "device". */
    connection_type?: 'peer' | 'agent' | 'device';
    status: 'pending' | 'active' | 'revoked' | 'expired';
    /** Not returned by `connection.list` — optional until the vault sends it. */
    direction?: 'outbound' | 'inbound';
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

export interface Message {
    id: string;
    connection_id: string;
    sender_id: string;
    content: string;
    content_type: 'text' | 'image' | 'file' | 'btc_address' | 'payment_request' | 'btc_payment_receipt' | 'btc_payment_decline';
    sent_at: string;
    status: 'sending' | 'sent' | 'delivered' | 'read' | 'failed';
}

export interface FeedEvent {
    event_id: string;
    event_type: string;
    title?: string;
    message?: string;
    timestamp: string;
    is_read: boolean;
    connection_id?: string;
}

export interface SecretEntry {
    id: string;
    name: string;
    category: string;
    created_at: string;
    last_accessed?: string;
}

export interface Proposal {
    id: string;
    title: string;
    description: string;
    status: 'upcoming' | 'open' | 'closed';
    created_at: string;
    closes_at?: string;
    vote_count?: number;
    my_vote?: 'yes' | 'no' | 'abstain';
}

export interface PersonalDataItem {
    field_id: string;
    display_name: string;
    value: string;
    category: string;
    updated_at?: string;
}

export interface WalletInfo {
    wallet_id: string;
    label: string;
    address: string;
    network: 'mainnet' | 'testnet';
    cached_balance_sats: number;
    is_public: boolean;
}

export interface TxHistoryEntry {
    txid: string;
    direction: 'sent' | 'received';
    amount_sats: number;
    fee_sats: number;
    confirmed: boolean;
    block_time?: string;
}

export interface AuditLogEntry {
    id: string;
    event_type: string;
    timestamp: string;
    details?: string;
    actor?: string;
}

export interface ConnectedDevice {
    device_id: string;
    hostname: string;
    platform: string;
    status: 'active' | 'suspended' | 'expired' | 'revoked';
    connected_at: string;
    last_heartbeat?: string;
}

export interface CallHistoryEntry {
    call_id: string;
    caller_id?: string;
    callee_id?: string;
    connection_id?: string;
    call_type?: 'voice' | 'video';
    direction: 'incoming' | 'outgoing';
    status?: 'initiated' | 'answered' | 'missed' | 'rejected' | 'blocked';
    started_at?: number;
    answered_at?: number;
    ended_at?: number;
    duration_secs?: number;
    block_reason?: string;
    seen_at?: number;
    /** Compatibility fields for older shapes. */
    peer_display_name?: string;
    end_reason?: 'completed' | 'missed' | 'rejected' | 'failed' | 'cancelled';
    initiated_at?: string;
    duration?: number;
}

export interface Profile {
    guid: string;
    display_name: string;
    email?: string;
    photo_data?: string;
}

// Vault operation response from Tauri
export interface VaultOpResponse {
    success: boolean;
    data?: unknown;
    error?: string;
    pending_approval: boolean;
}
