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
    status: 'pending' | 'active' | 'revoked' | 'expired';
    /** Not returned by `connection.list` — optional until the vault sends it. */
    direction?: 'outbound' | 'inbound';
    created_at: string;
    e2e_public_key?: string;
    peer_profile?: PeerProfile;
}

export interface PeerProfile {
    first_name?: string;
    last_name?: string;
    email?: string;
    photo?: string;
    fields?: Record<string, { display_name: string; value: string }>;
}

export interface Message {
    id: string;
    connection_id: string;
    sender_id: string;
    content: string;
    content_type: 'text' | 'image' | 'file' | 'btc_address' | 'payment_request' | 'btc_payment_receipt';
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
    peer_display_name?: string;
    call_type: 'audio' | 'video';
    direction: 'incoming' | 'outgoing';
    end_reason: 'completed' | 'missed' | 'rejected' | 'failed' | 'cancelled';
    initiated_at: string;
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
