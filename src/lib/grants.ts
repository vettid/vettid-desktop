// Data-sharing client surface: grants, share policies, presence
// overrides. Mirrors the Android `GrantsRepository` so the same vault
// records render identically on either client.

import { invoke } from '@tauri-apps/api/core';
import type { VaultOpResponse } from './types';

// ---------------------------------------------------------------------------
// Types — mirror enclave/vault-manager/grant_handler.go shapes.
// ---------------------------------------------------------------------------

export type ItemKind = 'data' | 'secret' | 'wallet' | 'handler';
export type GrantMode = 'one-shot' | 'renewable' | 'agent-renewable';
export type GrantStatus = 'active' | 'revoked' | 'expired';
export type Tier = 'required' | 'optional' | 'on_demand' | 'consent';
export type Retention = 'session' | 'time_limited' | 'until_revoked';

/** A grant record — the result of an approved access request. Returned
 *  by `grant.list-inbound` and `grant.list-outbound`. */
export interface GrantSummary {
    grant_id: string;
    owner_guid: string;
    requester_guid: string;
    granter_guid: string;
    connection_id: string;
    item_kind: ItemKind;
    item_ref: string;
    item_label: string;
    mode: GrantMode;
    expires_at: number; // unix seconds; 0 = never
    max_uses: number;
    uses_so_far: number;
    status: GrantStatus;
    created_at: number;
    granted_at: number;
    last_fetched: number;
}

/** A pending inbound request — the peer asked for access, the user
 *  hasn't approved/denied yet. */
export interface PendingRequestSummary {
    request_id: string;
    requester_guid: string;
    connection_id: string;
    item_kind: ItemKind;
    item_ref: string;
    item_label: string;
    /** ≥1 entry — group requests use this; single-item requests still
     *  populate it for uniform handling. */
    items: Array<{ item_kind: ItemKind; item_ref: string; item_label: string }>;
    requested_mode: GrantMode;
    requested_expires_at: number;
    requested_max_uses: number;
    deliver_to: string;
    reason: string;
    received_at: number;
}

/** An outgoing request — what I asked a peer for. */
export interface OutgoingRequestSummary {
    request_id: string;
    connection_id: string;
    item_kind: ItemKind;
    item_ref: string;
    item_label: string;
    mode: GrantMode;
    reason: string;
    /** "pending" until the peer responds; then "approved" or "denied". */
    status: 'pending' | 'approved' | 'denied';
    grant_id: string;
    denial_reason: string;
    created_at: number;
    responded_at: number;
}

/** One entry in a per-connection share policy. */
export interface SharePolicyItem {
    allowed: boolean;
    tier?: Tier;
    retention?: Retention;
    rate_limit_per_hour?: number;
    expires_at?: number;
}

export interface SharePolicy {
    /** Keyed by `"<kind>:<id>"`, e.g. `"data:contact.phone.mobile::Wife"`. */
    items: Record<string, SharePolicyItem>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function unwrap<T>(resp: VaultOpResponse): T {
    if (!resp.success) throw new Error(resp.error ?? 'vault op failed');
    return (resp.data ?? {}) as T;
}

// ---------------------------------------------------------------------------
// Requests (outbound — I'm asking peer for something)
// ---------------------------------------------------------------------------

export interface GrantRequestArgs {
    connectionId: string;
    itemKind: ItemKind;
    itemRef: string;
    itemLabel: string;
    mode?: GrantMode;
    requestedExpiresAt?: number;
    requestedMaxUses?: number;
    reason?: string;
}

export async function requestAccess(args: GrantRequestArgs): Promise<{ request_id: string }> {
    const resp = (await invoke('grant_request', {
        connectionId: args.connectionId,
        itemKind: args.itemKind,
        itemRef: args.itemRef,
        itemLabel: args.itemLabel,
        mode: args.mode ?? 'one-shot',
        requestedExpiresAt: args.requestedExpiresAt,
        requestedMaxUses: args.requestedMaxUses,
        reason: args.reason,
    })) as VaultOpResponse;
    return unwrap<{ request_id: string }>(resp);
}

export async function requestAccessGroup(
    connectionId: string,
    items: Array<{ item_kind: ItemKind; item_ref: string; item_label: string }>,
    mode: GrantMode = 'one-shot',
    reason?: string,
): Promise<{ request_id: string }> {
    const resp = (await invoke('grant_request_group', {
        connectionId,
        items,
        mode,
        reason,
    })) as VaultOpResponse;
    return unwrap<{ request_id: string }>(resp);
}

// ---------------------------------------------------------------------------
// Approvals (inbound — I'm answering a peer)
// ---------------------------------------------------------------------------

export async function approveRequest(
    requestId: string,
    expiresAt?: number,
    maxUses?: number,
    mode?: GrantMode,
): Promise<{ grant_id: string }> {
    const resp = (await invoke('grant_approve', {
        requestId,
        expiresAt,
        maxUses,
        mode,
    })) as VaultOpResponse;
    return unwrap<{ grant_id: string }>(resp);
}

export async function denyRequest(requestId: string, reason?: string): Promise<void> {
    const resp = (await invoke('grant_deny', { requestId, reason })) as VaultOpResponse;
    unwrap(resp);
}

export async function revokeGrant(grantId: string, reason?: string): Promise<void> {
    const resp = (await invoke('grant_revoke', { grantId, reason })) as VaultOpResponse;
    unwrap(resp);
}

// ---------------------------------------------------------------------------
// Listings
// ---------------------------------------------------------------------------

export async function listPending(): Promise<PendingRequestSummary[]> {
    const resp = (await invoke('grant_list_pending')) as VaultOpResponse;
    const data = unwrap<{ pending?: PendingRequestSummary[] }>(resp);
    return data.pending ?? [];
}

export async function listInbound(connectionId?: string): Promise<GrantSummary[]> {
    const resp = (await invoke('grant_list_inbound', { connectionId })) as VaultOpResponse;
    const data = unwrap<{ grants?: GrantSummary[] }>(resp);
    return data.grants ?? [];
}

export async function listOutbound(connectionId?: string): Promise<GrantSummary[]> {
    const resp = (await invoke('grant_list_outbound', { connectionId })) as VaultOpResponse;
    const data = unwrap<{ grants?: GrantSummary[] }>(resp);
    return data.grants ?? [];
}

export async function listMyRequests(connectionId?: string): Promise<OutgoingRequestSummary[]> {
    const resp = (await invoke('grant_list_my_requests', { connectionId })) as VaultOpResponse;
    const data = unwrap<{ requests?: OutgoingRequestSummary[] }>(resp);
    return data.requests ?? [];
}

export async function fetchRemoteValue(grantId: string): Promise<unknown> {
    // Returns the decoded value the peer authorized for this grant.
    // Shape varies by item kind (string for data, base64 for secret, etc.) —
    // callers know what to expect based on the grant's item_kind.
    const resp = (await invoke('grant_fetch_remote', { grantId })) as VaultOpResponse;
    return unwrap(resp);
}

// ---------------------------------------------------------------------------
// Share policy
// ---------------------------------------------------------------------------

export async function getSharePolicy(connectionId: string): Promise<SharePolicy> {
    const resp = (await invoke('share_policy_get', { connectionId })) as VaultOpResponse;
    const data = unwrap<{ policy?: SharePolicy }>(resp);
    return data.policy ?? { items: {} };
}

export async function setSharePolicy(
    connectionId: string,
    items: Record<string, SharePolicyItem>,
): Promise<void> {
    const resp = (await invoke('share_policy_set', { connectionId, items })) as VaultOpResponse;
    unwrap(resp);
}

// ---------------------------------------------------------------------------
// Presence override
// ---------------------------------------------------------------------------

/** `override` of `null` clears (follow default); `true`/`false` overrides. */
export async function setPresenceOverride(
    connectionId: string,
    override: boolean | null,
): Promise<void> {
    const resp = (await invoke('presence_override_set', {
        connectionId,
        override,
    })) as VaultOpResponse;
    unwrap(resp);
}
