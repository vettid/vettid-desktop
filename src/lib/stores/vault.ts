import { writable, derived, get, type Writable, type Readable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import type { Connection, ConnectionRequests, VaultOpResponse } from '../connections';
import { INBOUND_EVENT, type InboundBatch } from '../inbound';
import { inboundAction, livenessChanged } from '../connectionView.js';
import { decodeEventPayload } from '../events';
import { sessionStore } from './session';
import { selectedConnectionStore } from './navigation';

// ---------------------------------------------------------------------------
// Store-local types
// ---------------------------------------------------------------------------

export interface PendingApproval {
    requestId: string;
    operation: string;
    createdAt: number;
}

/**
 * Raw payload envelope for a `vault:*` push event: a subject and a
 * base64-encoded payload, which per-feature consumers decode. Nothing
 * emits these in this build (the NATS listener that did is gone).
 */
export interface AppEventEnvelope {
    subject: string;
    payload_b64: string;
}

// ---------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------

export const connectionsStore: Writable<Connection[]> = writable([]);
export const pendingApprovalsStore: Writable<PendingApproval[]> = writable([]);

/** Per-connection unread count, keyed by connection_id. */
export const unreadByConnectionStore: Writable<Record<string, number>> = writable({});

/** Total unread across all connections. */
export const totalUnreadStore: Readable<number> = derived(
    unreadByConnectionStore,
    ($unread) => Object.values($unread).reduce((sum, n) => sum + n, 0),
);

/** Count of inbound grant requests awaiting the user's approve/deny.
 *  Driven by DataGrantApprovalModal — it polls grant.list-pending on
 *  mount and on every data-request-received push, then writes the
 *  count here. The Sharing rail icon reads this for a notification
 *  dot so the user knows requests are queued even after dismissing
 *  the modal. `null`: not known (nothing loaded yet, or the last load
 *  failed): no count is claimed. */
export const pendingGrantCountStore: Writable<number | null> = writable(null);

// ---------------------------------------------------------------------------
// Loaders — call from views to (re)fetch from the vault
// ---------------------------------------------------------------------------

/** Why the last `loadConnections` failed (the backend's own text), or ''. */
export const connectionsErrorStore: Writable<string> = writable('');

/** Counts `loadConnections` calls: only the latest one's answer is applied. */
let connectionsSeq = 0;

/**
 * Re-fetch the connection list. On failure the list is cleared (a list
 * we could not confirm is not shown as current) and the backend's error
 * text goes to `connectionsErrorStore`; it never reads as an empty list.
 * The selected connection follows the list: replaced by its new copy, or
 * cleared when the list no longer has it or couldn't be read.
 */
export async function loadConnections(): Promise<void> {
    const seq = ++connectionsSeq;
    let list: Connection[] = [];
    let error = '';
    try {
        const resp: VaultOpResponse<{ connections?: Connection[] }> = await invoke('list_connections');
        if (resp.success && resp.data) list = resp.data.connections ?? [];
        else error = resp.error ?? 'Failed to load connections';
    } catch (e) {
        error = String(e);
    }
    if (seq !== connectionsSeq) return;
    connectionsStore.set(list);
    connectionsErrorStore.set(error);
    const selected = get(selectedConnectionStore);
    if (selected) selectedConnectionStore.set(list.find((c) => c.id === selected.id) ?? null);
}

/** The pending requests as the last load confirmed them; `null` when it failed. */
export const connectionRequestsStore: Writable<ConnectionRequests | null> = writable(null);
/** Why the last `loadConnectionRequests` failed (the backend's own text), or ''. */
export const connectionRequestsErrorStore: Writable<string> = writable('');

let requestsSeq = 0;

/**
 * Re-fetch the pending requests (`connection.request.list`). On failure
 * they are cleared and the backend's error text is kept, as for the list.
 */
export async function loadConnectionRequests(): Promise<void> {
    const seq = ++requestsSeq;
    let requests: ConnectionRequests | null = null;
    let error = '';
    try {
        const resp: VaultOpResponse<Partial<ConnectionRequests>> = await invoke('list_connection_requests');
        if (resp.success && resp.data) {
            requests = { incoming: resp.data.incoming ?? [], outgoing: resp.data.outgoing ?? [] };
        } else {
            error = resp.error ?? '';
        }
    } catch (e) {
        error = String(e);
    }
    if (seq !== requestsSeq) return;
    connectionRequestsStore.set(requests);
    connectionRequestsErrorStore.set(error);
}

/**
 * Bumped each time the connection views should read again: a view that
 * reads on its own (the detail's `connection.get`) follows it.
 */
export const connectionsReload: Writable<number> = writable(0);

/** Read the list and the requests again, and tell the other views to. */
export function reloadConnectionViews(): void {
    connectionsReload.update((n) => n + 1);
    void loadConnections();
    void loadConnectionRequests();
}

/** Shown in place of the list and the requests while no session is live. */
export const NOT_LIVE_TEXT = "Your session isn't live, so your connections aren't shown.";

/**
 * Clear the list, the requests and the selected connection at once when the
 * session stops being live. An answer to a read already under way is not
 * applied (its count is no longer the latest).
 */
export function clearConnectionViews(): void {
    connectionsSeq++;
    requestsSeq++;
    connectionsStore.set([]);
    connectionsErrorStore.set(NOT_LIVE_TEXT);
    connectionRequestsStore.set(null);
    connectionRequestsErrorStore.set(NOT_LIVE_TEXT);
    selectedConnectionStore.set(null);
}

// ---------------------------------------------------------------------------
// Real-time event listeners (called once on app init)
// ---------------------------------------------------------------------------

let listenersInitialized = false;

export function initVaultListeners(): void {
    if (listenersInitialized) return;
    listenersInitialized = true;

    // The connection views read again when the session goes live, and are
    // cleared when it stops being live, as the window's own session state
    // shows it (`vault:changed`, then the session snapshot). A new
    // `session_id` without a change in liveness needs nothing here: a new
    // grant drops the backend's queue and sends a resync, which reads the
    // views again (below).
    let lastSession: string | undefined;
    sessionStore.subscribe((s) => {
        const prev = lastSession;
        lastSession = s.state;
        if (prev === undefined || !livenessChanged(prev, s.state)) return;
        if (s.state === 'active') reloadConnectionViews();
        else clearConnectionViews();
    });

    // What the vault sent this desktop (Phase 5, 5.1): dropped while the
    // session isn't live here; a resync or a connection, request or block
    // change reads the views again.
    listen<InboundBatch>(INBOUND_EVENT, (event) => {
        const live = get(sessionStore).state === 'active';
        if (inboundAction(event.payload, live) === 'reload') reloadConnectionViews();
    });

    // New message — bump per-connection unread count for the in-app
    // badge. The OS notification is fired from notifications.ts
    // (which has the icon path + focused-window suppression); keeping
    // that here too produced duplicate toasts. Per-conversation views
    // reset their own count via `markConversationRead`.
    listen<AppEventEnvelope>('vault:message-received', (event) => {
        const body = decodeEventPayload<{ connection_id?: string }>(event.payload);
        const connectionId = body?.connection_id ?? '';
        if (!connectionId) return;
        unreadByConnectionStore.update((m) => ({
            ...m,
            [connectionId]: (m[connectionId] ?? 0) + 1,
        }));
    });

    // Read receipt from peer — clears the "delivered/read" badges on sent
    // messages. Conversation views consume this directly to update bubble UI.
    listen<AppEventEnvelope>('vault:read-receipt', () => {
        // No-op at the store level; the conversation view subscribes directly.
    });

    // Agent message — bump per-connection unread count for received.
    // OS notification fires from notifications.ts (single source).
    // Filter to direction !== 'outgoing' so an agent.message.sent
    // mirror from another surface (phone) doesn't badge a message
    // the user just sent themselves.
    listen<AppEventEnvelope>('vault:agent-message', (event) => {
        const body = decodeEventPayload<{
            connection_id?: string;
            direction?: string;
        }>(event.payload);
        const connectionId = body?.connection_id ?? '';
        if (!connectionId) return;
        if (body?.direction === 'outgoing') return;
        unreadByConnectionStore.update((m) => ({
            ...m,
            [connectionId]: (m[connectionId] ?? 0) + 1,
        }));
    });

    // Phone approval result — drop from pending list.
    listen<{ request_id?: string; requestId?: string }>(
        'vault:phone-approval-result',
        (event) => {
            const requestId =
                event.payload.request_id ?? event.payload.requestId ?? '';
            if (requestId) {
                pendingApprovalsStore.update((pending) =>
                    pending.filter((p) => p.requestId !== requestId),
                );
            }
        },
    );

    // Vault locked — UI must prompt for re-unlock.
    listen<unknown>('vault:vault-locked', () => {
        // The StatusBar could show a "vault locked" pill.
        // A dedicated locked-state store would belong in session.ts — wired
        // there in a follow-up when we have the re-unlock UX.
    });
}

/** Mark a conversation as read locally — call when opening it. */
export function markConversationRead(connectionId: string): void {
    unreadByConnectionStore.update((m) => {
        if (!(connectionId in m)) return m;
        const next = { ...m };
        delete next[connectionId];
        return next;
    });
}

// (OS-notification helpers consolidated into notifications.ts —
// this module now only owns the in-app unread-count store.)
