import { writable, derived, type Writable, type Readable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import type { Connection, VaultOpResponse } from '../types';
import { decodeEventPayload } from '../events';

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
 *  the modal. */
export const pendingGrantCountStore: Writable<number> = writable(0);

// ---------------------------------------------------------------------------
// Loaders — call from views to (re)fetch from the vault
// ---------------------------------------------------------------------------

/** Why the last `loadConnections` failed (the backend's own text), or ''. */
export const connectionsErrorStore: Writable<string> = writable('');

/**
 * Re-fetch the connection list. On failure the list is cleared (a list
 * we could not confirm is not shown as current) and the backend's error
 * text goes to `connectionsErrorStore`; it never reads as an empty list.
 */
export async function loadConnections(): Promise<void> {
    try {
        const resp: VaultOpResponse = await invoke('list_connections');
        if (resp.success && resp.data) {
            const data = resp.data as { connections?: Connection[] };
            connectionsStore.set(data.connections ?? []);
            connectionsErrorStore.set('');
            return;
        }
        connectionsStore.set([]);
        connectionsErrorStore.set(resp.error ?? 'Failed to load connections');
    } catch (e) {
        connectionsStore.set([]);
        connectionsErrorStore.set(String(e));
    }
}

// ---------------------------------------------------------------------------
// Real-time event listeners (called once on app init)
// ---------------------------------------------------------------------------

let listenersInitialized = false;

export function initVaultListeners(): void {
    if (listenersInitialized) return;
    listenersInitialized = true;

    // Connection lifecycle (peer-accepted, activated, key-exchanged, rejected).
    // We re-list to pick up state transitions — cheaper than maintaining a
    // delta-application path until the dataset gets large.
    listen<AppEventEnvelope>('vault:connection-event', () => {
        void loadConnections();
    });

    listen<AppEventEnvelope>('vault:connection-revoked', () => {
        void loadConnections();
    });

    // Profile changes — peer's published profile updated.
    listen<AppEventEnvelope>('vault:profile-update', () => {
        void loadConnections();
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
