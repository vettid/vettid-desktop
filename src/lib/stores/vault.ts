import { writable, derived, type Writable, type Readable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import type { Connection, VaultOpResponse } from '../types';
import { decodeEventPayload } from '../events';

// ---------------------------------------------------------------------------
// Store-local types
// ---------------------------------------------------------------------------

/**
 * NATS connection state surfaced by the Rust listener via `vault:nats-state`.
 * Mirrors the kebab-case serialization of `NatsConnectionEvent`.
 */
export type NatsState =
    | 'connected'
    | 'disconnected'
    | 'lame-duck-mode'
    | 'unknown';

export interface PendingApproval {
    requestId: string;
    operation: string;
    createdAt: number;
}

/**
 * Raw payload envelope from the Rust listener for any `vault:*` push event
 * coming off the per-device `MessageSpace.{owner}.forApp.device.{conn}.>`
 * channel (see nats/listener.rs::event_suffix for the subject routing).
 * The listener forwards the NATS subject and a base64-encoded payload —
 * per-feature consumers decode/decrypt as appropriate.
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
export const natsStateStore: Writable<NatsState> = writable('unknown');

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

export async function loadConnections(): Promise<void> {
    const resp: VaultOpResponse = await invoke('list_connections');
    if (resp.success && resp.data) {
        const data = resp.data as { connections?: Connection[] };
        connectionsStore.set(data.connections ?? []);
    }
}

// ---------------------------------------------------------------------------
// Real-time event listeners (called once on app init)
// ---------------------------------------------------------------------------

let listenersInitialized = false;

export function initVaultListeners(): void {
    if (listenersInitialized) return;
    listenersInitialized = true;

    // Connection-state events from the NATS listener — drives the StatusBar
    // indicator and triggers re-sync on reconnect.
    listen<{ [key: string]: unknown } | string>('vault:nats-state', (event) => {
        const value = event.payload;
        const stateName =
            typeof value === 'string'
                ? value
                : (Object.keys(value)[0] as string | undefined) ?? 'unknown';
        natsStateStore.set(stateName as NatsState);

        if (stateName === 'connected') {
            // Refresh the data the user can see when the link comes back up;
            // missed push events are replaced with the authoritative list.
            void loadConnections();
        }
    });

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
        // Surface via natsState so the StatusBar can show a "vault locked" pill.
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
