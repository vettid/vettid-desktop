import { writable, derived, type Writable, type Readable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import {
    isPermissionGranted,
    requestPermission,
    sendNotification,
} from '@tauri-apps/plugin-notification';
import { getCurrentWindow } from '@tauri-apps/api/window';
import type {
    Connection,
    FeedEvent,
    Message,
    SecretEntry,
    VaultOpResponse,
} from '../types';

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
 * coming off the `OwnerSpace.{guid}.forApp.>` channel. The listener forwards
 * the NATS subject and a base64-encoded payload — per-feature consumers
 * decode/decrypt as appropriate.
 */
export interface AppEventEnvelope {
    subject: string;
    payload_b64: string;
}

// ---------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------

export const connectionsStore: Writable<Connection[]> = writable([]);
export const feedStore: Writable<FeedEvent[]> = writable([]);
export const messagesStore: Writable<Message[]> = writable([]);
export const secretsCatalogStore: Writable<SecretEntry[]> = writable([]);
export const pendingApprovalsStore: Writable<PendingApproval[]> = writable([]);
export const natsStateStore: Writable<NatsState> = writable('unknown');

/** Per-connection unread count, keyed by connection_id. */
export const unreadByConnectionStore: Writable<Record<string, number>> = writable({});

/** Total unread across all connections. */
export const totalUnreadStore: Readable<number> = derived(
    unreadByConnectionStore,
    ($unread) => Object.values($unread).reduce((sum, n) => sum + n, 0),
);

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

export async function loadFeed(): Promise<void> {
    const resp: VaultOpResponse = await invoke('list_feed');
    if (resp.success && resp.data) {
        const data = resp.data as { events?: FeedEvent[] };
        feedStore.set(data.events ?? []);
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
            void loadFeed();
        }
    });

    // Connection lifecycle (peer-accepted, activated, key-exchanged, rejected).
    // We re-list to pick up state transitions — cheaper than maintaining a
    // delta-application path until the dataset gets large.
    listen<AppEventEnvelope>('vault:connection-event', () => {
        void loadConnections();
        void loadFeed();
    });

    listen<AppEventEnvelope>('vault:connection-revoked', () => {
        void loadConnections();
    });

    // Profile changes — peer's published profile updated.
    listen<AppEventEnvelope>('vault:profile-update', () => {
        void loadConnections();
    });

    // Feed events — the Rust listener emits this both for the legacy
    // device-channel "feed_event" type and for `OwnerSpace.*.forApp.feed.*`
    // push subjects. Either way: just re-list.
    listen<unknown>('vault:feed-event', () => {
        void loadFeed();
    });

    // New message — bump unread count and (when window isn't focused) fire an
    // OS notification. Per-conversation views reset their own count via
    // `markConversationRead`.
    listen<AppEventEnvelope>('vault:message-received', async (event) => {
        const subject = event.payload?.subject ?? '';
        // Subject pattern: `OwnerSpace.{guid}.forApp.new-message.{connectionId}`
        const connectionId = subject.split('.').pop() ?? '';
        if (connectionId) {
            unreadByConnectionStore.update((m) => ({
                ...m,
                [connectionId]: (m[connectionId] ?? 0) + 1,
            }));
        }
        void loadFeed();
        await maybeNotifyMessage(connectionId);
    });

    // Read receipt from peer — clears the "delivered/read" badges on sent
    // messages. Conversation views consume this directly to update bubble UI.
    listen<AppEventEnvelope>('vault:read-receipt', () => {
        // No-op at the store level; the conversation view subscribes directly.
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

// ---------------------------------------------------------------------------
// OS notifications
// ---------------------------------------------------------------------------

let notificationsEnabled: boolean | null = null;

async function ensureNotificationPermission(): Promise<boolean> {
    if (notificationsEnabled !== null) return notificationsEnabled;
    try {
        let granted = await isPermissionGranted();
        if (!granted) {
            const result = await requestPermission();
            granted = result === 'granted';
        }
        notificationsEnabled = granted;
    } catch {
        notificationsEnabled = false;
    }
    return notificationsEnabled;
}

/**
 * Fire an OS notification for an incoming message — but only when the app
 * window is *not* focused. If the user is already looking at the app, the UI
 * update is sufficient and a duplicate notification is just noise.
 */
async function maybeNotifyMessage(connectionId: string): Promise<void> {
    try {
        const win = getCurrentWindow();
        const focused = await win.isFocused();
        if (focused) return;
    } catch {
        // If we can't query focus state, err on the side of notifying.
    }

    const granted = await ensureNotificationPermission();
    if (!granted) return;

    // Look up the peer name from the current connections list. Falls back to
    // a generic title rather than leaking the raw connection id.
    let title = 'New message';
    const connections = getCurrentConnections();
    const conn = connections.find((c) => c.connection_id === connectionId);
    if (conn) {
        const p = conn.peer_profile;
        const name = `${p?.first_name ?? ''} ${p?.last_name ?? ''}`.trim();
        title = name || conn.label || title;
    }

    sendNotification({
        title,
        body: 'Tap to open the conversation.',
    });
}

function getCurrentConnections(): Connection[] {
    let snapshot: Connection[] = [];
    const unsub = connectionsStore.subscribe((v) => { snapshot = v; });
    unsub();
    return snapshot;
}
