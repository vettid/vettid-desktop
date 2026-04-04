import { writable, type Writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Connection {
    connectionId: string;
    peerGuid: string;
    label: string;
    status: string;
    direction: string;
    createdAt: string;
    peerProfile?: Record<string, unknown>;
}

export interface FeedEvent {
    eventId: string;
    eventType: string;
    title?: string;
    message?: string;
    timestamp: string;
    isRead: boolean;
}

export interface Message {
    id: string;
    connectionId: string;
    senderId: string;
    content: string;
    contentType: string;
    sentAt: string;
    status: string;
}

export interface SecretEntry {
    id: string;
    name: string;
    category: string;
    createdAt: string;
}

export interface PendingApproval {
    requestId: string;
    operation: string;
    createdAt: number;
}

// ---------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------

export const connectionsStore: Writable<Connection[]> = writable([]);
export const feedStore: Writable<FeedEvent[]> = writable([]);
export const messagesStore: Writable<Message[]> = writable([]);
export const secretsCatalogStore: Writable<SecretEntry[]> = writable([]);
export const pendingApprovalsStore: Writable<PendingApproval[]> = writable([]);

// ---------------------------------------------------------------------------
// Real-time event listeners (called once on app init)
// ---------------------------------------------------------------------------

let listenersInitialized = false;

export function initVaultListeners() {
    if (listenersInitialized) return;
    listenersInitialized = true;

    // New feed event from vault
    listen<FeedEvent>('vault:feed-event', (event) => {
        feedStore.update((events) => [event.payload, ...events]);
    });

    // New message received
    listen<Message>('vault:message-received', (event) => {
        messagesStore.update((msgs) => [...msgs, event.payload]);
    });

    // Phone approval result
    listen<{ requestId: string; approved: boolean }>('vault:phone-approval-result', (event) => {
        pendingApprovalsStore.update((pending) =>
            pending.filter((p) => p.requestId !== event.payload.requestId)
        );
    });
}
