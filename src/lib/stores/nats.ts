import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';

export interface NatsState {
    connected: boolean;
    /** Most recent state from the Rust listener — `null` until the first event. */
    rawState: string | null;
    error: string | null;
}

const initialState: NatsState = {
    connected: false,
    rawState: null,
    error: null,
};

export const natsStore = writable<NatsState>(initialState);

let initialized = false;

/**
 * Subscribe to `vault:nats-state` from the Rust listener and translate the
 * connection-state events (Connected, Disconnected, ServerError, etc.) into
 * the simpler shape this store exposes. Idempotent — safe to call from any
 * mount.
 */
export function initNatsListener(): void {
    if (initialized) return;
    initialized = true;

    listen<{ [k: string]: unknown } | string>('vault:nats-state', (event) => {
        const value = event.payload;
        // The Rust enum serializes as either a bare string ("connected") for
        // unit variants or `{ variant: { ... } }` for ones with payloads.
        const stateName =
            typeof value === 'string'
                ? value
                : (Object.keys(value)[0] as string | undefined) ?? null;

        const isConnected = stateName === 'connected';
        const errorMessage =
            typeof value === 'object' && value !== null && 'server-error' in value
                ? String((value as Record<string, { message?: string }>)['server-error']?.message ?? '')
                : typeof value === 'object' && value !== null && 'client-error' in value
                ? String((value as Record<string, { message?: string }>)['client-error']?.message ?? '')
                : null;

        natsStore.set({
            connected: isConnected,
            rawState: stateName,
            error: errorMessage,
        });
    });
}
