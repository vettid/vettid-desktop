import { writable } from 'svelte/store';

export interface NatsState {
  connected: boolean;
  url: string | null;
  error: string | null;
}

const initialState: NatsState = {
  connected: false,
  url: null,
  error: null,
};

export const natsStore = writable<NatsState>(initialState);

export function setConnected(url: string) {
  natsStore.set({ connected: true, url, error: null });
}

export function setDisconnected(error?: string) {
  natsStore.set({ connected: false, url: null, error: error || null });
}
