import { writable } from 'svelte/store';

export interface SessionState {
  state: 'inactive' | 'active' | 'suspended' | 'expired' | 'revoked';
  sessionId: string | null;
  connectionId: string | null;
  ownerName: string | null;
  expiresAt: number | null;
  secondsRemaining: number | null;
  extendedCount: number;
  maxExtensions: number;
  phoneReachable: boolean;
}

const initialState: SessionState = {
  state: 'inactive',
  sessionId: null,
  connectionId: null,
  ownerName: null,
  expiresAt: null,
  secondsRemaining: null,
  extendedCount: 0,
  maxExtensions: 3,
  phoneReachable: false,
};

export const sessionStore = writable<SessionState>(initialState);

export function activateSession(
  sessionId: string,
  expiresAt: number,
  connectionId?: string,
  ownerName?: string,
) {
  sessionStore.set({
    state: 'active',
    sessionId,
    connectionId: connectionId ?? null,
    ownerName: ownerName ?? null,
    expiresAt,
    secondsRemaining: Math.floor((expiresAt * 1000 - Date.now()) / 1000),
    extendedCount: 0,
    maxExtensions: 3,
    phoneReachable: true,
  });
}

export function suspendSession() {
  sessionStore.update(s => ({ ...s, state: 'suspended', phoneReachable: false }));
}

export function resumeSession() {
  sessionStore.update(s => ({ ...s, state: 'active', phoneReachable: true }));
}

export function expireSession() {
  sessionStore.update(s => ({ ...s, state: 'expired', secondsRemaining: 0 }));
}

export function revokeSession() {
  sessionStore.set({ ...initialState, state: 'revoked' });
}

export function resetSession() {
  sessionStore.set(initialState);
}
