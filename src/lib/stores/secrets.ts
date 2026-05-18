import { writable } from 'svelte/store';

/**
 * Per-session secrets-unlock state.
 *
 * `unlockedUntil` (unix seconds) is set when the phone approves a
 * `secret.unlock-session` request; until that timestamp passes, the
 * desktop can call `secret.get` without re-prompting. The vault is
 * the source of truth — this store mirrors the grant locally so the
 * UI can decide whether to surface a Reveal button as one-click vs
 * "approve on phone" without an extra round-trip.
 *
 * Cleared when the session ends/locks (App.svelte resets it on
 * session state changes).
 */
export interface SecretsUnlockState {
  unlockedUntil: number; // unix seconds; 0 = no grant
  pending: boolean;      // true while waiting on phone approval
  error: string | null;
}

const initial: SecretsUnlockState = {
  unlockedUntil: 0,
  pending: false,
  error: null,
};

export const secretsUnlockStore = writable<SecretsUnlockState>(initial);

export function isSecretsUnlocked(state: SecretsUnlockState): boolean {
  return state.unlockedUntil > Math.floor(Date.now() / 1000);
}

export function resetSecretsUnlock() {
  secretsUnlockStore.set(initial);
}
