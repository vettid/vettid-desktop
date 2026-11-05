import { get, writable } from 'svelte/store';
import { afterRead } from '../endState.js';

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

/**
 * A notice about the last session end that has to outlive the view it
 * came from (#26): ending a session routes to the Start-a-new-session
 * screen at once. Cleared when a session starts.
 */
export const sessionNotice = writable<string | null>(null);

/**
 * An End session the vault hasn't answered yet (#80), from the backend:
 * the Start-a-new-session screen says "Ending your session…" meanwhile,
 * so an unconfirmed end never looks like a confirmed one.
 */
export const endPending = writable<boolean>(false);

/** The not-confirmed notice End session showed while its end stayed
 *  pending: cleared once the vault answers that end (see endState.js). */
let endNotice: string | null = null;

/** End session was pressed: pending at once, before any read, since
 *  routing may leave the Session view before the next one. */
export function markEndStarted(): void {
  endNotice = null;
  endPending.set(true);
}

/** End session's notice, kept as the end's own if the end is still pending. */
export function noteEndNotice(notice: string | null): void {
  endNotice = notice !== null && get(endPending) ? notice : null;
}

function applyEndState(nowPending: boolean | null): void {
  const r = afterRead({ wasPending: get(endPending), nowPending, notice: get(sessionNotice), endNotice });
  endNotice = r.endNotice;
  if (r.notice !== get(sessionNotice)) sessionNotice.set(r.notice);
  endPending.set(r.pending);
}

/** The stale-session notice last shown from `get_session_info`, so it is
 *  cleared once the vault confirms the session again. */
let staleNoticeShown: string | null = null;

export function activateSession(
  sessionId: string,
  expiresAt: number,
  connectionId?: string,
  ownerName?: string,
) {
  sessionNotice.set(null);
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

/**
 * Ask the backend for the current session state from the loaded credentials
 * and update the store. Cheap and offline — no vault calls. Callers should
 * invoke on app launch and periodically (e.g., every 30s) to drive the
 * expiry UI.
 */
export async function refreshSessionFromBackend(): Promise<void> {
  const { invoke } = await import('@tauri-apps/api/core');
  try {
    const info = await invoke<{
      connection_id: string;
      session_id: string;
      expires_at: number;
      seconds_remaining: number;
      is_active: boolean;
      notice?: string | null;
      end_pending?: boolean;
    }>('get_session_info');

    // #80: an End session still waiting for the vault, and its notice.
    applyEndState(!!info.end_pending);

    if (info.is_active) {
      // Confirmed again: the stale-session notice no longer applies.
      if (staleNoticeShown) {
        const shown = staleNoticeShown;
        sessionNotice.update(n => (n === shown ? null : n));
        staleNoticeShown = null;
      }
      sessionStore.set({
        state: 'active',
        sessionId: info.session_id,
        connectionId: info.connection_id,
        ownerName: null,
        expiresAt: info.expires_at,
        secondsRemaining: info.seconds_remaining,
        extendedCount: 0,
        maxExtensions: 3,
        phoneReachable: true,
      });
    } else {
      // The vault hasn't confirmed the session lately: say so (shown on
      // the Start-a-new-session screen).
      if (info.notice) {
        sessionNotice.set(info.notice);
        staleNoticeShown = info.notice;
      }
      sessionStore.update(s => ({ ...s, state: 'expired', secondsRemaining: 0 }));
    }
  } catch {
    // No link: nothing is known of an end; its notice isn't touched.
    applyEndState(null);
    // `get_session_info` throws "not unlocked" when AppState has no
    // credentials in memory — which happens right after end_session,
    // lock, or logout, AND on a fresh launch before auto-unlock has
    // run. Previously the catch silently swallowed this, leaving the
    // store stuck on its previous state (active → user clicks End
    // session → store still says active → routing doesn't flip).
    //
    // Disambiguate by asking get_status whether we're even registered:
    //   - registered but locked → state: 'expired' (lock screen path)
    //   - not registered → state: 'inactive' (pair screen path)
    try {
      const status = await invoke<{ is_registered: boolean }>('get_status');
      if (status.is_registered) {
        sessionStore.update(s => ({ ...s, state: 'expired', secondsRemaining: 0 }));
      } else {
        sessionStore.set({
          state: 'inactive',
          sessionId: null,
          connectionId: null,
          ownerName: null,
          expiresAt: 0,
          secondsRemaining: 0,
          extendedCount: 0,
          maxExtensions: 3,
          phoneReachable: false,
        });
      }
    } catch {
      // Can't reach the backend at all — leave whatever state we had.
    }
  }
}
