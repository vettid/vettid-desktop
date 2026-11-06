import { get, writable } from 'svelte/store';
import { afterRead, afterEnd, readIsStale } from '../endState.js';
import { notLiveState, liveAt, msUntilOpenRunsOut, type VaultView } from '../vaultState.js';
import { CLOSED, openEnd, answer, type Confirm } from '../endConfirm.js';
import { createReadOrder } from '../readOrder.js';

/** Overlapping reads land in order (#77): see readOrder.js. */
const readOrder = createReadOrder();

export interface SessionState {
  state: 'inactive' | 'active' | 'suspended' | 'expired' | 'revoked';
  sessionId: string | null;
  connectionId: string | null;
  ownerName: string | null;
  expiresAt: number | null;
  secondsRemaining: number | null;
  phoneReachable: boolean;
}

const initialState: SessionState = {
  state: 'inactive',
  sessionId: null,
  connectionId: null,
  ownerName: null,
  expiresAt: null,
  secondsRemaining: null,
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
 * The phone declined a new session while the current one is live (#96):
 * the notice and the time it names (unix seconds). The app then moves from
 * the Start-a-new-session screen to Connections, which would drop a notice
 * kept on that screen, so App.svelte shows it in its own banner, by the
 * rule in `declined.js` (only while that session is active and before its
 * time; gone for good after).
 */
export const declinedNotice = writable<{ text: string; until: number; seen: boolean } | null>(null);

/**
 * An End session the vault hasn't answered yet (#80), from the backend:
 * the Start-a-new-session screen says "Ending your session…" meanwhile,
 * so an unconfirmed end never looks like a confirmed one.
 */
export const endPending = writable<boolean>(false);

/**
 * The vault's lock and hold as of the last read (#77): `get_session_info`'s
 * `vault`, which the backend takes at the time of the read. `null` while no
 * link is open (nothing known).
 */
export const vaultStore = writable<VaultView | null>(null);

/**
 * End session's confirmation (#77, §3.2), above the views: a screen swap
 * neither closes it nor re-points it (see endConfirm.js). App.svelte shows
 * it.
 */
export const endConfirm = writable<Confirm>(CLOSED);

/** End session is under way (App.svelte shows it over every view). */
export const endBusy = writable<boolean>(false);

/** What the last End session said, for the Session view. */
export const endStatus = writable<string>('');

/** Open End session's confirmation. */
export function askToEnd(): void {
  endConfirm.set(openEnd());
}

/** The person answered End session's confirmation. */
export async function answerEnd(yes: boolean): Promise<void> {
  const r = answer(get(endConfirm), yes);
  endConfirm.set(r.confirm);
  if (r.run === 'end') await endSessionNow();
}

/**
 * End session (§6.8, all of this desktop's access): offered in every
 * vault state (§3.2). Run from above the views, so a screen swap while it
 * waits doesn't lose its outcome.
 */
export async function endSessionNow(): Promise<void> {
  if (get(endBusy)) return;
  const { invoke } = await import('@tauri-apps/api/core');
  endBusy.set(true);
  endStatus.set('');
  sessionNotice.set(null);
  markEndStarted();
  try {
    // The session stops being shown as live at once; `notice` says when
    // the vault didn't confirm the end (or a newer session runs on).
    const result = await invoke<{ notice: string | null; end_pending?: boolean }>('end_session');
    endStatus.set(result.notice ?? 'Session ended.');
    // The view is usually replaced by now (routing follows the poll); the
    // notice is shown on the next.
    sessionNotice.set(result.notice);
    // #80: before any read. Still pending: kept as the end's own notice,
    // to go on a later confirmation; otherwise the outcome is final.
    endReturned(result.notice, !!result.end_pending);
    // Refresh the store at once so the pill and routing follow.
    await refreshSessionFromBackend();
  } catch (e) {
    endStatus.set(`Failed to end session: ${e}`);
  } finally {
    endBusy.set(false);
  }
}

/**
 * The window gained focus (#77, §3.1): the backend reads `vault.status` if
 * its word is old (and takes a sleep its refresh saw as a resume), then
 * the store is read again.
 */
export async function checkVaultOnFocus(): Promise<void> {
  const { invoke } = await import('@tauri-apps/api/core');
  try {
    await invoke<boolean>('check_vault');
  } catch {
    // Nothing to check (no link): the poll goes on as before.
  }
  // Read again whether or not the backend read the vault: what it shows
  // may have changed since the last poll anyway.
  await refreshSessionFromBackend();
}

/**
 * The backend tells the window at once when what it shows of the vault,
 * or whether a session is live, changes (`vault:changed`, #77): read
 * again then, not on the next poll. Returns the unlisten function.
 */
export async function listenForVaultChanges(): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event');
  return listen('vault:changed', () => {
    refreshSessionFromBackend();
  });
}

/** A re-read for when the last read's Open runs out (see vaultState.js). */
let decayTimer: ReturnType<typeof setTimeout> | null = null;

function scheduleDecayRead(view: VaultView | null): void {
  if (decayTimer) clearTimeout(decayTimer);
  decayTimer = null;
  const ms = msUntilOpenRunsOut(view);
  // Read just after it runs out: the backend then says Unknown, or Open
  // again if the vault confirmed it meanwhile.
  if (ms !== null) decayTimer = setTimeout(() => refreshSessionFromBackend(), ms + 500);
}

/** The not-confirmed notice End session showed while its end stayed
 *  pending: cleared once the vault answers that end (see endState.js). */
let endNotice: string | null = null;

/** Counts End session presses: a read that began before the latest one is
 *  dropped (see readIsStale). */
let endSeq = 0;

/** End session was pressed: pending at once, before any read, since
 *  routing may leave the Session view before the next one. */
export function markEndStarted(): void {
  endSeq += 1;
  endNotice = null;
  endPending.set(true);
}

/** End session returned: `pending` is whether its end still waits. */
export function endReturned(notice: string | null, pending: boolean): void {
  const r = afterEnd({ notice, pending });
  endNotice = r.endNotice;
  endPending.set(r.pending);
}

/** A new session or a new pairing: an earlier end no longer applies (#80). */
export function resetEndState(): void {
  endNotice = null;
  endPending.set(false);
}

function applyEndState(nowPending: boolean | null, confirmed = false, settledNotice: string | null = null): void {
  const r = afterRead({ wasPending: get(endPending), nowPending, notice: get(sessionNotice), endNotice, confirmed, settledNotice });
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
  // A new session is live: the last End session's message no longer applies.
  endStatus.set('');
  resetEndState();
  sessionStore.set({
    state: 'active',
    sessionId,
    connectionId: connectionId ?? null,
    ownerName: ownerName ?? null,
    expiresAt,
    secondsRemaining: Math.floor((expiresAt * 1000 - Date.now()) / 1000),
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
  const seq = endSeq;
  const readNo = readOrder.begin();
  try {
    const info = await invoke<{
      connection_id: string;
      session_id: string;
      expires_at: number;
      seconds_remaining: number;
      is_active: boolean;
      notice?: string | null;
      end_pending?: boolean;
      end_confirmed?: boolean;
      end_notice?: string | null;
      vault?: VaultView | null;
      seq?: number;
    }>('get_session_info');
    // #80: from before an End session press: it would undo it.
    if (readIsStale(seq, endSeq)) return;
    // #77: an answer older than one already applied (another read, begun
    // later, answered first) would put the store back.
    if (!readOrder.accept(readNo, typeof info.seq === 'number' ? info.seq : null)) return;

    // #77: the vault's state, as of this read. It changes nothing of the
    // end's state below (a pending end and its notice survive a swap).
    vaultStore.set(info.vault ?? null);
    scheduleDecayRead(info.vault ?? null);
    // Live as the backend said, and only while the vault's Open hasn't run
    // out (as the backend's vault_at).
    const live = liveAt(!!info.is_active, info.vault);

    // #80: an End session still waiting for the vault, and its notice.
    // A live session makes an earlier end's "not confirmed" moot (#80, L1).
    applyEndState(!!info.end_pending, !!info.end_confirmed, live ? null : (info.end_notice ?? null));

    if (live) {
      // A new session gone live: the last End session's message goes.
      if (get(sessionStore).state !== 'active') endStatus.set('');
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
        phoneReachable: true,
      });
    } else {
      // The vault hasn't confirmed the session lately: say so (shown on
      // the Start-a-new-session screen).
      if (info.notice) {
        sessionNotice.set(info.notice);
        staleNoticeShown = info.notice;
      } else if (staleNoticeShown) {
        // #107: the backend no longer says it (the clock was set right, or
        // the vault answered): the notice it gave goes, if still shown. A
        // notice from elsewhere is left.
        const shown = staleNoticeShown;
        sessionNotice.update(n => (n === shown ? null : n));
        staleNoticeShown = null;
      }
      // #77: held or locked is the vault's word ("suspended"), not an
      // expiry.
      sessionStore.update(s => ({ ...s, state: notLiveState(info.vault), secondsRemaining: 0 }));
    }
  } catch {
    if (readIsStale(seq, endSeq)) return;
    if (!readOrder.accept(readNo, null)) return;
    // No link open (before its unlock, or after one that failed): no
    // vault state; the screen is the one the app always showed there.
    vaultStore.set(null);
    scheduleDecayRead(null);
    // No link: nothing is known of an end; its notice isn't touched.
    applyEndState(null);
    // `get_session_info` throws "not unlocked" when AppState has no
    // credentials in memory — which happens right after end_session
    // or logout, AND on a fresh launch before auto-unlock has
    // run. Previously the catch silently swallowed this, leaving the
    // store stuck on its previous state (active → user clicks End
    // session → store still says active → routing doesn't flip).
    //
    // Disambiguate by asking get_status whether we're even registered:
    //   - registered but not open → state: 'expired' (Start-a-new-session path)
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
          phoneReachable: false,
        });
      }
    } catch {
      // Can't reach the backend at all — leave whatever state we had.
    }
  }
}
