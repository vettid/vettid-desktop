// What the desktop shows of the vault's lock and hold (#77,
// VAULT-LOCK-PLAN §3.2-§3.4), kept free of Svelte and Tauri for
// `npm test`. The texts are §3.4's, approved by the owner (decision 3,
// 2026-11-05): change them only with the owner's approval.

/**
 * The backend's view of the vault (`get_session_info`'s `vault`, already
 * taken at the time of the read).
 * @typedef {{
 *   state: 'unknown' | 'open' | 'held' | 'locked',
 *   due?: boolean,
 *   waiting?: { messages: number, requests: number, calls: number, other: number } | null,
 *   deadline?: string | null,
 *   idle_lock_at?: string | null,
 *   locked_since?: string | null,
 *   as_of?: string | null,
 *   reason?: string | null,
 * }} VaultView
 */

export const TEXT = Object.freeze({
  locked: 'Your vault was locked. Unlock it on your phone to continue.',
  lockedIdle: "Your vault locked itself because your daily check wasn't done. Unlock it on your phone.",
  lockedOwnerCheck: 'Your vault locked itself after too many failed daily checks. Unlock it on your phone.',
  lockedRecovery: 'Your vault was locked because a recovery started. Use your phone to continue.',
  unknown: "This desktop can't tell whether your vault is open. It keeps checking.",
  held: 'Your vault is waiting for your daily check. Open VettID on your phone to continue.',
  heldNoCounts: 'Something may be waiting for you.',
  holdOff: "Your daily check is overdue. Your vault's hold is off, so this desktop keeps working.",
});

/**
 * A time of day in the reader's own locale, as tooSoon.js writes it.
 * @param {string} iso
 * @param {string | undefined} [locale]
 */
export function timeOf(iso, locale) {
  return new Intl.DateTimeFormat(locale, { hour: 'numeric', minute: '2-digit' }).format(new Date(iso));
}

/** @param {string} time */
export function lockedAsOfText(time) {
  return `Your vault was locked at ${time}. This desktop can't reach it now to check.`;
}

/** @param {string} time */
export function idleLockText(time) {
  return `Your vault locks itself at ${time} unless you do your daily check.`;
}

/**
 * The locked text for `reason` (`vault.locking`'s): a reason this desktop
 * doesn't know, or none, is the plain lock.
 * @param {string | null | undefined} reason
 */
export function lockedText(reason) {
  switch (reason) {
    case 'idle':
      return TEXT.lockedIdle;
    case 'owner_check':
      return TEXT.lockedOwnerCheck;
    case 'recovery':
      return TEXT.lockedRecovery;
    default:
      return TEXT.locked;
  }
}

/**
 * "Waiting: 3 messages, 1 request, 2 missed calls, 1 other." A count of 1
 * takes its singular and a count of 0 is left out. `null` when every count
 * is 0 (nothing is waiting, so there is nothing to list).
 * @param {{ messages: number, requests: number, calls: number, other: number }} w
 * @returns {string | null}
 */
export function countsLine(w) {
  /** @type {string[]} */
  const parts = [];
  const add = (/** @type {number} */ n, /** @type {string} */ one, /** @type {string} */ many) => {
    if (n > 0) parts.push(`${n} ${n === 1 ? one : many}`);
  };
  add(w.messages, 'message', 'messages');
  add(w.requests, 'request', 'requests');
  add(w.calls, 'missed call', 'missed calls');
  add(w.other, 'other', 'other');
  return parts.length ? `Waiting: ${parts.join(', ')}.` : null;
}

/**
 * What the screen shows for the vault (`view` at the time of the read):
 * - `kind`: which state;
 * - `lines`: the texts, in order (none for a plain Open);
 * - `holdOff`: the line for `due` (Open past the deadline with the hold
 *   off), or null;
 * - `showStart`: Start New Session is offered only while Open: held,
 *   locked or unknown, the vault would refuse it or not answer (§3.2).
 * A missing view (no link) is Unknown.
 *
 * @param {VaultView | null | undefined} view
 * @param {string | undefined} [locale]
 * @returns {{ kind: 'unknown' | 'open' | 'held' | 'locked', lines: string[], holdOff: string | null, showStart: boolean }}
 */
export function vaultScreen(view, locale) {
  const state = view?.state ?? 'unknown';
  if (state === 'open') {
    return { kind: 'open', lines: [], holdOff: view?.due ? TEXT.holdOff : null, showStart: true };
  }
  if (state === 'held') {
    /** @type {string[]} */
    const lines = [TEXT.held];
    if (view?.waiting) {
      const counts = countsLine(view.waiting);
      if (counts) lines.push(counts);
    } else {
      // No notice and no status gave the counts (§3.6.5): never zeros.
      lines.push(TEXT.heldNoCounts);
    }
    if (view?.idle_lock_at) lines.push(idleLockText(timeOf(view.idle_lock_at, locale)));
    return { kind: 'held', lines, holdOff: null, showStart: false };
  }
  if (state === 'locked') {
    // Owner decision 2: when this desktop can't check, "locked as of".
    const lines = view?.as_of ? [lockedAsOfText(timeOf(view.as_of, locale))] : [lockedText(view?.reason)];
    return { kind: 'locked', lines, holdOff: null, showStart: false };
  }
  return { kind: 'unknown', lines: [TEXT.unknown], holdOff: null, showStart: false };
}

/**
 * Whether End session is offered (§3.2): in every vault state, held,
 * locked and unknown included (`device.session.end` is allowed while held,
 * and a stored end keeps retrying through a lock), and while Open whenever
 * a session is live. Open with no session has nothing to end.
 *
 * @param {'unknown' | 'open' | 'held' | 'locked'} kind
 * @param {boolean} live
 */
export function endOffered(kind, live) {
  return kind !== 'open' || live;
}

/**
 * The session store's state for a read that isn't live: "suspended" while
 * held or locked (the vault's word, and the current pill and routing show
 * it as such), "expired" otherwise.
 * @param {VaultView | null | undefined} view
 * @returns {'suspended' | 'expired'}
 */
export function notLiveState(view) {
  return view?.state === 'held' || view?.state === 'locked' ? 'suspended' : 'expired';
}
