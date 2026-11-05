// What the desktop shows of the vault's lock and hold (#77,
// VAULT-LOCK-PLAN §3.2-§3.4), kept free of Svelte and Tauri for
// `npm test`. The texts are §3.4's, approved by the owner (decision 3,
// 2026-11-05): change them only with the owner's approval.

/**
 * The backend's view of the vault (`get_session_info`'s `vault`, taken at
 * the time of the read). An Open counts only until `open_until` (the
 * vault's last confirmation plus the backend's STALE_AFTER): read late, it
 * is Unknown, as the backend's `vault_at` says (see `vaultAt`).
 * @typedef {{
 *   state: 'unknown' | 'open' | 'held' | 'locked',
 *   open_until?: string | null,
 *   due?: boolean,
 *   waiting?: { messages: number, requests: number, calls: number, other: number } | null,
 *   deadline?: string | null,
 *   idle_lock_at?: string | null,
 *   locked_since?: string | null,
 *   as_of?: string | null,
 *   reason?: string | null,
 * }} VaultView
 */

/**
 * Which screen: a vault state, or `none` when no link is open (this
 * desktop's own Lock, or before its unlock): then the screen is the one
 * the app always showed there, with Start New Session, and no vault state.
 * @typedef {'none' | 'unknown' | 'open' | 'held' | 'locked'} Kind
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
 * A time in the reader's own locale: the time of day (as tooSoon.js
 * writes it) when it falls on today's date by this computer's clock, and
 * the locale's date and time otherwise (a lock seen the next morning).
 * @param {string} iso
 * @param {string | undefined} [locale]
 * @param {Date} [now]
 */
export function timeOf(iso, locale, now = new Date()) {
  const t = new Date(iso);
  const today = t.getFullYear() === now.getFullYear() && t.getMonth() === now.getMonth() && t.getDate() === now.getDate();
  const options = today ? { hour: 'numeric', minute: '2-digit' } : { dateStyle: 'medium', timeStyle: 'short' };
  return new Intl.DateTimeFormat(locale, /** @type {Intl.DateTimeFormatOptions} */ (options)).format(t);
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
 * The view at `now`: an Open past its `open_until` (or without one) is
 * Unknown, as the backend's `vault_at` says. Anything else as it is.
 * @param {VaultView | null | undefined} view
 * @param {Date} [now]
 * @returns {VaultView | null | undefined}
 */
export function vaultAt(view, now = new Date()) {
  if (view?.state !== 'open') return view;
  const until = view.open_until ? new Date(view.open_until).getTime() : NaN;
  return until >= now.getTime() ? view : { state: 'unknown' };
}

/**
 * Whether a read's session is live at `now`: the backend said so, and the
 * vault's Open hasn't run out since (`vaultAt`).
 * @param {boolean} isActive
 * @param {VaultView | null | undefined} view
 * @param {Date} [now]
 */
export function liveAt(isActive, view, now = new Date()) {
  return isActive && vaultAt(view, now)?.state === 'open';
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
 * What the screen shows for the vault, at `now`:
 * - `kind`: which state (`none`: no link open);
 * - `lines`: the texts, in order (none for a plain Open, nor for `none`);
 * - `holdOff`: the line for `due` (Open past the deadline with the hold
 *   off), or null;
 * - `showStart`: Start New Session is offered only while Open (and with no
 *   link, as always): held, locked or unknown, the vault would refuse it
 *   or not answer (§3.2).
 *
 * @param {VaultView | null | undefined} view `null`: no link open
 * @param {string | undefined} [locale]
 * @param {Date} [now]
 * @returns {{ kind: Kind, lines: string[], holdOff: string | null, showStart: boolean }}
 */
export function vaultScreen(view, locale, now = new Date()) {
  if (view == null) return { kind: 'none', lines: [], holdOff: null, showStart: true };
  const v = vaultAt(view, now) ?? { state: 'unknown' };
  if (v.state === 'open') {
    return { kind: 'open', lines: [], holdOff: v.due ? TEXT.holdOff : null, showStart: true };
  }
  if (v.state === 'held') {
    /** @type {string[]} */
    const lines = [TEXT.held];
    if (v.waiting) {
      const counts = countsLine(v.waiting);
      if (counts) lines.push(counts);
    } else {
      // No notice and no status gave the counts (§3.6.5): never zeros.
      lines.push(TEXT.heldNoCounts);
    }
    if (v.idle_lock_at) lines.push(idleLockText(timeOf(v.idle_lock_at, locale, now)));
    return { kind: 'held', lines, holdOff: null, showStart: false };
  }
  if (v.state === 'locked') {
    // Owner decision 2: when this desktop can't check, "locked as of".
    const lines = v.as_of ? [lockedAsOfText(timeOf(v.as_of, locale, now))] : [lockedText(v.reason)];
    return { kind: 'locked', lines, holdOff: null, showStart: false };
  }
  return { kind: 'unknown', lines: [TEXT.unknown], holdOff: null, showStart: false };
}

/**
 * Whether End session is offered (§3.2): in every vault state, Open with
 * no live session included (an end with nothing to end is harmless;
 * `device.session.end` is allowed while held, and a stored end keeps
 * retrying through a lock). Not with no link open: that screen is the one
 * the app always showed there.
 *
 * @param {Kind} kind
 */
export function endOffered(kind) {
  return kind !== 'none';
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

/**
 * When a read's Open runs out (ms from `now`), for a re-read then: `null`
 * if it isn't an Open that will.
 * @param {VaultView | null | undefined} view
 * @param {Date} [now]
 * @returns {number | null}
 */
export function msUntilOpenRunsOut(view, now = new Date()) {
  if (view?.state !== 'open' || !view.open_until) return null;
  const ms = new Date(view.open_until).getTime() - now.getTime();
  return ms >= 0 ? ms : null;
}
