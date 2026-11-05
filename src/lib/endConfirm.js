// The End-session confirmation (#77, VAULT-LOCK-PLAN §3.2), kept free of
// Svelte and Tauri for `npm test`. It is held above the views (the store
// in stores/session.ts, the dialog in App.svelte), so a screen swap (the
// vault held, locked, unknown, or a session gone live or not) neither
// closes it nor points it at something else: it stays on the action the
// person opened it for, End session, until they answer or cancel. End
// session names no session (§6.8: it ends all of this desktop's access),
// so there is nothing in it to re-point.

/** @typedef {{ open: boolean, action: 'end' | null }} Confirm */

/** @type {Confirm} */
export const CLOSED = Object.freeze({ open: false, action: null });

/** The person opened End session's confirmation. @returns {Confirm} */
export function openEnd() {
  return { open: true, action: 'end' };
}

/**
 * A read of the backend came in (and the screen may swap with it): the
 * confirmation is left exactly as it was.
 * @param {Confirm} confirm
 * @returns {Confirm}
 */
export function afterRead(confirm) {
  return confirm;
}

/**
 * The person answered: `yes` runs the action the confirmation was opened
 * for; either way it closes.
 * @param {Confirm} confirm
 * @param {boolean} yes
 * @returns {{ confirm: Confirm, run: 'end' | null }}
 */
export function answer(confirm, yes) {
  return { confirm: CLOSED, run: confirm.open && yes ? confirm.action : null };
}
