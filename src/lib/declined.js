// The "your phone declined a new session" banner (#96), kept free of Svelte and Tauri for `npm test`.
//
// The phone declined Start New Session while the current session is live. The app then moves from the
// Start-a-new-session screen to Connections, which would drop a notice kept on that screen, so the notice has its
// own banner in App.svelte. It names when the current session ends, so it may only be shown while that is true:
// - shown while the session is active and before that time;
// - removed for good once the session stops being active after it was shown (ended, locked, held, stale), or
//   once the time has passed: a later session doesn't bring it back;
// - kept, hidden, while it hasn't been shown yet and the session isn't active yet (the app reads the live
//   session a moment after the decline), until the time passes.

/**
 * @typedef {{ text: string, until: number, seen: boolean }} DeclinedNotice
 */

/**
 * @param {DeclinedNotice | null} notice
 * @param {string} session The app's session state ('active', 'expired', ...)
 * @param {number} nowSecs Unix seconds
 * @returns {{ show: string | null, next: DeclinedNotice | null }} What to show now, and the notice to keep
 */
export function declinedStep(notice, session, nowSecs) {
  if (!notice || nowSecs >= notice.until) return { show: null, next: null };
  if (session === 'active') return { show: notice.text, next: notice.seen ? notice : { ...notice, seen: true } };
  return { show: null, next: notice.seen ? null : notice };
}
