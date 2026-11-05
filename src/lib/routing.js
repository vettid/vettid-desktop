// The app's routing rule on state changes, kept free of Svelte and Tauri so
// it can be tested on its own (`npm test`). App.svelte applies its answer.

/**
 * @typedef {'loading' | 'pairing' | 'expired' | 'session-detail' | 'vault' | 'connections' | 'settings'} View
 * @typedef {'active' | 'expired' | 'suspended' | 'revoked' | 'inactive'} SessionKind
 */

/**
 * Where a state change takes the person, from `current`.
 *
 * While a pairing is under way on the pairing view (`pairingHeld`: the
 * code was sent, or its result is on screen), nothing moves the person off
 * it (#79): the pairing view itself says how the pairing went, and the
 * person leaves it with Continue or Try Again. Without that, the 30 s poll
 * could replace a rejection with "Your pairing is in place".
 *
 * @param {{ current: View, session: SessionKind, isRegistered: boolean, pairingHeld: boolean }} s
 * @returns {View}
 */
export function nextView({ current, session, isRegistered, pairingHeld }) {
  if (pairingHeld && current === 'pairing') return current;

  if (session === 'active') {
    // Out of the pre-session takeovers, to Connections; a real
    // destination stays.
    if (current === 'loading' || current === 'pairing' || current === 'expired') return 'connections';
    return current;
  }
  if (session === 'expired' || session === 'suspended') {
    // Don't take the person out of Settings.
    return current === 'settings' ? current : 'expired';
  }
  if (session === 'revoked') {
    return current === 'settings' ? current : 'pairing';
  }
  // inactive
  if (isRegistered) return current === 'settings' ? current : 'expired';
  return 'pairing';
}
