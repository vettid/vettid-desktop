// What the connection views show and when they read again (DESKTOP-REWORK-PLAN
// Phase 5, 5.2), kept free of Svelte and Tauri for `npm test`. The names and
// texts are VAULT-MESSAGING 0.94.1's: §10.8 "What apps show" and "Showing
// received text", §10.4 `relay_held`.

/** §10.8: a connection's title when it has no names yet, or they clean to nothing. */
export const NAME_NOT_SHARED = 'Name not shared yet';
/** §10.8 "Showing received text" step 4: an empty name inside a sentence. */
export const A_CONNECTION = 'a connection';

const FSI = '\u2068';
const PDI = '\u2069';

/**
 * §10.8 "Showing received text", steps 1-3, for text shown on one line (a
 * name, a list row): each break and tab becomes a space, other Cc and Cf code
 * points go (ZWNJ and ZWJ stay), a lone surrogate becomes U+FFFD, and
 * White_Space is trimmed at both ends.
 * @param {unknown} text
 * @returns {string}
 */
export function cleanOneLine(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/\r\n|[\n\r\u000B\u000C\u0085\u2028\u2029\t]/g, ' ')
    .replace(/\p{Cs}/gu, '\uFFFD')
    .replace(/(?![\u200C\u200D])[\p{Cc}\p{Cf}]/gu, '')
    .replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '');
}

/**
 * §10.8 step 4: empty once every Default_Ignorable_Code_Point, White_Space
 * code point and U+2800 is set aside.
 * @param {string} text
 */
export function isEmptyText(text) {
  return text.replace(/[\p{Default_Ignorable_Code_Point}\p{White_Space}\u2800]/gu, '') === '';
}

/** Cleaned one-line text, or '' when it is empty by step 4. */
function shown(/** @type {unknown} */ text) {
  const t = cleanOneLine(text);
  return isEmptyText(t) ? '' : t;
}

/**
 * `first_name`, one space, `last_name` (§10.8), cleaned; '' when empty.
 * @param {{ first_name?: string, last_name?: string } | null | undefined} profile
 */
export function namesOf(profile) {
  if (!profile) return '';
  return shown(`${profile.first_name ?? ''} ${profile.last_name ?? ''}`);
}

/**
 * A connection's title (§10.8 "What apps show"): the owner's own `alias`
 * when set (it "may replace the title on the owner's screens"), else
 * `first_name last_name` from its `profile`, else "Name not shared yet".
 * Never from `name` alone (§10.4).
 * @param {{ alias?: string, profile?: { first_name?: string, last_name?: string } | null }} c
 * @returns {string}
 */
export function connectionTitle(c) {
  return shown(c.alias) || namesOf(c.profile) || NAME_NOT_SHARED;
}

/**
 * The secondary text under a title (§10.8): the names when the alias
 * replaced them ("the names still shown with it"), and the display name
 * when it is non-empty and differs from the names. Each is cleaned.
 * @param {{ alias?: string, name?: string, profile?: { first_name?: string, last_name?: string, name?: string } | null }} c
 * @returns {string[]}
 */
export function secondaryNames(c) {
  const names = namesOf(c.profile);
  const out = [];
  if (shown(c.alias) && names) out.push(names);
  const display = shown(c.name ?? c.profile?.name);
  if (display && display !== names) out.push(display);
  return out;
}

/**
 * A pending request's title (§10.8: "Pending requests show the requester's
 * names ... the same way"): its profile's names, else "Name not shared yet".
 * @param {{ name?: string, profile?: { first_name?: string, last_name?: string } | null }} r
 */
export function requestTitle(r) {
  return namesOf(r.profile) || NAME_NOT_SHARED;
}

/**
 * A request's display name as secondary text, when non-empty and different
 * from its names: an incoming request's profile `name`, an outgoing one's
 * `name` (the bundle's `hint.name`).
 * @param {{ name?: string, profile?: { first_name?: string, last_name?: string, name?: string } | null }} r
 * @returns {string[]}
 */
export function requestSecondary(r) {
  const display = shown(r.name ?? r.profile?.name);
  return display && display !== namesOf(r.profile) ? [display] : [];
}

/**
 * Text received from another party, put inside a sentence: wrapped in FSI ...
 * PDI (§10.8 step 5); "a connection" when it is the placeholder or empty.
 * @param {string} title
 */
export function inSentence(title) {
  const t = shown(title);
  if (!t || t === NAME_NOT_SHARED) return A_CONNECTION;
  return `${FSI}${t}${PDI}`;
}

/**
 * The owner-approved `relay_held` line (§10.4, 2026-11-12), with the title.
 * @param {string} title
 */
export function relayHeldText(title) {
  return `Waiting to reach ${inSentence(title)} at their vault's new address.`;
}

/**
 * The arguments for `decline_connection_request`: an incoming request by its
 * `pending_id`, an outgoing one by its `connection_id`, never both. `null`
 * when the id is missing (nothing is sent).
 * @param {'incoming' | 'outgoing'} side
 * @param {{ pending_id?: string, connection_id?: string }} req
 * @returns {{ pendingId: string } | { connectionId: string } | null}
 */
export function declineArgs(side, req) {
  if (side === 'incoming') return req.pending_id ? { pendingId: req.pending_id } : null;
  if (side === 'outgoing') return req.connection_id ? { connectionId: req.connection_id } : null;
  return null;
}

/** The `sync.event` kinds after which the connection views read again. */
export const RELOAD_KINDS = Object.freeze(['connection.changed', 'connection.request', 'block.added', 'block.removed']);

/**
 * What to do with a `vault:inbound` batch: `drop` it while the session isn't
 * live as the window shows it; `reload` the connection views on `resync` or
 * on a `sync.event` of one of RELOAD_KINDS; otherwise `none`.
 * @param {{ messages?: Array<{ type: string, body?: unknown }>, resync?: boolean } | null | undefined} batch
 * @param {boolean} live
 * @returns {'drop' | 'reload' | 'none'}
 */
export function inboundAction(batch, live) {
  if (!live) return 'drop';
  if (!batch) return 'none';
  if (batch.resync) return 'reload';
  const hit = (batch.messages ?? []).some(
    (m) => m?.type === 'sync.event' && RELOAD_KINDS.includes(/** @type {{ kind?: string } | undefined} */ (m.body)?.kind ?? ''),
  );
  return hit ? 'reload' : 'none';
}

/**
 * Whether the session's liveness changed between two session states: the
 * views read again then (to live: fresh data), or are cleared (to not live).
 * @param {string | undefined} prev
 * @param {string} next
 */
export function livenessChanged(prev, next) {
  return (prev === 'active') !== (next === 'active');
}
