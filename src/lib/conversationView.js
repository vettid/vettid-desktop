// What a conversation shows and how a send's answer changes it
// (DESKTOP-REWORK-PLAN Phase 5, 5.3), kept free of Svelte and Tauri for
// `npm test`. The shapes are VAULT-MESSAGING 0.95.0's (§10.5, §10.5.1,
// §10.5.2); the text rules are §10.5 "Links" and §10.8 "Showing received
// text". The send rule is in the doc comments of `send_message` and
// `retry_send` in src-tauri/src/commands/vault.rs.
//
// Message text is plaintext: these helpers keep it in memory only and never
// log it.

import { isEmptyText, relayHeldText } from './connectionView.js';

/** `message.send`'s bound on `text`, in UTF-8 bytes (§10.5; `MAX_TEXT_LEN` in link/inbound.rs). */
export const MAX_TEXT_BYTES = 16 * 1024;

/** The newest page and each older one are read with this `limit` (chosen; the vault's default is 100). */
export const PAGE_LIMIT = 50;

/** How long a receipt for a message this view doesn't have yet is kept, in
 *  case `send_message`'s answer naming it is still on its way (chosen). */
export const RECEIPT_HOLD_MS = 2 * 60_000;

// NEW TEXT (owner approval needed)
/** On a send past its `expires_at`, or done with an unreadable answer,
 *  while the conversation is read again to see whether it went. */
export const CHECKING_TEXT = 'Checking whether your vault sent this…';

// NEW TEXT (owner approval needed)
/** On a send that expired unconfirmed and that the conversation, read again
 *  since, doesn't show: its text is kept for the member to send again. */
export const NOT_FOUND_TEXT =
  "Your vault didn't confirm this message, and it isn't in the conversation. It may not have been sent.";

// NEW TEXT (owner approval needed)
/** §10.5.1 "Desktops": a message's attachment, in place of a thumbnail. */
export const ATTACHMENT_PLACEHOLDER = 'Attachment: open it on your phone.';

// NEW TEXT (owner approval needed)
/** A text message whose text is empty by §10.8 step 4 (never a blank bubble). */
export const EMPTY_MESSAGE = 'Empty message';

// NEW TEXT (owner approval needed)
/** §10.5: a service connection takes no messages; shown instead of a conversation. */
export const SERVICE_NO_MESSAGES = "This connection is a service. It doesn't take messages.";

// NEW TEXT (owner approval needed)
/** In place of the conversation while the session isn't live (as NOT_LIVE_TEXT for the list). */
export const MESSAGES_NOT_LIVE_TEXT = "Your session isn't live, so your messages aren't shown.";

// NEW TEXT (owner approval needed)
/** Shown above the messages when the page left some out as unreadable. */
export const UNREADABLE_MESSAGES =
  "Some messages couldn't be shown: your vault sent them in a form this desktop can't read.";

// NEW TEXT (owner approval needed) — the words are the plan's (Phase 5,
// "A message's state"); `held` uses the owner-approved relay_held line.
/** What an outgoing message's state is called, as Android shows it. */
export const DELIVERY_TEXT = Object.freeze({
  sending: 'Sending…',
  sent: 'Sent',
  delivered: 'Delivered',
  read: 'Read',
  // Unconfirmed, expired, unreadable and unsent show a notice instead.
  unconfirmed: 'Not confirmed yet',
});

const FSI = '\u2068';
const PDI = '\u2069';

// ---------------------------------------------------------------------------
// Ordering and merging
// ---------------------------------------------------------------------------

/**
 * @typedef {{
 *   connection_id: string, message_id: string, direction: 'in' | 'out',
 *   text: string, sent_at: string, delivered: boolean, read: boolean,
 *   attachment?: { att_id: string, kind: string, state: string, reason?: string } | null,
 * }} Message
 */

/** @param {string | undefined} iso */
function ms(iso) {
  const n = iso ? Date.parse(iso) : NaN;
  return Number.isNaN(n) ? 0 : n;
}

/**
 * The view's order: by `sent_at`, then `message_id`.
 * @param {{ sent_at: string, message_id: string }} a
 * @param {{ sent_at: string, message_id: string }} b
 */
export function compareMessages(a, b) {
  return ms(a.sent_at) - ms(b.sent_at) || (a.message_id < b.message_id ? -1 : a.message_id > b.message_id ? 1 : 0);
}

/**
 * Two copies of one message: the later copy's fields, with receipts never
 * going back (a page read before a receipt arrived doesn't undo it), and
 * the attachment kept when the later copy has none.
 * @param {Message} a
 * @param {Message} b
 * @returns {Message}
 */
function combine(a, b) {
  return {
    ...a,
    ...b,
    delivered: a.delivered || b.delivered || a.read || b.read,
    read: a.read || b.read,
    attachment: b.attachment ?? a.attachment ?? null,
  };
}

/**
 * Pages and live `message.new` merged by `message_id`, with no duplicates, in
 * the view's order. Messages of another connection are left out.
 * @param {Message[]} have
 * @param {Message[]} more
 * @param {string} connectionId
 * @returns {Message[]}
 */
export function mergeMessages(have, more, connectionId) {
  /** @type {Map<string, Message>} */
  const by = new Map();
  for (const m of [...have, ...more]) {
    if (!m || m.connection_id !== connectionId || !m.message_id) continue;
    const old = by.get(m.message_id);
    by.set(m.message_id, old ? combine(old, m) : { ...m, attachment: m.attachment ?? null });
  }
  return [...by.values()].sort(compareMessages);
}

/**
 * A `sync.event` of kind `message.receipt`, `message.read` or
 * `message.attachment` (§10.1) applied to the messages it names; any other
 * kind, or another connection's, changes nothing. A `read` receipt also
 * means delivered.
 * @template {{ connection_id?: string, message_id?: string, delivered?: boolean, read?: boolean, attachment?: Message['attachment'] }} M
 * @param {M[]} messages
 * @param {{ kind?: string, members?: Record<string, unknown> } | null | undefined} ev
 * @param {string} connectionId
 * @returns {M[]}
 */
export function applySyncEvent(messages, ev, connectionId) {
  const m = ev?.members ?? {};
  if (m.connection_id !== connectionId || typeof m.message_id !== 'string') return messages;
  /** @type {(x: M) => M} */
  let change;
  switch (ev?.kind) {
    case 'message.receipt':
      if (m.receipt === 'read') change = (x) => ({ ...x, delivered: true, read: true });
      else if (m.receipt === 'delivered') change = (x) => ({ ...x, delivered: true });
      else return messages;
      break;
    case 'message.read':
      // Another of the owner's devices marked an incoming message read.
      change = (x) => ({ ...x, read: true });
      break;
    case 'message.attachment':
      if (typeof m.state !== 'string') return messages;
      change = (x) =>
        x.attachment
          ? { ...x, attachment: { ...x.attachment, state: /** @type {string} */ (m.state), reason: typeof m.reason === 'string' ? m.reason : undefined } }
          : x;
      break;
    default:
      return messages;
  }
  return messages.map((x) => (x.message_id === m.message_id ? change(x) : x));
}

/**
 * Incoming messages marked read here (`message.read` answered `{}`).
 * @param {Message[]} messages
 * @param {string} messageId
 */
export function markedRead(messages, messageId) {
  return messages.map((x) => (x.message_id === messageId && x.direction === 'in' ? { ...x, read: true } : x));
}

/**
 * The next incoming unread message to mark read: oldest first, among those
 * the member has seen (shown in the viewport), skipping those already tried
 * in this read of the conversation; `null` when none. `message.read` names
 * one message (§10.5) and the spec doesn't say that it marks earlier ones,
 * so each is marked, one call at a time.
 * @param {Message[]} messages
 * @param {Set<string>} tried
 * @param {Set<string>} seen
 * @returns {string | null}
 */
export function nextToMark(messages, tried, seen) {
  const m = messages.find((x) => x.direction === 'in' && !x.read && seen.has(x.message_id) && !tried.has(x.message_id));
  return m ? m.message_id : null;
}

// ---------------------------------------------------------------------------
// Sends the view made itself
// ---------------------------------------------------------------------------

/**
 * A message this view sent, kept until a page has it. `state`:
 * - `sending`: `send_message` (or, with `retry`, `retry_send`) hasn't
 *   answered;
 * - `sent`: answered `{message_id, sent_at}` (the vault sends no
 *   `message.new` back to the desktop that sent it);
 * - `unconfirmed`: it may still be carried out: with `pending_id` and
 *   `expires_at` (ms) when the backend kept it, without them when the
 *   answer never came;
 * - `expired`: unconfirmed past `expires_at`, and `unreadable`: done with
 *   an answer that couldn't be read: the conversation is read again
 *   (`since` is when this state began);
 * - `unsent`: not sent, or not found by that read: its text is kept on the
 *   bubble for the member to send again deliberately.
 * `everUnconfirmed`: it was unconfirmed once, so it never goes back to a
 * draft on its own (only `settled: "not_done"` or a read that doesn't show
 * it after it expired).
 * @typedef {{
 *   key: string, connection_id: string, text: string, at: number,
 *   state: 'sending' | 'sent' | 'unconfirmed' | 'expired' | 'unreadable' | 'unsent',
 *   retry?: boolean, everUnconfirmed?: boolean,
 *   pending_id?: string, expires_at?: number, notice?: string, since?: number,
 *   message_id?: string, sent_at?: string, delivered?: boolean, read?: boolean,
 * }} Local
 */

/** A text that goes back to the member: the compose box, or an `unsent` bubble.
 *  @typedef {{ connection_id: string, text: string, error: string }} Returned */

let localSeq = 0;

/**
 * A new send, `sending`.
 * @param {string} connectionId
 * @param {string} text
 * @param {number} now
 * @returns {Local}
 */
export function newLocal(connectionId, text, now) {
  localSeq += 1;
  return { key: `local:${now}:${localSeq}`, connection_id: connectionId, text, at: now, state: 'sending' };
}

/**
 * An unconfirmed send whose "Try again" was pressed: `sending`, by
 * `retry_send` with its `pending_id`. Only an unconfirmed send with a
 * `pending_id` can be tried again; others are left as they are.
 * @param {Local[]} locals
 * @param {string} key
 * @returns {Local[]}
 */
export function startRetry(locals, key) {
  return locals.map((l) => (l.key === key && l.state === 'unconfirmed' && l.pending_id ? { ...l, state: /** @type {const} */ ('sending'), retry: true } : l));
}

/** @param {unknown} v */
function str(v) {
  return typeof v === 'string' && v !== '' ? v : null;
}

/** @param {unknown} v */
function time(v) {
  const n = typeof v === 'string' ? Date.parse(v) : NaN;
  return Number.isNaN(n) ? null : n;
}

/**
 * @param {unknown} d
 * @returns {{ message_id: string, sent_at: string } | null}
 */
function sentData(d) {
  const o = /** @type {{ message_id?: unknown, sent_at?: unknown } | null | undefined} */ (d);
  const id = str(o?.message_id);
  const at = str(o?.sent_at);
  return id && at && time(at) !== null ? { message_id: id, sent_at: at } : null;
}

/**
 * An answer about one send, from the top of a VaultOpResponse or from its
 * `earlier`.
 * @typedef {{ success: boolean, settled: string | null, code: string, error: string,
 *   sent: { message_id: string, sent_at: string } | null,
 *   pendingId: string | null, expiresAt: number | null, noAnswer: boolean }} Answer
 */

/**
 * @param {{ success?: boolean, data?: any, error?: string, error_code?: string } | null | undefined} r
 * @returns {Answer}
 */
function answerOf(r) {
  if (!r) return { success: false, settled: null, code: 'unconfirmed', error: '', sent: null, pendingId: null, expiresAt: null, noAnswer: true };
  const d = r.data ?? {};
  return { success: !!r.success, settled: str(d.settled), code: r.error_code ?? '', error: r.error ?? '', sent: sentData(d), pendingId: str(d.pending_id), expiresAt: time(d.expires_at), noAnswer: false };
}

/**
 * @param {any} e
 * @returns {Answer}
 */
function earlierOf(e) {
  return { success: !!e.success, settled: str(e.settled), code: e.error_code ?? '', error: e.error ?? '', sent: sentData(e.data), pendingId: str(e.pending_id), expiresAt: time(e.expires_at), noAnswer: false };
}

/**
 * What an answer does to one send (send_message's rule, 5.3b):
 * - success or `settled: "done"`: sent, with `{message_id, sent_at}`; done
 *   without a usable one: `unreadable` (read again), never a draft;
 * - `settled: "not_done"`: not sent: its text goes back;
 * - `unconfirmed_expired`: `expired`; `answer_unreadable`: `unreadable`;
 * - a `pending_id`: unconfirmed until `expires_at` (a new id is a new
 *   request: its time starts now);
 * - `unconfirmed`, or no answer at all: unconfirmed;
 * - anything else: unconfirmed if it ever was (or holds a `pending_id`);
 *   otherwise, for a first try (`fresh`), never sent: its text goes back.
 * @param {Local} l
 * @param {Answer} a
 * @param {number} now
 * @param {boolean} fresh
 * @returns {{ local: Local | null, returned: Returned | null, refresh: boolean }}
 */
function settleLocal(l, a, now, fresh) {
  const { retry: _r, ...base } = l;
  if (a.success || a.settled === 'done') {
    if (a.sent) {
      const { pending_id: _p, expires_at: _e, notice: _n, since: _s, ...rest } = base;
      return { local: { ...rest, state: 'sent', ...a.sent }, returned: null, refresh: false };
    }
    return { local: { ...base, state: 'unreadable', notice: a.error || CHECKING_TEXT, since: now }, returned: null, refresh: true };
  }
  if (a.settled === 'not_done') return { local: null, returned: { connection_id: l.connection_id, text: l.text, error: a.error }, refresh: false };
  if (a.code === 'unconfirmed_expired') return { local: { ...base, state: 'expired', notice: a.error || CHECKING_TEXT, since: now }, returned: null, refresh: true };
  if (a.code === 'answer_unreadable') return { local: { ...base, state: 'unreadable', notice: a.error || CHECKING_TEXT, since: now }, returned: null, refresh: true };
  if (a.pendingId) {
    const at = l.pending_id && l.pending_id !== a.pendingId ? now : l.at;
    return {
      local: { ...base, state: 'unconfirmed', everUnconfirmed: true, pending_id: a.pendingId, expires_at: a.expiresAt ?? l.expires_at, at, notice: a.error || l.notice || '' },
      returned: null,
      refresh: false,
    };
  }
  if (a.code === 'unconfirmed' || a.noAnswer || l.everUnconfirmed || l.pending_id || !fresh) {
    return { local: { ...base, state: 'unconfirmed', everUnconfirmed: true, notice: a.error || l.notice || '' }, returned: null, refresh: false };
  }
  return { local: null, returned: { connection_id: l.connection_id, text: l.text, error: a.error }, refresh: false };
}

/**
 * @param {Local[]} out
 * @param {number} i
 * @param {{ local: Local | null, returned: Returned | null, refresh: boolean }} s
 * @param {Returned[]} returned
 */
function put(out, i, s, returned) {
  if (s.local) out[i] = s.local;
  else out.splice(i, 1);
  if (s.returned) returned.push(s.returned);
  return s.refresh;
}

/**
 * `send_message`'s answer applied to the send `key` (always a new message;
 * see its doc comment in commands/vault.rs). `data.earlier` first: the kept
 * send it names by `pending_id` (never this send itself) is settled as
 * above; one the view doesn't have only asks for a read when it settled
 * or expired. Then this send, as a first try. `returned`: texts that go
 * back to the member (placeReturned); `refresh`: read the newest page.
 * @param {Local[]} locals
 * @param {string} key
 * @param {{ success?: boolean, data?: any, error?: string, error_code?: string } | null} resp
 * @param {number} now
 * @returns {{ locals: Local[], returned: Returned[], refresh: boolean }}
 */
export function applySendAnswer(locals, key, resp, now) {
  const out = locals.slice();
  /** @type {Returned[]} */
  const returned = [];
  let refresh = false;
  const e = resp?.data?.earlier;
  if (e && str(e.pending_id)) {
    const a = earlierOf(e);
    const i = out.findIndex((l) => l.key !== key && l.pending_id === e.pending_id);
    if (i >= 0) refresh = put(out, i, settleLocal(out[i], a, now, false), returned) || refresh;
    else if (a.success || a.settled || a.code === 'unconfirmed_expired') refresh = true;
  }
  const j = out.findIndex((l) => l.key === key);
  if (j >= 0) refresh = put(out, j, settleLocal(out[j], answerOf(resp), now, true), returned) || refresh;
  return { locals: dedupeLocals(out), returned, refresh };
}

/**
 * `retry_send`'s answer applied to the send `key`: sent on `settled:
 * "done"`, back to the member on `settled: "not_done"`, expired or
 * unreadable on those codes, and otherwise still unconfirmed (never a
 * draft).
 * @param {Local[]} locals
 * @param {string} key
 * @param {{ success?: boolean, data?: any, error?: string, error_code?: string } | null} resp
 * @param {number} now
 * @returns {{ locals: Local[], returned: Returned[], refresh: boolean }}
 */
export function applyRetryAnswer(locals, key, resp, now) {
  const out = locals.slice();
  /** @type {Returned[]} */
  const returned = [];
  const j = out.findIndex((l) => l.key === key);
  const refresh = j >= 0 ? put(out, j, settleLocal(out[j], answerOf(resp), now, false), returned) : false;
  return { locals: dedupeLocals(out), returned, refresh };
}

/**
 * One local per `message_id` and per `pending_id`: the first is kept.
 * @param {Local[]} locals
 * @returns {Local[]}
 */
export function dedupeLocals(locals) {
  const ids = new Set();
  const pids = new Set();
  return locals.filter((l) => {
    if (l.message_id) {
      if (ids.has(l.message_id)) return false;
      ids.add(l.message_id);
    }
    if (l.pending_id) {
      if (pids.has(l.pending_id)) return false;
      pids.add(l.pending_id);
    }
    return true;
  });
}

/**
 * Unconfirmed sends past their `expires_at` (the backend's: `exp` plus its
 * margin): expired, so the conversation is read again before anything is
 * offered. A send in flight, and one without `expires_at`, is left as it is.
 * @param {Local[]} locals
 * @param {number} now
 * @returns {{ locals: Local[], changed: boolean }}
 */
export function expireDue(locals, now) {
  let changed = false;
  const out = locals.map((l) => {
    if (l.state !== 'unconfirmed' || l.expires_at == null || now < l.expires_at) return l;
    changed = true;
    return { ...l, state: /** @type {const} */ ('expired'), notice: CHECKING_TEXT, since: now };
  });
  return { locals: out, changed };
}

/**
 * After a read of the newest page that started at `startedAt`:
 * - a sent message the page has is no longer kept here;
 * - an unreadable send (it was done) is dropped;
 * - an expired send, and an unconfirmed one without a `pending_id`, is
 *   looked for on the page: an outgoing message with the same text, sent at
 *   or after the send began, each page message matching one send. Found, it
 *   is dropped (the page shows it); not found, an expired send is `unsent`
 *   (its text kept on the bubble, never put in the box), and one without a
 *   `pending_id` stays unconfirmed;
 * - only sends in that state before the read started count.
 * `recheck`: this connection still has expired or unreadable sends that
 * began after the read started, so read again.
 * @param {Local[]} locals
 * @param {string} connectionId
 * @param {Message[]} page
 * @param {number} startedAt
 * @returns {{ locals: Local[], recheck: boolean }}
 */
export function afterReload(locals, connectionId, page, startedAt) {
  const ids = new Set(page.map((m) => m.message_id));
  const used = new Set(locals.filter((l) => l.connection_id === connectionId && l.message_id && ids.has(l.message_id)).map((l) => l.message_id));
  const outs = page.filter((m) => m.direction === 'out');
  /** @param {Local} l */
  const found = (l) => {
    const m = outs.find((x) => !used.has(x.message_id) && x.text === l.text && ms(x.sent_at) >= l.at);
    if (m) used.add(m.message_id);
    return !!m;
  };
  /** @type {Local[]} */
  const out = [];
  for (const l of locals) {
    if (l.connection_id !== connectionId) {
      out.push(l);
      continue;
    }
    if (l.state === 'sent') {
      if (!(l.message_id && ids.has(l.message_id))) out.push(l);
      continue;
    }
    const before = (l.since ?? Infinity) <= startedAt;
    if (l.state === 'unreadable' && before) continue;
    if (l.state === 'expired' && before) {
      if (!found(l)) out.push({ ...l, state: 'unsent', notice: NOT_FOUND_TEXT });
      continue;
    }
    if (l.state === 'unconfirmed' && !l.pending_id && l.at <= startedAt && found(l)) continue;
    out.push(l);
  }
  const recheck = out.some((l) => l.connection_id === connectionId && (l.state === 'expired' || l.state === 'unreadable'));
  return { locals: out, recheck };
}

/**
 * Texts that go back to the member: the first for a connection fills its
 * compose box when the box is empty, with its error under the box; any
 * other is kept as an `unsent` bubble with its error, so that texts are
 * never joined into one.
 * @param {Local[]} locals
 * @param {Record<string, string>} drafts
 * @param {Returned[]} returned
 * @param {number} now
 * @returns {{ locals: Local[], drafts: Record<string, string>, errors: Record<string, string> }}
 */
export function placeReturned(locals, drafts, returned, now) {
  const d = { ...drafts };
  /** @type {Record<string, string>} */
  const errors = {};
  const out = locals.slice();
  for (const r of returned) {
    if (!(d[r.connection_id] ?? '') && !(r.connection_id in errors)) {
      d[r.connection_id] = r.text;
      errors[r.connection_id] = r.error;
    } else {
      out.push({ ...newLocal(r.connection_id, r.text, now), state: 'unsent', notice: r.error });
    }
  }
  return { locals: out, drafts: d, errors };
}

/**
 * An `unsent` bubble's "Edit": its text goes to the compose box, only when
 * the box is empty; `null` otherwise.
 * @param {Local[]} locals
 * @param {Record<string, string>} drafts
 * @param {string} key
 * @returns {{ locals: Local[], drafts: Record<string, string> } | null}
 */
export function unsentToDraft(locals, drafts, key) {
  const l = locals.find((x) => x.key === key && x.state === 'unsent');
  if (!l || (drafts[l.connection_id] ?? '') !== '') return null;
  return { locals: locals.filter((x) => x !== l), drafts: { ...drafts, [l.connection_id]: l.text } };
}

/**
 * Sends and drafts of connections the list no longer has are dropped.
 * @param {Local[]} locals
 * @param {Record<string, string>} drafts
 * @param {Set<string>} ids
 */
export function pruneKept(locals, drafts, ids) {
  /** @type {Record<string, string>} */
  const d = {};
  for (const [k, v] of Object.entries(drafts)) if (ids.has(k)) d[k] = v;
  return { locals: locals.filter((l) => ids.has(l.connection_id)), drafts: d };
}

// ---------------------------------------------------------------------------
// Receipts that come before the answer naming their message
// ---------------------------------------------------------------------------

/** @typedef {{ kind?: string, members?: Record<string, unknown> }} SyncEv */

/**
 * Whether a `sync.event` names a message this view has (on a page, or one
 * of its own sends with a `message_id`); events of other kinds or other
 * connections count as known (nothing to hold).
 * @param {Message[]} messages
 * @param {Local[]} locals
 * @param {SyncEv | null | undefined} ev
 * @param {string} connectionId
 */
export function knowsEvent(messages, locals, ev, connectionId) {
  const m = ev?.members ?? {};
  if (!['message.receipt', 'message.read', 'message.attachment'].includes(ev?.kind ?? '')) return true;
  if (m.connection_id !== connectionId || typeof m.message_id !== 'string') return true;
  const id = m.message_id;
  return messages.some((x) => x.message_id === id) || locals.some((l) => l.message_id === id);
}

/**
 * Events held for messages not known yet, the stale ones (past
 * RECEIPT_HOLD_MS) dropped; `ready` are those whose message is known now,
 * in the order they came.
 * @param {Array<{ ev: SyncEv, at: number }>} held
 * @param {(ev: SyncEv) => boolean} known
 * @param {number} now
 * @returns {{ ready: SyncEv[], held: Array<{ ev: SyncEv, at: number }> }}
 */
export function releaseHeld(held, known, now) {
  /** @type {SyncEv[]} */
  const ready = [];
  const rest = [];
  for (const h of held) {
    if (now - h.at > RECEIPT_HOLD_MS) continue;
    if (known(h.ev)) ready.push(h.ev);
    else rest.push(h);
  }
  return { ready, held: rest };
}

/**
 * One list for the view: the vault's messages, and this view's own sends of
 * this connection that no page has yet. Sends without `sent_at` come last,
 * in the order they were made.
 * @param {Message[]} messages
 * @param {Local[]} locals
 * @param {string} connectionId
 * @returns {Array<Message & { key: string, local?: Local }>}
 */
export function viewMessages(messages, locals, connectionId) {
  const have = new Set(messages.map((m) => m.message_id));
  /** @type {Array<Message & { key: string, local?: Local }>} */
  const out = messages.map((m) => ({ ...m, key: m.message_id }));
  const mine = locals.filter((l) => l.connection_id === connectionId && !(l.message_id && have.has(l.message_id)));
  for (const l of mine.filter((x) => x.state === 'sent')) {
    out.push({
      connection_id: connectionId,
      message_id: l.message_id ?? '',
      direction: 'out',
      text: l.text,
      sent_at: l.sent_at ?? '',
      // Receipts that came before a page had it.
      delivered: !!l.delivered,
      read: !!l.read,
      attachment: null,
      key: l.key,
      local: l,
    });
  }
  out.sort(compareMessages);
  for (const l of mine.filter((x) => x.state !== 'sent').sort((a, b) => a.at - b.at)) {
    out.push({ connection_id: connectionId, message_id: '', direction: 'out', text: l.text, sent_at: '', delivered: false, read: false, attachment: null, key: l.key, local: l });
  }
  return out;
}

// ---------------------------------------------------------------------------
// What a bubble shows
// ---------------------------------------------------------------------------

/**
 * An outgoing message's delivery state, as the plan's "A message's state"
 * says (the booleans, never a guess): `sending`, `unconfirmed`, `expired`,
 * `unreadable` and `unsent` for this view's own sends; then `read`,
 * `delivered`, `held` (the connection's `relay_held`, without
 * `delivered`), `sent`. `feed` is 5.4's hook: a `message.not_delivered` or
 * `message.delivery_unconfirmed` item for this message, when there is one.
 * `null` for an incoming message.
 * @param {{ direction: string, delivered: boolean, read: boolean, local?: { state: string } }} m
 * @param {{ relayHeld?: boolean, feed?: 'not_delivered' | 'not_confirmed' | null }} [opts]
 * @returns {null | 'sending' | 'unconfirmed' | 'expired' | 'unreadable' | 'unsent' | 'not_delivered' | 'not_confirmed' | 'read' | 'delivered' | 'held' | 'sent'}
 */
export function deliveryState(m, opts = {}) {
  if (m.direction !== 'out') return null;
  const s = m.local?.state;
  if (s === 'sending' || s === 'unconfirmed' || s === 'expired' || s === 'unreadable' || s === 'unsent') return s;
  if (m.read) return 'read';
  if (m.delivered) return 'delivered';
  if (opts.feed) return opts.feed;
  if (opts.relayHeld) return 'held';
  return 'sent';
}

/**
 * The line under an outgoing bubble for its state; '' when there is none
 * to show (5.4 brings the feed's texts). The notice of an unconfirmed,
 * expired, unreadable or unsent send is the backend's text, or this view's.
 * @param {ReturnType<typeof deliveryState>} state
 * @param {{ notice?: string, title?: string }} [opts]
 */
export function deliveryText(state, opts = {}) {
  switch (state) {
    case 'sending':
    case 'sent':
    case 'delivered':
    case 'read':
      return DELIVERY_TEXT[state];
    case 'held':
      return relayHeldText(opts.title ?? '');
    case 'unconfirmed':
      return opts.notice || DELIVERY_TEXT.unconfirmed;
    case 'expired':
    case 'unreadable':
      return opts.notice || CHECKING_TEXT;
    case 'unsent':
      return opts.notice || NOT_FOUND_TEXT;
    default:
      return '';
  }
}

/**
 * §10.8 "Showing received text", the lighter cleaning for a message's full
 * text in its own bubble: breaks become LF (CR LF is one); tabs become
 * spaces; Cc and Cf code points go except LF, ZWNJ, ZWJ, LRM, RLM and ALM;
 * a lone surrogate becomes U+FFFD; White_Space is trimmed at the ends of
 * the whole text only (a line's indentation stays).
 * @param {unknown} text
 * @returns {string}
 */
export function cleanBubble(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/\r\n|[\r\u000B\u000C\u0085\u2028\u2029]/g, '\n')
    .replace(/\t/g, ' ')
    .replace(/\p{Cs}/gu, '\uFFFD')
    .replace(/(?![\n\u200C\u200D\u200E\u200F\u061C])[\p{Cc}\p{Cf}]/gu, '')
    .replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '');
}

/** @typedef {{ text: string } | { text: string, href: string, host: string }} Piece */

/** Closing brackets, with the opening one each pairs with. */
const CLOSERS = Object.freeze({ ')': '(', ']': '[', '}': '{' });

/**
 * A URL without the punctuation that more often ends the sentence: a
 * trailing `.,;:!?'">`, and a closing bracket the URL doesn't open (a
 * balanced one, as in a Wikipedia link, stays).
 * @param {string} raw
 */
function trimTrail(raw) {
  let s = raw;
  for (;;) {
    const c = s.slice(-1);
    if (/[.,;:!?'">]/.test(c) && c !== '') {
      s = s.slice(0, -1);
      continue;
    }
    const open = CLOSERS[/** @type {keyof typeof CLOSERS} */ (c)];
    if (open && s.split(open).length - 1 < s.split(c).length - 1) {
      s = s.slice(0, -1);
      continue;
    }
    return s;
  }
}

/**
 * §10.5 "Links": only `https://` URLs are links; every other scheme is
 * text. A link's `host` is what the view shows before it asks to open it
 * (the URL's own parsing, so an internationalised host shows as punycode).
 * @param {string} line
 * @returns {Piece[]}
 */
export function linkPieces(line) {
  /** @type {Piece[]} */
  const out = [];
  let last = 0;
  for (const m of line.matchAll(/https:\/\/[^\s]+/gi)) {
    const start = m.index ?? 0;
    const raw = trimTrail(m[0]);
    let url = null;
    try {
      url = new URL(raw);
    } catch {
      url = null;
    }
    if (!url || url.protocol !== 'https:' || !url.hostname) continue;
    if (start > last) out.push({ text: line.slice(last, start) });
    out.push({ text: raw, href: url.href, host: url.hostname });
    last = start + raw.length;
  }
  if (last < line.length) out.push({ text: line.slice(last) });
  return out;
}

/**
 * A bubble's body: its lines, cleaned as above, each as link pieces; the
 * view shows each line in FSI ... PDI (§10.8: "each line in FSI … PDI").
 * `empty` when the text is empty by §10.8 step 4.
 * @param {unknown} text
 * @returns {{ empty: boolean, lines: Piece[][] }}
 */
export function bubbleLines(text) {
  const t = cleanBubble(text);
  if (isEmptyText(t)) return { empty: true, lines: [] };
  return { empty: false, lines: t.split('\n').map(linkPieces) };
}

/** The isolates around one line of a bubble. */
export const LINE_ISOLATE = Object.freeze({ start: FSI, end: PDI });

/**
 * What a message's bubble holds: an attachment shows its placeholder (no
 * thumbnail; nothing is fetched), its caption under it when the caption
 * isn't empty; a text message shows its text, or EMPTY_MESSAGE when that
 * is empty by step 4.
 * @param {{ text: string, attachment?: unknown }} m
 * @returns {{ placeholder: string | null, body: { empty: boolean, lines: Piece[][] } | null }}
 */
export function bubbleContent(m) {
  const body = bubbleLines(m.text);
  if (m.attachment) return { placeholder: ATTACHMENT_PLACEHOLDER, body: body.empty ? null : body };
  return { placeholder: null, body };
}

/**
 * A draft's size as `send_message` counts it: UTF-8 bytes.
 * @param {string} text
 */
export function textBytes(text) {
  return new TextEncoder().encode(text).length;
}

/**
 * Whether the compose box can be sent: 1 B to MAX_TEXT_BYTES, and not
 * empty by §10.8 step 4 (white space, zero-width and other invisible code
 * points only).
 * @param {string} text
 */
export function canSend(text) {
  const n = textBytes(text);
  return n >= 1 && n <= MAX_TEXT_BYTES && !isEmptyText(text);
}

// NEW TEXT (owner approval needed)
/**
 * Under the box when the draft is over the bound.
 * @param {number} bytes
 */
export function tooLongText(bytes) {
  return `This message is too long to send: ${bytes.toLocaleString('en-US')} of ${MAX_TEXT_BYTES.toLocaleString('en-US')} bytes.`;
}

/** Whether a connection takes messages (§10.5: a service connection doesn't). */
export function takesMessages(/** @type {{ peer_kind?: string }} */ c) {
  return c.peer_kind !== 'service';
}

/**
 * What to do with a `vault:inbound` batch for the conversation on screen:
 * `drop` while the session isn't live; `reload` the newest page on
 * `resync`; otherwise `apply` its messages.
 * @param {{ resync?: boolean } | null | undefined} batch
 * @param {boolean} live
 * @returns {'drop' | 'reload' | 'apply'}
 */
export function conversationAction(batch, live) {
  if (!live || !batch) return 'drop';
  return batch.resync ? 'reload' : 'apply';
}

// NEW TEXT (owner approval needed)
/**
 * Asked before a link is opened (§10.5: "show its host and ask").
 * @param {string} host
 */
export function openLinkQuestion(host) {
  return `Open this link in your browser? It goes to ${FSI}${host}${PDI}.`;
}

// NEW TEXT (owner approval needed)
/** When the system wouldn't open a link (the app's shell scope refuses most hosts). */
export const LINK_NOT_OPENED = "This desktop couldn't open this link.";
