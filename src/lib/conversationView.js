// What a conversation shows and how a send's answer changes it
// (DESKTOP-REWORK-PLAN Phase 5, 5.3), kept free of Svelte and Tauri for
// `npm test`. The shapes are VAULT-MESSAGING 0.94.1's (§10.5, §10.5.1,
// §10.5.2); the text rules are §10.5 "Links" and §10.8 "Showing received
// text". The send rule is `send_message`'s in src-tauri/src/commands/vault.rs.
//
// Message text is plaintext: these helpers keep it in memory only and never
// log it.

import { isEmptyText, relayHeldText } from './connectionView.js';

/** `message.send`'s bound on `text`, in UTF-8 bytes (§10.5; `MAX_TEXT_LEN` in link/inbound.rs). */
export const MAX_TEXT_BYTES = 16 * 1024;

/** The newest page and each older one are read with this `limit` (chosen; the vault's default is 100). */
export const PAGE_LIMIT = 50;

/**
 * How long after its first try a send left unconfirmed can still be carried
 * out: the change's `exp` (`ops::CHANGE_TTL`, 2 minutes), the margin for the
 * vault's clock (`ops::KEPT_MARGIN`, 5 minutes), and 30 s for the time
 * between this view's clock reading and the backend's. Past it the view
 * treats the message as the backend's `unconfirmed_expired`: it reads the
 * conversation again before it offers the text again.
 */
export const KEPT_FOR_MS = (2 + 5) * 60_000 + 30_000;

// NEW TEXT (owner approval needed) — the backend's
// `OP_UNCONFIRMED_EXPIRED_NOTICE`, word for word, said when this view's own
// clock finds a send past KEPT_FOR_MS.
export const UNCONFIRMED_EXPIRED_TEXT =
  "Your vault didn't confirm this in time. Refresh to see whether it was done before you try again.";

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
  // Unconfirmed, expired and unreadable show the backend's notice instead.
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
 * The next incoming unread message to mark read, oldest first, skipping
 * those already tried in this read of the conversation; `null` when none.
 * `message.read` names one message (§10.5) and the spec doesn't say that
 * it marks earlier ones, so each is marked, one call at a time.
 * @param {Message[]} messages
 * @param {Set<string>} tried
 * @returns {string | null}
 */
export function nextToMark(messages, tried) {
  const m = messages.find((x) => x.direction === 'in' && !x.read && !tried.has(x.message_id));
  return m ? m.message_id : null;
}

// ---------------------------------------------------------------------------
// Sends the view made itself
// ---------------------------------------------------------------------------

/**
 * A message this view sent, kept until a page has it. `state`:
 * - `sending`: `send_message` hasn't answered;
 * - `sent`: answered `{message_id, sent_at}` (the vault sends no
 *   `message.new` back to the desktop that sent it);
 * - `unconfirmed`: it may still be carried out; `pending_id` when the
 *   backend kept it under one;
 * - `expired`: unconfirmed past its time: read the conversation, then the
 *   text is offered again;
 * - `unreadable`: the vault did it, its answer couldn't be read: read the
 *   conversation, and the text is not offered again.
 * A send that never got a `pending_id` and failed is no message: its text
 * goes back to the compose box (a draft).
 * @typedef {{
 *   key: string, connection_id: string, text: string, at: number,
 *   state: 'sending' | 'sent' | 'unconfirmed' | 'expired' | 'unreadable',
 *   pending_id?: string, notice?: string, since?: number,
 *   message_id?: string, sent_at?: string, delivered?: boolean, read?: boolean,
 * }} Local
 */

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
 * The unconfirmed message a new send of `text` is the same as: the backend
 * retries a kept send under its id when the same text goes to the same
 * connection again, so that send is this message's, not a new one.
 * @param {Local[]} locals
 * @param {string} connectionId
 * @param {string} text
 * @returns {Local | undefined}
 */
export function sameUnconfirmed(locals, connectionId, text) {
  return locals.find((l) => l.state === 'unconfirmed' && l.connection_id === connectionId && l.text === text);
}

/**
 * @typedef {{ success: boolean, data?: any, error?: string, error_code?: string }} SendResp
 */

/**
 * @param {unknown} d
 * @returns {{ message_id: string, sent_at: string } | null}
 */
function sentData(d) {
  const o = /** @type {{ message_id?: unknown, sent_at?: unknown } | null | undefined} */ (d);
  return o && typeof o.message_id === 'string' && o.message_id && typeof o.sent_at === 'string' && o.sent_at
    ? { message_id: o.message_id, sent_at: o.sent_at }
    : null;
}

/**
 * What an answer does to a message that holds a `pending_id`, or to the one
 * just sent: `sent`, `expired`, `unreadable`, or still `unconfirmed`. The
 * rule (send_message, 5.3b): unconfirmed on every answer except success,
 * `unconfirmed_expired` and `answer_unreadable`.
 * @param {Local} l
 * @param {{ success?: boolean, data?: unknown, error?: string, error_code?: string }} r
 * @param {number} now
 * @returns {Local}
 */
function settle(l, r, now) {
  const sent = r.success ? sentData(r.data) : null;
  if (sent) {
    const { pending_id: _p, notice: _n, since: _s, ...rest } = l;
    return { ...rest, state: 'sent', ...sent };
  }
  if (r.error_code === 'unconfirmed_expired') return { ...l, state: 'expired', notice: r.error ?? UNCONFIRMED_EXPIRED_TEXT, since: now };
  if (r.error_code === 'answer_unreadable') return { ...l, state: 'unreadable', notice: r.error ?? '', since: now };
  return { ...l, state: 'unconfirmed', notice: r.error ?? l.notice ?? '' };
}

/**
 * `send_message`'s answer applied to the send `key` (VaultOpResponse; see
 * `sent_response` in commands/vault.rs).
 * - `data.earlier` first: the kept send it names by `pending_id` is sent,
 *   expired, unreadable or still unconfirmed. One the view doesn't have
 *   (another window's, or forgotten) only asks for a read.
 * - Then this send: sent on success; unconfirmed on `unconfirmed` (with
 *   `data.pending_id` when there is one), expired or unreadable on those
 *   codes. A send that already holds a `pending_id` (a retry of the same
 *   text) stays unconfirmed on any other answer, `no_session`, `locked`,
 *   `held`, `not_sent`, `clock` and `earlier_unconfirmed` included: it may
 *   still be carried out. A first try with any other answer is no message:
 *   `draft` is its text, and `error` the backend's text, for under the box.
 * - `refresh`: read the newest page (an expired or unreadable send, or an
 *   `earlier` the view couldn't place).
 * A send that gets no answer at all (the call itself failed) is taken as
 * unconfirmed, never as not sent.
 * @param {Local[]} locals
 * @param {string} key
 * @param {SendResp | null} resp
 * @param {number} now
 * @returns {{ locals: Local[], draft: string | null, error: string, refresh: boolean }}
 */
export function applySendAnswer(locals, key, resp, now) {
  let refresh = false;
  let out = locals.slice();
  const earlier = resp?.data?.earlier;
  if (earlier && typeof earlier.pending_id === 'string' && earlier.pending_id) {
    const i = out.findIndex((l) => l.key !== key && l.pending_id === earlier.pending_id);
    if (i >= 0) {
      out[i] = settle(out[i], earlier, now);
      if (out[i].state === 'expired' || out[i].state === 'unreadable') refresh = true;
    } else {
      refresh = true;
    }
  }
  const j = out.findIndex((l) => l.key === key);
  if (j < 0) return { locals: out, draft: null, error: '', refresh };
  const l = out[j];
  const r = resp ?? { success: false, error_code: 'unconfirmed' };
  /** @type {string | null} */
  let draft = null;
  let error = '';
  if (r.success && sentData(r.data)) {
    out[j] = settle(l, r, now);
  } else if (l.pending_id || ['unconfirmed', 'unconfirmed_expired', 'answer_unreadable'].includes(r.error_code ?? '')) {
    const pid = r.error_code === 'unconfirmed' && typeof r.data?.pending_id === 'string' && r.data.pending_id ? r.data.pending_id : l.pending_id;
    // A new id is a new request, with its own time to run.
    const at = pid && pid !== l.pending_id && l.pending_id ? now : l.at;
    out[j] = settle(pid ? { ...l, pending_id: pid, at } : l, r, now);
    if (out[j].state === 'expired' || out[j].state === 'unreadable') refresh = true;
  } else {
    // Never sent: the text is the draft again.
    out.splice(j, 1);
    draft = l.text;
    error = r.error ?? '';
  }
  return { locals: out, draft, error, refresh };
}

/**
 * A send the view is about to retry (the same text again): `sending`, with
 * its `pending_id` kept.
 * @param {Local[]} locals
 * @param {string} key
 */
export function retrying(locals, key) {
  return locals.map((l) => (l.key === key ? { ...l, state: /** @type {const} */ ('sending') } : l));
}

/**
 * Unconfirmed sends past KEPT_FOR_MS, by this view's clock: expired, as the
 * backend's `unconfirmed_expired` would say. `changed` when any was.
 * @param {Local[]} locals
 * @param {number} now
 * @returns {{ locals: Local[], changed: boolean }}
 */
export function expireStale(locals, now) {
  let changed = false;
  const out = locals.map((l) => {
    if (l.state !== 'unconfirmed' || now - l.at < KEPT_FOR_MS) return l;
    changed = true;
    return { ...l, state: /** @type {const} */ ('expired'), notice: UNCONFIRMED_EXPIRED_TEXT, since: now };
  });
  return { locals: out, changed };
}

/**
 * After a read of the newest page that started at `startedAt`: a sent
 * message the page has is no longer kept here; an unreadable send (it was
 * done) is dropped; an expired send's text is offered again (`returned`,
 * oldest first) once a read started after it expired.
 * @param {Local[]} locals
 * @param {string} connectionId
 * @param {Set<string>} pageIds
 * @param {number} startedAt
 * @returns {{ locals: Local[], returned: string[] }}
 */
export function afterReload(locals, connectionId, pageIds, startedAt) {
  /** @type {string[]} */
  const returned = [];
  const out = locals.filter((l) => {
    if (l.connection_id !== connectionId) return true;
    if (l.state === 'sent') return !(l.message_id && pageIds.has(l.message_id));
    if ((l.state === 'expired' || l.state === 'unreadable') && (l.since ?? Infinity) <= startedAt) {
      if (l.state === 'expired') returned.push(l.text);
      return false;
    }
    return true;
  });
  return { locals: out, returned };
}

/**
 * The compose box after texts are offered again: those texts first, then
 * what is in the box, one per line.
 * @param {string} current
 * @param {string[]} texts
 */
export function withReturned(current, texts) {
  return [...texts, current].filter((t) => t !== '').join('\n');
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
 * says (the booleans, never a guess): `sending`, `unconfirmed`, `expired`
 * and `unreadable` for this view's own sends; then `read`, `delivered`,
 * `held` (the connection's `relay_held`, without `delivered`), `sent`.
 * `feed` is 5.4's hook: a `message.not_delivered` or
 * `message.delivery_unconfirmed` item for this message, when there is one.
 * `null` for an incoming message.
 * @param {{ direction: string, delivered: boolean, read: boolean, local?: { state: string } }} m
 * @param {{ relayHeld?: boolean, feed?: 'not_delivered' | 'not_confirmed' | null }} [opts]
 * @returns {null | 'sending' | 'unconfirmed' | 'expired' | 'unreadable' | 'not_delivered' | 'not_confirmed' | 'read' | 'delivered' | 'held' | 'sent'}
 */
export function deliveryState(m, opts = {}) {
  if (m.direction !== 'out') return null;
  const s = m.local?.state;
  if (s === 'sending' || s === 'unconfirmed' || s === 'expired' || s === 'unreadable') return s;
  if (m.read) return 'read';
  if (m.delivered) return 'delivered';
  if (opts.feed) return opts.feed;
  if (opts.relayHeld) return 'held';
  return 'sent';
}

/**
 * The line under an outgoing bubble for its state; '' when there is none
 * to show (5.4 brings the feed's texts). The notice of an unconfirmed,
 * expired or unreadable send is the backend's text.
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
      return opts.notice ?? '';
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

/** Trailing punctuation left off a link: it more often ends the sentence. */
const TRAIL = /[.,;:!?'")\]}>]+$/;

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
    const raw = m[0].replace(TRAIL, '');
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
 * Whether the compose box can be sent: 1 B to MAX_TEXT_BYTES, and not only
 * white space.
 * @param {string} text
 */
export function canSend(text) {
  const n = textBytes(text);
  return n >= 1 && n <= MAX_TEXT_BYTES && text.trim() !== '';
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
