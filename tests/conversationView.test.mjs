// The conversation view's rules (src/lib/conversationView.js, DESKTOP-REWORK-PLAN Phase 5, 5.3): merging
// pages and live messages, receipts, the send states, bubble text and links. Run with `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_TEXT_BYTES,
  RECEIPT_HOLD_MS,
  NO_ID_BOUND_MS,
  ATTACHMENT_PLACEHOLDER,
  EMPTY_MESSAGE,
  CHECKING_TEXT,
  NOT_FOUND_TEXT,
  compareMessages,
  mergeMessages,
  applySyncEvent,
  markedRead,
  nextToMark,
  newLocal,
  knownOutgoing,
  deadlineOf,
  seenInView,
  startRetry,
  applySendAnswer,
  applyRetryAnswer,
  dedupeLocals,
  expireDue,
  afterReload,
  placeReturned,
  unsentToDraft,
  pruneKept,
  knowsEvent,
  releaseHeld,
  viewMessages,
  deliveryState,
  deliveryText,
  cleanBubble,
  linkPieces,
  bubbleLines,
  bubbleContent,
  textBytes,
  canSend,
  takesMessages,
  conversationAction,
  openLinkQuestion,
  logoutWiped,
  returnedElsewhereText,
} from '../src/lib/conversationView.js';

const FSI = '\u2068';
const PDI = '\u2069';
const C = 'c1';

/** @returns {any} */
function msg(id, sent_at, extra = {}) {
  return { connection_id: C, message_id: id, direction: 'in', text: `t${id}`, sent_at, delivered: false, read: false, attachment: null, ...extra };
}

test('ordered by sent_at, then message_id', () => {
  const a = msg('B', '2026-11-25T10:00:00Z');
  const b = msg('A', '2026-11-25T10:00:00Z');
  const c = msg('C', '2026-11-25T09:00:00Z');
  assert.deepEqual([a, b, c].sort(compareMessages).map((m) => m.message_id), ['C', 'A', 'B']);
});

test('pages and live messages merge by message_id, without duplicates, in order', () => {
  const page1 = [msg('2', '2026-11-25T10:02:00Z'), msg('3', '2026-11-25T10:03:00Z')];
  const older = [msg('1', '2026-11-25T10:01:00Z'), msg('2', '2026-11-25T10:02:00Z')];
  const live = [msg('4', '2026-11-25T10:04:00Z'), msg('3', '2026-11-25T10:03:00Z', { delivered: true })];
  const out = mergeMessages(mergeMessages(page1, older, C), live, C);
  assert.deepEqual(out.map((m) => m.message_id), ['1', '2', '3', '4']);
  assert.equal(out[2].delivered, true);
});

test('merging never takes a receipt back, and leaves other connections out', () => {
  const have = [msg('1', '2026-11-25T10:01:00Z', { delivered: true, read: true })];
  const out = mergeMessages(have, [msg('1', '2026-11-25T10:01:00Z'), { ...msg('9', '2026-11-25T10:09:00Z'), connection_id: 'other' }], C);
  assert.equal(out.length, 1);
  assert.equal(out[0].read, true);
  assert.equal(out[0].delivered, true);
});

test('receipts: delivered, then read (read also means delivered)', () => {
  const ms = [msg('1', 'x', { direction: 'out' }), msg('2', 'y', { direction: 'out' })];
  const d = applySyncEvent(ms, { kind: 'message.receipt', members: { connection_id: C, message_id: '1', receipt: 'delivered' } }, C);
  assert.equal(d[0].delivered, true);
  assert.equal(d[0].read, false);
  const r = applySyncEvent(ms, { kind: 'message.receipt', members: { connection_id: C, message_id: '2', receipt: 'read' } }, C);
  assert.equal(r[1].read, true);
  assert.equal(r[1].delivered, true);
  // Another connection's, an unknown receipt, or another kind: nothing.
  assert.equal(applySyncEvent(ms, { kind: 'message.receipt', members: { connection_id: 'x', message_id: '1', receipt: 'read' } }, C), ms);
  assert.equal(applySyncEvent(ms, { kind: 'message.receipt', members: { connection_id: C, message_id: '1', receipt: 'seen' } }, C), ms);
  assert.equal(applySyncEvent(ms, { kind: 'connection.changed', members: { connection_id: C, message_id: '1' } }, C), ms);
});

test('message.read from another device, and the attachment state', () => {
  const att = { att_id: 'a', kind: 'photo', state: 'fetching', size: 1, width: 1, height: 1 };
  const ms = [msg('1', 'x'), msg('2', 'y', { attachment: att })];
  assert.equal(applySyncEvent(ms, { kind: 'message.read', members: { connection_id: C, message_id: '1' } }, C)[0].read, true);
  const a = applySyncEvent(ms, { kind: 'message.attachment', members: { connection_id: C, message_id: '2', state: 'failed', reason: 'full' } }, C);
  assert.equal(a[1].attachment.state, 'failed');
  assert.equal(a[1].attachment.reason, 'full');
  // A message without an attachment is left as it is.
  const b = applySyncEvent(ms, { kind: 'message.attachment', members: { connection_id: C, message_id: '1', state: 'stored' } }, C);
  assert.equal(b[0].attachment, null);
});

test('marking read: only seen messages, oldest incoming unread first, each tried once, outgoing never', () => {
  const ms = [msg('1', 'a', { read: true }), msg('2', 'b', { direction: 'out' }), msg('3', 'c'), msg('4', 'd')];
  const tried = new Set();
  // Nothing seen: nothing marked, though 3 and 4 are loaded.
  assert.equal(nextToMark(ms, tried, new Set()), null);
  const seen = new Set(['2', '4']);
  assert.equal(nextToMark(ms, tried, seen), '4');
  seen.add('3');
  assert.equal(nextToMark(ms, tried, seen), '3');
  tried.add('3');
  assert.equal(nextToMark(ms, tried, seen), '4');
  assert.equal(markedRead(ms, '4')[3].read, true);
  assert.equal(markedRead(ms, '2')[1].read, false);
  tried.add('4');
  assert.equal(nextToMark(ms, tried, seen), null);
});

const SENT = { message_id: 'M1', sent_at: '2026-11-25T10:00:00Z' };
const EXP = '2026-11-25T10:07:00Z';

/** @returns {any} */
function unconf(text, at, pid, extra = {}) {
  return { ...newLocal(C, text, at), state: 'unconfirmed', everUnconfirmed: true, pending_id: pid, expires_at: Date.parse(EXP), notice: 'old', ...extra };
}

test('a send answered {message_id, sent_at} is sent', () => {
  const l = newLocal(C, 'hi', 1000);
  assert.equal(l.state, 'sending');
  const r = applySendAnswer([l], l.key, { success: true, data: SENT }, 2000);
  assert.equal(r.locals[0].state, 'sent');
  assert.equal(r.locals[0].message_id, 'M1');
  assert.deepEqual(r.returned, []);
  assert.equal(r.refresh, false);
});

test('L1: success without a usable {message_id, sent_at} is read again, never a draft', () => {
  for (const data of [{}, { message_id: '', sent_at: SENT.sent_at }, { message_id: 'M', sent_at: '' }, { message_id: 'M', sent_at: 'not a time' }, undefined]) {
    const l = newLocal(C, 'hi', 1000);
    const r = applySendAnswer([l], l.key, { success: true, data }, 2000);
    assert.equal(r.locals.length, 1, JSON.stringify(data));
    assert.equal(r.locals[0].state, 'unreadable', JSON.stringify(data));
    assert.equal(r.locals[0].message_id, undefined);
    assert.deepEqual(r.returned, []);
    assert.equal(r.refresh, true);
  }
});

test('a first try that never got a pending_id goes back to the member, with the error', () => {
  for (const code of ['not_sent', 'bad_argument', 'no_session', 'locked', 'held', 'earlier_unconfirmed', 'forbidden', 'vault_error']) {
    const l = newLocal(C, 'draft me', 1000);
    const r = applySendAnswer([l], l.key, { success: false, error: `E ${code}`, error_code: code }, 2000);
    assert.equal(r.locals.length, 0, code);
    assert.deepEqual(r.returned, [{ connection_id: C, text: 'draft me', error: `E ${code}` }], code);
  }
});

test('a kept answer (any code, clock included) is unconfirmed until expires_at', () => {
  for (const code of ['unconfirmed', 'clock']) {
    const l = newLocal(C, 'maybe', 1000);
    const r = applySendAnswer([l], l.key, { success: false, error: 'not yet', error_code: code, data: { pending_id: 'P1', expires_at: EXP } }, 2000);
    assert.deepEqual(r.returned, [], code);
    assert.equal(r.locals[0].state, 'unconfirmed', code);
    assert.equal(r.locals[0].pending_id, 'P1');
    assert.equal(r.locals[0].expires_at, Date.parse(EXP));
    assert.equal(r.locals[0].everUnconfirmed, true);
    assert.equal(r.locals[0].notice, 'not yet');
  }
});

test('M2: unconfirmed without an id, or no answer at all, stays unconfirmed and never returns on its own', () => {
  const l = newLocal(C, 'maybe', 1000);
  const r = applySendAnswer([l], l.key, { success: false, error: 'not yet', error_code: 'unconfirmed' }, 2000);
  assert.equal(r.locals[0].state, 'unconfirmed');
  assert.equal(r.locals[0].everUnconfirmed, true);
  assert.deepEqual(r.returned, []);
  const l2 = newLocal(C, 'maybe', 1000);
  const r2 = applySendAnswer([l2], l2.key, null, 2000);
  assert.equal(r2.locals[0].state, 'unconfirmed');
  assert.equal(r2.locals[0].pending_id, undefined);
  // It can't be tried again by id.
  assert.equal(startRetry(r2.locals, l2.key)[0].state, 'unconfirmed');
  // Once unconfirmed, a later answer about it (not_sent, say) doesn't make it a draft.
  const again = applyRetryAnswer(r.locals, l.key, { success: false, error: 'x', error_code: 'not_sent' }, 3000);
  assert.equal(again.locals[0].state, 'unconfirmed');
  assert.deepEqual(again.returned, []);
  // Even an answer taken as its first try's leaves it unconfirmed.
  const firstAgain = applySendAnswer(r2.locals, l2.key, { success: false, error: 'x', error_code: 'not_sent' }, 3000);
  assert.equal(firstAgain.locals[0].state, 'unconfirmed');
  assert.deepEqual(firstAgain.returned, []);
  // Without an expires_at it is bounded by NO_ID_BOUND_MS (the L1 test).
  assert.equal(expireDue(r2.locals, 1000 + NO_ID_BOUND_MS - 1).changed, false);
});

test('retry_send: settled done is sent, not_done goes back, expired and unreadable read again', () => {
  const u = unconf('same', 1000, 'P1');
  const s = startRetry([u], u.key);
  assert.equal(s[0].state, 'sending');
  assert.equal(s[0].retry, true);
  const done = applyRetryAnswer(s, u.key, { success: true, data: { ...SENT, pending_id: 'P1', settled: 'done' } }, 2000);
  assert.equal(done.locals[0].state, 'sent');
  assert.equal(done.locals[0].pending_id, undefined);
  assert.equal(done.locals[0].retry, undefined);
  const nd = applyRetryAnswer(s, u.key, { success: false, error: 'refused', error_code: 'forbidden', data: { pending_id: 'P1', settled: 'not_done', vault_code: 'forbidden' } }, 2000);
  assert.equal(nd.locals.length, 0);
  assert.deepEqual(nd.returned, [{ connection_id: C, text: 'same', error: 'refused' }]);
  const ex = applyRetryAnswer(s, u.key, { success: false, error: 'late', error_code: 'unconfirmed_expired', data: { pending_id: 'P1' } }, 5000);
  assert.equal(ex.locals[0].state, 'expired');
  assert.equal(ex.locals[0].since, 5000);
  assert.equal(ex.refresh, true);
  const un = applyRetryAnswer(s, u.key, { success: false, error: 'unread', error_code: 'answer_unreadable', data: { pending_id: 'P1', settled: 'done' } }, 5000);
  assert.equal(un.locals[0].state, 'unreadable');
  assert.equal(un.refresh, true);
});

test('a pending_id message stays unconfirmed on every other answer, retry or earlier', () => {
  for (const code of ['no_session', 'locked', 'held', 'not_sent', 'clock', 'earlier_unconfirmed', 'unconfirmed', 'bad_argument']) {
    const u = unconf('same', 1000, 'P1');
    const r = applyRetryAnswer(startRetry([u], u.key), u.key, { success: false, error: `N ${code}`, error_code: code }, 2000);
    assert.deepEqual(r.returned, [], code);
    assert.equal(r.locals[0].state, 'unconfirmed', code);
    assert.equal(r.locals[0].pending_id, 'P1', code);
    assert.equal(r.locals[0].notice, `N ${code}`, code);
    assert.equal(r.locals[0].retry, undefined, code);
  }
  // The call itself failed: still unconfirmed, with its id.
  const u = unconf('same', 1000, 'P1');
  assert.equal(applyRetryAnswer(startRetry([u], u.key), u.key, null, 2000).locals[0].pending_id, 'P1');
});

test('a new pending_id is a new request: its time starts then; the same id keeps it', () => {
  const u = unconf('same', 1000, 'P1');
  const same = applyRetryAnswer([u], u.key, { success: false, error_code: 'unconfirmed', data: { pending_id: 'P1', expires_at: EXP } }, 9000);
  assert.equal(same.locals[0].at, 1000);
  const fresh = applyRetryAnswer([u], u.key, { success: false, error_code: 'unconfirmed', data: { pending_id: 'P2', expires_at: EXP } }, 9000);
  assert.equal(fresh.locals[0].at, 9000);
  assert.equal(fresh.locals[0].pending_id, 'P2');
  // A first send's id keeps its creation time.
  const l = newLocal(C, 'x', 1000);
  assert.equal(applySendAnswer([l], l.key, { success: false, error_code: 'unconfirmed', data: { pending_id: 'P3', expires_at: EXP } }, 9000).locals[0].at, 1000);
});

test('earlier settles the unconfirmed message it names by pending_id', () => {
  const u = unconf('first', 1000, 'P1');
  const l = newLocal(C, 'second', 2000);
  const r = applySendAnswer([u, l], l.key, {
    success: true,
    data: { message_id: 'M2', sent_at: '2026-11-25T10:02:00Z', earlier: { pending_id: 'P1', expires_at: EXP, connection_id: C, success: true, settled: 'done', data: SENT } },
  }, 3000);
  assert.deepEqual(r.locals.map((x) => [x.state, x.message_id]), [['sent', 'M1'], ['sent', 'M2']]);
  assert.equal(r.refresh, false);
});

test('earlier not_done goes back; with the new send also back, only one fills the box', () => {
  const u = unconf('first', 1000, 'P1');
  const l = newLocal(C, 'second', 2000);
  const r = applySendAnswer([u, l], l.key, {
    success: false,
    error: 'not sent',
    error_code: 'not_sent',
    data: { earlier: { pending_id: 'P1', connection_id: C, success: false, settled: 'not_done', vault_code: 'vault_error', error: 'refused', error_code: 'vault_error' } },
  }, 3000);
  assert.equal(r.locals.length, 0);
  assert.deepEqual(r.returned.map((x) => x.text), ['first', 'second']);
  const p = placeReturned(r.locals, { [C]: '' }, r.returned, 4000);
  assert.equal(p.drafts[C], 'first');
  assert.equal(p.errors[C], 'refused');
  assert.equal(p.locals.length, 1);
  assert.equal(p.locals[0].state, 'unsent');
  assert.equal(p.locals[0].text, 'second');
  assert.equal(p.locals[0].notice, 'not sent');
});

test('placeReturned never joins texts: a box with text keeps it, the returned text is a bubble', () => {
  const p = placeReturned([], { [C]: 'typing' }, [{ connection_id: C, text: 'back', error: 'E' }], 1);
  assert.equal(p.drafts[C], 'typing');
  assert.equal(p.locals[0].text, 'back');
  assert.equal(p.locals[0].state, 'unsent');
  assert.deepEqual(p.errors, {});
  // Another connection's box.
  const q = placeReturned([], { [C]: 'typing' }, [{ connection_id: 'c2', text: 'other', error: 'E' }], 1);
  assert.equal(q.drafts.c2, 'other');
});

test('earlier still unconfirmed stays so; the new send that wasn’t sent goes back', () => {
  const u = unconf('first', 1000, 'P1');
  const l = newLocal(C, 'second', 2000);
  const r = applySendAnswer([u, l], l.key, {
    success: false,
    error: 'previous not confirmed',
    error_code: 'earlier_unconfirmed',
    data: { earlier: { pending_id: 'P1', expires_at: EXP, connection_id: C, success: false, error: 'still', error_code: 'unconfirmed' } },
  }, 3000);
  assert.equal(r.locals.length, 1);
  assert.equal(r.locals[0].state, 'unconfirmed');
  assert.equal(r.locals[0].notice, 'still');
  assert.deepEqual(r.returned, [{ connection_id: C, text: 'second', error: 'previous not confirmed' }]);
});

test('earlier never matches the send it came with, even with the same pending_id', () => {
  const l = { ...newLocal(C, 'mine', 1000), pending_id: 'P1' };
  const r = applySendAnswer([l], l.key, {
    success: true,
    data: { ...SENT, earlier: { pending_id: 'P1', success: false, settled: 'not_done', error: 'E', error_code: 'vault_error' } },
  }, 2000);
  assert.equal(r.locals.length, 1);
  assert.equal(r.locals[0].state, 'sent');
  assert.deepEqual(r.returned, []);
});

test('earlier expired asks for a read; one the view lacks asks only when it settled or expired', () => {
  const u = unconf('first', 1000, 'P1');
  const l = newLocal(C, 'second', 2000);
  const ex = applySendAnswer([u, l], l.key, { success: true, data: { ...SENT, earlier: { pending_id: 'P1', success: false, error: 'late', error_code: 'unconfirmed_expired' } } }, 3000);
  assert.equal(ex.locals[0].state, 'expired');
  assert.equal(ex.refresh, true);
  const lost = applySendAnswer([l], l.key, { success: true, data: { ...SENT, earlier: { pending_id: 'P9', success: true, settled: 'done', data: SENT } } }, 3000);
  assert.equal(lost.refresh, true);
  const quiet = applySendAnswer([l], l.key, { success: true, data: { message_id: 'M3', sent_at: SENT.sent_at, earlier: { pending_id: 'P9', success: false, error_code: 'unconfirmed' } } }, 3000);
  assert.equal(quiet.refresh, false);
});

test('the same text twice is two messages', () => {
  const u = unconf('same', 1000, 'P1');
  const l = newLocal(C, 'same', 2000);
  const r = applySendAnswer([u, l], l.key, { success: true, data: SENT }, 3000);
  assert.equal(r.locals.length, 2);
  assert.equal(r.locals[0].state, 'unconfirmed');
  assert.equal(r.locals[1].state, 'sent');
});

test('L2: locals are one per message_id and per pending_id', () => {
  const a = { ...newLocal(C, 'a', 1), state: 'sent', message_id: 'M1', sent_at: 'x' };
  const b = { ...newLocal(C, 'a', 2), state: 'sent', message_id: 'M1', sent_at: 'x' };
  const c = unconf('c', 3, 'P1');
  const d = unconf('c', 4, 'P1');
  assert.deepEqual(dedupeLocals([a, b, c, d]).map((l) => l.key), [a.key, c.key]);
  // A retry that comes back sent with a message_id another local has is merged away.
  const r = applyRetryAnswer([a, c], c.key, { success: true, data: { ...SENT, settled: 'done' } }, 5);
  assert.equal(r.locals.length, 1);
});

test('only unconfirmed sends past expires_at expire; a send in flight never does', () => {
  const u = unconf('old', 0, 'P1');
  assert.equal(expireDue([u], Date.parse(EXP) - 1).changed, false);
  const e = expireDue([u], Date.parse(EXP));
  assert.equal(e.changed, true);
  assert.equal(e.locals[0].state, 'expired');
  assert.equal(e.locals[0].notice, CHECKING_TEXT);
  const inFlight = startRetry([u], u.key);
  assert.equal(expireDue(inFlight, 1e15).changed, false);
  assert.equal(expireDue([newLocal(C, 'x', 0)], 1e15).changed, false);
});

// What the view had when a send began: an earlier "ok" (A), sent by the vault at 10:00:00.
const KNOWN_PAGE = [msg('A', '2026-11-25T10:00:00Z', { direction: 'out', text: 'ok' }), msg('B', '2026-11-25T10:00:30Z', { direction: 'in', text: 'hi' })];

/** An expired send of `text` begun at `at` by this computer's clock, knowing `page`. */
function expiredSend(text, at, page = KNOWN_PAGE) {
  return { ...unconf(text, at, 'P1'), known: knownOutgoing(page, [], C), state: 'expired', since: at + 10 };
}

test('M-A: what was known is recorded in the vault’s terms: outgoing ids and the newest outgoing sent_at', () => {
  const sent = { ...newLocal(C, 'x', 0), state: 'sent', message_id: 'L1', sent_at: '2026-11-25T10:01:00Z' };
  const k = knownOutgoing(KNOWN_PAGE, [sent, { ...sent, connection_id: 'c2', message_id: 'Z' }], C);
  assert.deepEqual(k.ids, ['A', 'L1']);
  assert.equal(k.newest, '2026-11-25T10:01:00Z');
  assert.deepEqual(knownOutgoing([], [], C), { ids: [], newest: null });
  assert.deepEqual(newLocal(C, 't', 0, k).known, k);
});

for (const [skew, at] of [
  ['this computer behind the vault', Date.parse('2026-11-25T09:50:00Z')],
  ['this computer ahead of the vault', Date.parse('2026-11-25T10:20:00Z')],
]) {
  test(`M-A, ${skew}: a send that went is found by what wasn’t known, whatever this clock says`, () => {
    const e = expiredSend('ok', at);
    const page = [...KNOWN_PAGE, msg('C', '2026-11-25T10:01:00Z', { direction: 'out', text: 'ok' })];
    const r = afterReload([e], C, page, at + 20);
    assert.equal(r.locals.length, 0);
  });

  test(`M-A, ${skew}: a send that didn’t go isn’t matched to an earlier same text; it stays as unsent`, () => {
    const e = expiredSend('ok', at);
    const r = afterReload([e], C, KNOWN_PAGE, at + 20);
    assert.equal(r.locals.length, 1);
    assert.equal(r.locals[0].state, 'unsent');
    assert.equal(r.locals[0].notice, NOT_FOUND_TEXT);
  });
}

test('M-A: a same-text message older than the newest known one (further back than was read) is not it', () => {
  const at = 1000;
  const e = expiredSend('ok', at);
  // "Load older" since brought in an "ok" from before the newest known outgoing message.
  const page = [msg('O', '2026-11-25T09:00:00Z', { direction: 'out', text: 'ok' }), ...KNOWN_PAGE];
  assert.equal(afterReload([e], C, page, at + 20).locals[0].state, 'unsent');
});

test('M-A: a send that began with nothing known matches nothing', () => {
  const e = { ...unconf('ok', 1000, 'P1'), state: 'expired', since: 1010 };
  const page = [msg('C', '2026-11-25T10:01:00Z', { direction: 'out', text: 'ok' })];
  assert.equal(afterReload([e], C, page, 1020).locals[0].state, 'unsent');
  // A conversation that had no outgoing message yet: any new one is not known.
  const e2 = expiredSend('ok', 1000, []);
  assert.equal(afterReload([e2], C, page, 1020).locals.length, 0);
});

test('M1: an expired send the page doesn’t show is kept on its bubble as unsent, never put in the box', () => {
  const e = expiredSend('hello', 1000);
  // Another text, or an incoming one with the same text: not it.
  const page = [
    ...KNOWN_PAGE,
    msg('8', '2026-11-25T10:01:05Z', { direction: 'out', text: 'other' }),
    msg('9', '2026-11-25T10:01:06Z', { direction: 'in', text: 'hello' }),
  ];
  const r = afterReload([e], C, page, 1020);
  assert.equal(r.locals.length, 1);
  assert.equal(r.locals[0].state, 'unsent');
  // Its "Edit" puts it in an empty box only.
  assert.equal(unsentToDraft(r.locals, { [C]: 'typing' }, r.locals[0].key), null);
  const d = unsentToDraft(r.locals, { [C]: '' }, r.locals[0].key);
  assert.equal(d?.drafts[C], 'hello');
  assert.equal(d?.locals.length, 0);
});

test('M1: two expired sends of the same text need two new page messages', () => {
  const e1 = expiredSend('ok', 1000);
  const e2 = { ...expiredSend('ok', 1001), pending_id: 'P2' };
  const page = [...KNOWN_PAGE, msg('C', '2026-11-25T10:01:00Z', { direction: 'out', text: 'ok' })];
  const r = afterReload([e1, e2], C, page, 1020);
  assert.deepEqual(r.locals.map((l) => l.state), ['unsent']);
});

test('M2: an unconfirmed send without an id goes once a read shows it, and stays otherwise', () => {
  const at = 1000;
  const u = { ...newLocal(C, 'ok', at, knownOutgoing(KNOWN_PAGE, [], C)), state: 'unconfirmed', everUnconfirmed: true };
  const shown = afterReload([u], C, [...KNOWN_PAGE, msg('C', '2026-11-25T10:01:00Z', { direction: 'out', text: 'ok' })], at + 5);
  assert.equal(shown.locals.length, 0);
  // Only the "ok" it knew: not found, still unconfirmed.
  const not = afterReload([u], C, KNOWN_PAGE, at + 5);
  assert.equal(not.locals[0].state, 'unconfirmed');
  // One with a pending_id waits for its own answers.
  const p = { ...unconf('ok', at, 'P1'), known: knownOutgoing(KNOWN_PAGE, [], C) };
  assert.equal(afterReload([p], C, [...KNOWN_PAGE, msg('C', '2026-11-25T10:01:00Z', { direction: 'out', text: 'ok' })], at + 5).locals.length, 1);
});

test('L1: a send without expires_at expires at at + NO_ID_BOUND_MS, later than any backend window', () => {
  assert.equal(NO_ID_BOUND_MS, 10 * 60_000);
  assert.ok(NO_ID_BOUND_MS > (2 + 5) * 60_000);
  const u = { ...newLocal(C, 'ok', 1000), state: 'unconfirmed', everUnconfirmed: true };
  assert.equal(deadlineOf(u), 1000 + NO_ID_BOUND_MS);
  assert.equal(deadlineOf({ ...u, expires_at: 5000 }), 5000);
  assert.equal(expireDue([u], 1000 + NO_ID_BOUND_MS - 1).changed, false);
  const e = expireDue([u], 1000 + NO_ID_BOUND_MS);
  assert.equal(e.changed, true);
  assert.equal(e.locals[0].state, 'expired');
  // Then a read that doesn't show it makes it unsent (Edit, Remove).
  const r = afterReload(e.locals, C, [], 1000 + NO_ID_BOUND_MS + 1);
  assert.equal(r.locals[0].state, 'unsent');
});

test('L2: seen at 60% of the bubble, or 60% of the view for a tall one', () => {
  const view = { height: 500 };
  assert.equal(seenInView({ isIntersecting: false, intersectionRatio: 0, intersectionRect: { height: 0 }, rootBounds: view }), false);
  // Not intersecting is never seen, whatever else the entry says (an edge entry at threshold 0).
  assert.equal(seenInView({ isIntersecting: false, intersectionRatio: 0.6, intersectionRect: { height: 400 }, rootBounds: view }), false);
  assert.equal(seenInView({ isIntersecting: true, intersectionRatio: 0.59, intersectionRect: { height: 59 }, rootBounds: view }), false);
  assert.equal(seenInView({ isIntersecting: true, intersectionRatio: 0.6, intersectionRect: { height: 60 }, rootBounds: view }), true);
  // A bubble three times the view's height can't reach 60% of itself.
  assert.equal(seenInView({ isIntersecting: true, intersectionRatio: 0.33, intersectionRect: { height: 500 }, rootBounds: view }), true);
  assert.equal(seenInView({ isIntersecting: true, intersectionRatio: 0.19, intersectionRect: { height: 299 }, rootBounds: view }), false);
  assert.equal(seenInView({ isIntersecting: true, intersectionRatio: 0.2, intersectionRect: { height: 300 }, rootBounds: view }), true);
  assert.equal(seenInView({ isIntersecting: true, intersectionRatio: 0.3, intersectionRect: { height: 300 }, rootBounds: null }), false);
});

test('after a read: unreadable sends go (they were done), sent ones go once the page has them; L5 recheck', () => {
  const un = { ...newLocal(C, 'done', 0), state: 'unreadable', since: 10 };
  const s1 = { ...newLocal(C, 'a', 0), state: 'sent', message_id: 'M1', sent_at: 'x' };
  const s2 = { ...newLocal(C, 'b', 0), state: 'sent', message_id: 'M2', sent_at: 'y' };
  const other = { ...newLocal('c2', 'z', 0), state: 'unreadable', since: 10 };
  const r = afterReload([un, s1, s2, other], C, [msg('M1', 'x', { direction: 'out' })], 20);
  assert.deepEqual(r.locals.map((l) => l.text), ['b', 'z']);
  assert.equal(r.recheck, false);
  // One that began after the read started is read about again.
  const late = { ...newLocal(C, 'late', 0), state: 'expired', since: 30 };
  const r2 = afterReload([late], C, [], 20);
  assert.equal(r2.locals[0].state, 'expired');
  assert.equal(r2.recheck, true);
});

test('L3: sends and drafts of connections no longer listed are dropped', () => {
  const p = pruneKept([newLocal(C, 'a', 1), newLocal('gone', 'b', 1)], { [C]: 'x', gone: 'y' }, new Set([C]));
  assert.deepEqual(p.locals.map((l) => l.connection_id), [C]);
  assert.deepEqual(p.drafts, { [C]: 'x' });
});

test('L6: a receipt for a message not known yet is held, then applied once it is', () => {
  const ev = { kind: 'message.receipt', members: { connection_id: C, message_id: 'M1', receipt: 'delivered' } };
  const l = newLocal(C, 'hi', 0);
  assert.equal(knowsEvent([], [l], ev, C), false);
  // Other kinds and other connections have nothing to hold.
  assert.equal(knowsEvent([], [], { kind: 'connection.changed', members: {} }, C), true);
  assert.equal(knowsEvent([], [], { ...ev, members: { ...ev.members, connection_id: 'c2' } }, C), true);
  let held = [{ ev, at: 1000 }];
  const sent = applySendAnswer([l], l.key, { success: true, data: SENT }, 1500).locals;
  assert.equal(knowsEvent([], sent, ev, C), true);
  const rel = releaseHeld(held, (e) => knowsEvent([], sent, e, C), 2000);
  assert.equal(rel.ready.length, 1);
  assert.equal(rel.held.length, 0);
  const after = applySyncEvent(sent, rel.ready[0], C);
  assert.equal(after[0].delivered, true);
  // Not known yet: still held; too old: dropped.
  assert.equal(releaseHeld(held, () => false, 2000).held.length, 1);
  assert.equal(releaseHeld(held, () => true, 1000 + RECEIPT_HOLD_MS + 1).ready.length, 0);
});

test('the view list: own sent messages by sent_at, pending sends last, no duplicate once a page has one', () => {
  const ms = [msg('1', '2026-11-25T10:01:00Z'), msg('3', '2026-11-25T10:03:00Z')];
  const sent = { ...newLocal(C, 'mine', 0), state: 'sent', message_id: '2', sent_at: '2026-11-25T10:02:00Z' };
  const pend = { ...newLocal(C, 'pending', 5), state: 'unconfirmed', pending_id: 'P' };
  const v = viewMessages(ms, [pend, sent], C);
  assert.deepEqual(v.map((m) => m.text), ['t1', 'mine', 't3', 'pending']);
  const dup = viewMessages([...ms, msg('2', '2026-11-25T10:02:00Z', { direction: 'out' })], [sent], C);
  assert.equal(dup.filter((m) => m.message_id === '2').length, 1);
});

test('delivery state as the booleans say, never a guess', () => {
  assert.equal(deliveryState({ direction: 'in', delivered: true, read: true }), null);
  assert.equal(deliveryState({ direction: 'out', delivered: false, read: false }), 'sent');
  assert.equal(deliveryState({ direction: 'out', delivered: true, read: false }), 'delivered');
  assert.equal(deliveryState({ direction: 'out', delivered: true, read: true }), 'read');
  assert.equal(deliveryState({ direction: 'out', delivered: false, read: false }, { relayHeld: true }), 'held');
  assert.equal(deliveryState({ direction: 'out', delivered: true, read: false }, { relayHeld: true }), 'delivered');
  assert.equal(deliveryState({ direction: 'out', delivered: false, read: false, local: { state: 'unconfirmed' } }), 'unconfirmed');
  assert.equal(deliveryState({ direction: 'out', delivered: false, read: false, local: { state: 'sending' } }), 'sending');
  // 5.4's hook.
  assert.equal(deliveryState({ direction: 'out', delivered: false, read: false }, { feed: 'not_delivered' }), 'not_delivered');
});

test('delivery text: the plan’s words, the relay_held line, and the backend’s notice', () => {
  assert.equal(deliveryText('delivered'), 'Delivered');
  assert.equal(deliveryText('held', { title: 'Ada King' }), `Waiting to reach ${FSI}Ada King${PDI} at their vault's new address.`);
  assert.equal(deliveryText('unconfirmed', { notice: 'N' }), 'N');
  assert.equal(deliveryText('expired', { notice: 'E' }), 'E');
  assert.equal(deliveryText(null), '');
  assert.equal(deliveryText('unsent'), NOT_FOUND_TEXT);
  assert.equal(deliveryText('expired'), CHECKING_TEXT);
  assert.equal(deliveryState({ direction: 'out', delivered: false, read: false, local: { state: 'unsent' } }), 'unsent');
});

test('§10.8 bubble cleaning: lines kept, directional marks kept, other controls go, ends trimmed', () => {
  assert.equal(cleanBubble('  a\r\nb\rc\u2028d\te  '), 'a\nb\nc\nd e');
  assert.equal(cleanBubble('\u200Fمرحبا\u200E x\u061C'), '\u200Fمرحبا\u200E x\u061C');
  assert.equal(cleanBubble('a\u202Eb\u2066c\u200Bd\u{E0041}e'), 'abcde');
  assert.equal(cleanBubble('a\u200Db\u200Cc'), 'a\u200Db\u200Cc');
  assert.equal(cleanBubble('x\uD800y'), 'x\uFFFDy');
  // Indentation inside the text stays; only the whole text's ends are trimmed.
  assert.equal(cleanBubble('\n  line1\n    line2\n'), 'line1\n    line2');
  assert.equal(cleanBubble(undefined), '');
});

test('§10.5 links: only https:// is a link, with its host; other schemes are text', () => {
  assert.deepEqual(linkPieces('see https://example.com/a?b=1.'), [
    { text: 'see ' },
    { text: 'https://example.com/a?b=1', href: 'https://example.com/a?b=1', host: 'example.com' },
    { text: '.' },
  ]);
  // A balanced closing bracket stays; one the URL doesn't open goes.
  assert.equal(/** @type {any} */ (linkPieces('https://en.wikipedia.org/wiki/Tor_(network)')[0]).href, 'https://en.wikipedia.org/wiki/Tor_(network)');
  assert.deepEqual(linkPieces('(see https://example.com/a)').map((p) => p.text), ['(see ', 'https://example.com/a', ')']);
  assert.equal(/** @type {any} */ (linkPieces('https://x.example/f(a)).')[0]).text, 'https://x.example/f(a)');
  for (const t of ['http://example.com', 'someapp://x', 'javascript:alert(1)', 'www.example.com', 'ftp://x']) {
    assert.deepEqual(linkPieces(t), [{ text: t }], t);
  }
  // The host is the URL's own: user info is not the host, IDN shows as punycode.
  assert.equal(/** @type {any} */ (linkPieces('https://good.com@evil.example/')[0]).host, 'evil.example');
  assert.equal(/** @type {any} */ (linkPieces('https://bücher.example/')[0]).host, 'xn--bcher-kva.example');
});

test('bubble lines and content: attachment placeholder, caption under it, never an empty bubble', () => {
  assert.deepEqual(bubbleLines('a\nb'), { empty: false, lines: [[{ text: 'a' }], [{ text: 'b' }]] });
  assert.equal(bubbleLines('\u200B \u2800').empty, true);
  const att = { att_id: 'a', kind: 'photo', state: 'stored' };
  assert.deepEqual(bubbleContent({ text: '', attachment: att }), { placeholder: ATTACHMENT_PLACEHOLDER, body: null });
  const cap = bubbleContent({ text: 'caption', attachment: att });
  assert.equal(cap.placeholder, ATTACHMENT_PLACEHOLDER);
  assert.deepEqual(cap.body?.lines, [[{ text: 'caption' }]]);
  const empty = bubbleContent({ text: '\u200B', attachment: null });
  assert.equal(empty.placeholder, null);
  assert.equal(empty.body?.empty, true);
  assert.equal(EMPTY_MESSAGE, 'Empty message');
});

test('the placeholder text, word for word', () => {
  assert.equal(ATTACHMENT_PLACEHOLDER, 'Attachment: open it on your phone.');
});

test('the compose box counts UTF-8 bytes, 1 B to 16 KiB', () => {
  assert.equal(MAX_TEXT_BYTES, 16384);
  assert.equal(textBytes('é'), 2);
  assert.equal(textBytes('😀'), 4);
  assert.equal(canSend(''), false);
  assert.equal(canSend('   '), false);
  // Empty by §10.8 step 4: zero-width and blank code points only.
  assert.equal(canSend(String.fromCharCode(0x200b, 0x2800, 0x3164)), false);
  assert.equal(canSend('a'), true);
  assert.equal(canSend('a'.repeat(16384)), true);
  assert.equal(canSend('a'.repeat(16385)), false);
  assert.equal(canSend('é'.repeat(8192)), true);
  assert.equal(canSend('é'.repeat(8193)), false);
});

test('a service connection takes no messages', () => {
  assert.equal(takesMessages({ peer_kind: 'service' }), false);
  assert.equal(takesMessages({ peer_kind: 'member' }), true);
  assert.equal(takesMessages({}), true);
});

test('inbound batches: dropped while not live, a resync reads the newest page', () => {
  assert.equal(conversationAction({ resync: true }, false), 'drop');
  assert.equal(conversationAction({ resync: true }, true), 'reload');
  assert.equal(conversationAction({ resync: false }, true), 'apply');
  assert.equal(conversationAction(null, true), 'drop');
});

test('the link question names the host, isolated', () => {
  assert.equal(openLinkQuestion('example.com'), `Open this link in your browser? It goes to ${FSI}example.com${PDI}.`);
});

test('L3: kept sends and drafts go only when the log-out wiped this desktop', () => {
  assert.equal(logoutWiped({ revoke_sent: true, local_wiped: true }), true);
  assert.equal(logoutWiped({ revoke_sent: false, local_wiped: true }), true);
  assert.equal(logoutWiped({ revoke_sent: true, local_wiped: false }), false);
  assert.equal(logoutWiped({}), false);
  assert.equal(logoutWiped(null), false);
  assert.equal(logoutWiped(undefined), false);
});

test('L4: a text back in another conversation is said with its title, isolated', () => {
  assert.equal(returnedElsewhereText('Ada King'), `Your message to ${FSI}Ada King${PDI} wasn't sent. Its text is back in that conversation.`);
  assert.equal(returnedElsewhereText(''), "Your message to a connection wasn't sent. Its text is back in that conversation.");
});
