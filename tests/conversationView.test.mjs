// The conversation view's rules (src/lib/conversationView.js, DESKTOP-REWORK-PLAN Phase 5, 5.3): merging
// pages and live messages, receipts, the send states, bubble text and links. Run with `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_TEXT_BYTES,
  KEPT_FOR_MS,
  ATTACHMENT_PLACEHOLDER,
  EMPTY_MESSAGE,
  UNCONFIRMED_EXPIRED_TEXT,
  compareMessages,
  mergeMessages,
  applySyncEvent,
  markedRead,
  nextToMark,
  newLocal,
  sameUnconfirmed,
  applySendAnswer,
  retrying,
  expireStale,
  afterReload,
  withReturned,
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

test('marking read: oldest incoming unread first, each tried once, outgoing never', () => {
  const ms = [msg('1', 'a', { read: true }), msg('2', 'b', { direction: 'out' }), msg('3', 'c'), msg('4', 'd')];
  const tried = new Set();
  assert.equal(nextToMark(ms, tried), '3');
  tried.add('3');
  assert.equal(nextToMark(ms, tried), '4');
  const after = markedRead(ms, '4');
  assert.equal(after[3].read, true);
  assert.equal(markedRead(ms, '2')[1].read, false);
  tried.add('4');
  assert.equal(nextToMark(ms, tried), null);
});

test('a send answered {message_id, sent_at} is sent', () => {
  const l = newLocal(C, 'hi', 1000);
  assert.equal(l.state, 'sending');
  const r = applySendAnswer([l], l.key, { success: true, data: { message_id: 'M1', sent_at: '2026-11-25T10:00:00Z' } }, 2000);
  assert.equal(r.locals[0].state, 'sent');
  assert.equal(r.locals[0].message_id, 'M1');
  assert.equal(r.draft, null);
  assert.equal(r.refresh, false);
});

test('a first try that never got a pending_id keeps its text as the draft, with the error', () => {
  for (const code of ['not_sent', 'bad_argument', 'clock', 'no_session', 'locked', 'held', 'earlier_unconfirmed', 'forbidden', 'vault_error']) {
    const l = newLocal(C, 'draft me', 1000);
    const r = applySendAnswer([l], l.key, { success: false, error: `E ${code}`, error_code: code }, 2000);
    assert.equal(r.locals.length, 0, code);
    assert.equal(r.draft, 'draft me', code);
    assert.equal(r.error, `E ${code}`, code);
  }
});

test('unconfirmed with a pending_id: kept on the bubble, with the notice, never a draft', () => {
  const l = newLocal(C, 'maybe', 1000);
  const r = applySendAnswer([l], l.key, { success: false, error: 'not yet', error_code: 'unconfirmed', data: { pending_id: 'P1' } }, 2000);
  assert.equal(r.draft, null);
  assert.equal(r.locals[0].state, 'unconfirmed');
  assert.equal(r.locals[0].pending_id, 'P1');
  assert.equal(r.locals[0].notice, 'not yet');
  // Unconfirmed without an id is still unconfirmed.
  const l2 = newLocal(C, 'maybe', 1000);
  const r2 = applySendAnswer([l2], l2.key, { success: false, error: 'not yet', error_code: 'unconfirmed' }, 2000);
  assert.equal(r2.locals[0].state, 'unconfirmed');
  assert.equal(r2.draft, null);
  // No answer at all (the call failed): unconfirmed, never not sent.
  const l3 = newLocal(C, 'maybe', 1000);
  assert.equal(applySendAnswer([l3], l3.key, null, 2000).locals[0].state, 'unconfirmed');
});

test('a message holding a pending_id stays unconfirmed on every answer but success, expired, unreadable', () => {
  for (const code of ['no_session', 'locked', 'held', 'not_sent', 'clock', 'earlier_unconfirmed', 'unconfirmed', 'forbidden']) {
    const u = { ...newLocal(C, 'same', 1000), state: 'unconfirmed', pending_id: 'P1', notice: 'old' };
    const r = applySendAnswer(retrying([u], u.key), u.key, { success: false, error: `N ${code}`, error_code: code }, 2000);
    assert.equal(r.draft, null, code);
    assert.equal(r.locals[0].state, 'unconfirmed', code);
    assert.equal(r.locals[0].pending_id, 'P1', code);
    assert.equal(r.locals[0].notice, `N ${code}`, code);
  }
  const u = { ...newLocal(C, 'same', 1000), state: 'unconfirmed', pending_id: 'P1' };
  const ex = applySendAnswer([u], u.key, { success: false, error: 'late', error_code: 'unconfirmed_expired' }, 5000);
  assert.equal(ex.locals[0].state, 'expired');
  assert.equal(ex.locals[0].since, 5000);
  assert.equal(ex.refresh, true);
  const un = applySendAnswer([u], u.key, { success: false, error: 'unread', error_code: 'answer_unreadable' }, 5000);
  assert.equal(un.locals[0].state, 'unreadable');
  assert.equal(un.refresh, true);
  const ok = applySendAnswer([u], u.key, { success: true, data: { message_id: 'M', sent_at: '2026-11-25T10:00:00Z' } }, 5000);
  assert.equal(ok.locals[0].state, 'sent');
  assert.equal(ok.locals[0].pending_id, undefined);
});

test('earlier settles the unconfirmed message it names by pending_id', () => {
  const u = { ...newLocal(C, 'first', 1000), state: 'unconfirmed', pending_id: 'P1' };
  const l = newLocal(C, 'second', 2000);
  const r = applySendAnswer([u, l], l.key, {
    success: true,
    data: { message_id: 'M2', sent_at: '2026-11-25T10:02:00Z', earlier: { pending_id: 'P1', connection_id: C, success: true, data: { message_id: 'M1', sent_at: '2026-11-25T10:01:00Z' } } },
  }, 3000);
  assert.deepEqual(r.locals.map((x) => [x.state, x.message_id]), [['sent', 'M1'], ['sent', 'M2']]);
  assert.equal(r.refresh, false);
});

test('earlier still unconfirmed: it stays so; the new send that wasn’t sent is the draft', () => {
  const u = { ...newLocal(C, 'first', 1000), state: 'unconfirmed', pending_id: 'P1' };
  const l = newLocal(C, 'second', 2000);
  const r = applySendAnswer([u, l], l.key, {
    success: false,
    error: 'previous not confirmed',
    error_code: 'earlier_unconfirmed',
    data: { earlier: { pending_id: 'P1', connection_id: C, success: false, error: 'still', error_code: 'unconfirmed' } },
  }, 3000);
  assert.equal(r.locals.length, 1);
  assert.equal(r.locals[0].state, 'unconfirmed');
  assert.equal(r.locals[0].notice, 'still');
  assert.equal(r.draft, 'second');
  assert.equal(r.error, 'previous not confirmed');
});

test('earlier expired or unreadable asks for a read; one the view lacks asks too', () => {
  const u = { ...newLocal(C, 'first', 1000), state: 'unconfirmed', pending_id: 'P1' };
  const l = newLocal(C, 'second', 2000);
  const sent = { message_id: 'M2', sent_at: '2026-11-25T10:02:00Z' };
  const ex = applySendAnswer([u, l], l.key, { success: true, data: { ...sent, earlier: { pending_id: 'P1', success: false, error: 'late', error_code: 'unconfirmed_expired' } } }, 3000);
  assert.equal(ex.locals[0].state, 'expired');
  assert.equal(ex.refresh, true);
  const lost = applySendAnswer([l], l.key, { success: true, data: { ...sent, earlier: { pending_id: 'P9', success: true, data: sent } } }, 3000);
  assert.equal(lost.refresh, true);
  assert.equal(lost.locals[0].state, 'sent');
});

test('the same text again is the unconfirmed message’s retry', () => {
  const u = { ...newLocal(C, 'same', 1000), state: 'unconfirmed', pending_id: 'P1' };
  assert.equal(sameUnconfirmed([u], C, 'same'), u);
  assert.equal(sameUnconfirmed([u], C, 'other'), undefined);
  assert.equal(sameUnconfirmed([u], 'c2', 'same'), undefined);
});

test('unconfirmed past its time, by this clock, is expired; then a read offers the text again', () => {
  const u = { ...newLocal(C, 'old', 0), state: 'unconfirmed', pending_id: 'P1' };
  assert.equal(expireStale([u], KEPT_FOR_MS - 1).changed, false);
  const e = expireStale([u], KEPT_FOR_MS);
  assert.equal(e.changed, true);
  assert.equal(e.locals[0].state, 'expired');
  assert.equal(e.locals[0].notice, UNCONFIRMED_EXPIRED_TEXT);
  // A read that started before it expired doesn't count.
  assert.equal(afterReload(e.locals, C, new Set(), KEPT_FOR_MS - 1).returned.length, 0);
  const r = afterReload(e.locals, C, new Set(), KEPT_FOR_MS + 1);
  assert.deepEqual(r.returned, ['old']);
  assert.equal(r.locals.length, 0);
});

test('after a read: unreadable sends go (they were done), sent ones go once the page has them', () => {
  const un = { ...newLocal(C, 'done', 0), state: 'unreadable', since: 10 };
  const s1 = { ...newLocal(C, 'a', 0), state: 'sent', message_id: 'M1', sent_at: 'x' };
  const s2 = { ...newLocal(C, 'b', 0), state: 'sent', message_id: 'M2', sent_at: 'y' };
  const other = { ...newLocal('c2', 'z', 0), state: 'unreadable', since: 10 };
  const r = afterReload([un, s1, s2, other], C, new Set(['M1']), 20);
  assert.deepEqual(r.locals.map((l) => l.text), ['b', 'z']);
  assert.deepEqual(r.returned, []);
});

test('texts offered again go before what is in the box', () => {
  assert.equal(withReturned('', ['a']), 'a');
  assert.equal(withReturned('typed', ['a', 'b']), 'a\nb\ntyped');
  assert.equal(withReturned('typed', []), 'typed');
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
