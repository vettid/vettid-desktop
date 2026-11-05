// The vault's lock and hold on screen (src/lib/vaultState.js, #77,
// VAULT-LOCK-PLAN §3.2-§3.4). Run with `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TEXT, vaultScreen, countsLine, lockedText, endOffered, notLiveState, timeOf } from '../src/lib/vaultState.js';

const LOCALE = 'en-US';
const AT = '2026-11-05T15:04:00.000Z';
const at = timeOf(AT, LOCALE);

test('§3.4: the texts are the owner-approved ones, word for word', () => {
  assert.equal(TEXT.locked, 'Your vault was locked. Unlock it on your phone to continue.');
  assert.equal(TEXT.lockedIdle, "Your vault locked itself because your daily check wasn't done. Unlock it on your phone.");
  assert.equal(TEXT.lockedOwnerCheck, 'Your vault locked itself after too many failed daily checks. Unlock it on your phone.');
  assert.equal(TEXT.lockedRecovery, 'Your vault was locked because a recovery started. Use your phone to continue.');
  assert.equal(TEXT.unknown, "This desktop can't tell whether your vault is open. It keeps checking.");
  assert.equal(TEXT.held, 'Your vault is waiting for your daily check. Open VettID on your phone to continue.');
  assert.equal(TEXT.heldNoCounts, 'Something may be waiting for you.');
  assert.equal(TEXT.holdOff, "Your daily check is overdue. Your vault's hold is off, so this desktop keeps working.");
});

test('Locked: each reason its own text; an unknown or no reason the plain one', () => {
  assert.equal(lockedText(null), TEXT.locked);
  assert.equal(lockedText('idle'), TEXT.lockedIdle);
  assert.equal(lockedText('owner_check'), TEXT.lockedOwnerCheck);
  assert.equal(lockedText('recovery'), TEXT.lockedRecovery);
  assert.equal(lockedText('later'), TEXT.locked);
  for (const reason of [null, 'idle', 'owner_check', 'recovery']) {
    const s = vaultScreen({ state: 'locked', reason, locked_since: AT }, LOCALE);
    assert.deepEqual(s, { kind: 'locked', lines: [lockedText(reason)], holdOff: null, showStart: false });
  }
});

test('Locked, can\'t check now (owner decision 2): "locked at <time>", as of the last confirmation', () => {
  const s = vaultScreen({ state: 'locked', reason: 'idle', locked_since: AT, as_of: AT }, LOCALE);
  assert.deepEqual(s.lines, [`Your vault was locked at ${at}. This desktop can't reach it now to check.`]);
  assert.equal(s.showStart, false);
});

test('Held: the text, the counts with their plurals, and the idle-lock line', () => {
  const s = vaultScreen({ state: 'held', waiting: { messages: 3, requests: 1, calls: 2, other: 1 }, idle_lock_at: AT }, LOCALE);
  assert.deepEqual(s.lines, [
    TEXT.held,
    'Waiting: 3 messages, 1 request, 2 missed calls, 1 other.',
    `Your vault locks itself at ${at} unless you do your daily check.`,
  ]);
  assert.equal(s.kind, 'held');
  assert.equal(s.showStart, false);
});

test('Held, the plurals: a count of 1 singular, a count of 0 left out', () => {
  assert.equal(countsLine({ messages: 1, requests: 0, calls: 0, other: 0 }), 'Waiting: 1 message.');
  assert.equal(countsLine({ messages: 0, requests: 2, calls: 1, other: 0 }), 'Waiting: 2 requests, 1 missed call.');
  assert.equal(countsLine({ messages: 0, requests: 0, calls: 0, other: 5 }), 'Waiting: 5 other.');
  assert.equal(countsLine({ messages: 2, requests: 1, calls: 3, other: 0 }), 'Waiting: 2 messages, 1 request, 3 missed calls.');
  // All zero: nothing is waiting, so no line (and no "may be waiting").
  assert.equal(countsLine({ messages: 0, requests: 0, calls: 0, other: 0 }), null);
  assert.deepEqual(vaultScreen({ state: 'held', waiting: { messages: 0, requests: 0, calls: 0, other: 0 } }).lines, [TEXT.held]);
});

test('Held without counts (§3.6.5): "something may be waiting", never zeros; no idle line without its time', () => {
  for (const waiting of [null, undefined]) {
    assert.deepEqual(vaultScreen({ state: 'held', waiting }).lines, [TEXT.held, TEXT.heldNoCounts]);
  }
});

test('Unknown, and no view at all (no link): the Unknown text', () => {
  for (const v of [{ state: 'unknown' }, null, undefined]) {
    assert.deepEqual(vaultScreen(v), { kind: 'unknown', lines: [TEXT.unknown], holdOff: null, showStart: false });
  }
});

test('Open: no state text; the hold-off line only while due', () => {
  assert.deepEqual(vaultScreen({ state: 'open', due: false }), { kind: 'open', lines: [], holdOff: null, showStart: true });
  assert.deepEqual(vaultScreen({ state: 'open', due: true }), { kind: 'open', lines: [], holdOff: TEXT.holdOff, showStart: true });
});

test('§3.2: Start New Session hidden while held, locked or unknown', () => {
  const shown = (state) => vaultScreen({ state }).showStart;
  assert.equal(shown('open'), true);
  assert.equal(shown('held'), false);
  assert.equal(shown('locked'), false);
  assert.equal(shown('unknown'), false);
});

test('§3.2: End session offered in every state (Open: while a session is live)', () => {
  for (const kind of ['held', 'locked', 'unknown']) {
    assert.equal(endOffered(kind, false), true, kind);
    assert.equal(endOffered(kind, true), true, kind);
  }
  assert.equal(endOffered('open', true), true);
  assert.equal(endOffered('open', false), false, 'open with no session: nothing to end');
});

test('Held and locked are "suspended", never "expired" (which offers Start New Session)', () => {
  assert.equal(notLiveState({ state: 'held' }), 'suspended');
  assert.equal(notLiveState({ state: 'locked' }), 'suspended');
  assert.equal(notLiveState({ state: 'unknown' }), 'expired');
  assert.equal(notLiveState({ state: 'open' }), 'expired');
  assert.equal(notLiveState(null), 'expired');
});
