// The vault's lock and hold on screen (src/lib/vaultState.js, #77,
// VAULT-LOCK-PLAN §3.2-§3.4). Run with `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TEXT, vaultScreen, countsLine, lockedText, endOffered, notLiveState, timeOf, vaultAt, liveAt, msUntilOpenRunsOut } from '../src/lib/vaultState.js';

const LOCALE = 'en-US';
// "Now" for the screens, and a time on the same day by this computer's clock.
const NOW = new Date(2026, 10, 5, 16, 0, 0);
const AT = new Date(2026, 10, 5, 15, 4, 0).toISOString();
const at = timeOf(AT, LOCALE, NOW);
const screen = (view) => vaultScreen(view, LOCALE, NOW);
const OPEN_UNTIL = new Date(NOW.getTime() + 60_000).toISOString();
const open = (over) => ({ state: 'open', open_until: OPEN_UNTIL, ...over });

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
    const s = screen({ state: 'locked', reason, locked_since: AT });
    assert.deepEqual(s, { kind: 'locked', lines: [lockedText(reason)], holdOff: null, showStart: false });
  }
});

test('Locked, can\'t check now (owner decision 2): "locked at <time>", as of the last confirmation', () => {
  const s = screen({ state: 'locked', reason: 'idle', locked_since: AT, as_of: AT });
  assert.deepEqual(s.lines, [`Your vault was locked at ${at}. This desktop can't reach it now to check.`]);
  assert.equal(s.showStart, false);
});

test('Held: the text, the counts with their plurals, and the idle-lock line', () => {
  const s = screen({ state: 'held', waiting: { messages: 3, requests: 1, calls: 2, other: 1 }, idle_lock_at: AT });
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
  assert.deepEqual(screen({ state: 'held', waiting: { messages: 0, requests: 0, calls: 0, other: 0 } }).lines, [TEXT.held]);
});

test('Held without counts (§3.6.5): "something may be waiting", never zeros; no idle line without its time', () => {
  for (const waiting of [null, undefined]) {
    assert.deepEqual(screen({ state: 'held', waiting }).lines, [TEXT.held, TEXT.heldNoCounts]);
  }
});

test('Unknown: the Unknown text', () => {
  assert.deepEqual(screen({ state: 'unknown' }), { kind: 'unknown', lines: [TEXT.unknown], holdOff: null, showStart: false });
});

test('No link open (own Lock, before unlock): the screen the app always showed, no vault state, Start shown', () => {
  for (const v of [null, undefined]) {
    assert.deepEqual(screen(v), { kind: 'none', lines: [], holdOff: null, showStart: true });
  }
  assert.equal(endOffered('none'), false);
});

test('Open: no state text; the hold-off line only while due', () => {
  assert.deepEqual(screen(open({ due: false })), { kind: 'open', lines: [], holdOff: null, showStart: true });
  assert.deepEqual(screen(open({ due: true })), { kind: 'open', lines: [], holdOff: TEXT.holdOff, showStart: true });
});

test('Open past open_until (or without one) is Unknown, as the backend\'s vault_at; and not live', () => {
  const late = new Date(NOW.getTime() + 61_000);
  assert.equal(vaultScreen(open(), LOCALE, late).kind, 'unknown');
  assert.deepEqual(vaultScreen(open(), LOCALE, late).lines, [TEXT.unknown]);
  assert.equal(vaultScreen(open(), LOCALE, late).showStart, false);
  assert.equal(screen({ state: 'open' }).kind, 'unknown', 'no open_until: never Open');
  assert.equal(vaultAt(open(), NOW).state, 'open');
  assert.equal(vaultAt(open(), late).state, 'unknown');
  assert.equal(vaultAt({ state: 'held' }, late).state, 'held', 'only Open runs out');
  assert.equal(liveAt(true, open(), NOW), true);
  assert.equal(liveAt(true, open(), late), false);
  assert.equal(liveAt(true, { state: 'held' }, NOW), false);
  assert.equal(liveAt(false, open(), NOW), false);
  assert.equal(msUntilOpenRunsOut(open(), NOW), 60_000);
  assert.equal(msUntilOpenRunsOut(open(), late), null);
  assert.equal(msUntilOpenRunsOut({ state: 'locked' }, NOW), null);
});

test('§3.2: Start New Session hidden while held, locked or unknown', () => {
  assert.equal(screen(open()).showStart, true);
  for (const state of ['held', 'locked', 'unknown']) {
    assert.equal(screen({ state }).showStart, false, state);
  }
});

test('§3.2: End session offered in every vault state, Open with no live session included', () => {
  for (const kind of ['open', 'held', 'locked', 'unknown']) {
    assert.equal(endOffered(kind), true, kind);
  }
});

test('A time not today shows its date too, in the locale\'s format; today, the time alone', () => {
  const yesterday = new Date(2026, 10, 4, 23, 30, 0).toISOString();
  const shown = timeOf(yesterday, LOCALE, NOW);
  assert.equal(shown, new Intl.DateTimeFormat(LOCALE, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(yesterday)));
  assert.match(shown, /Nov 4, 2026/);
  assert.equal(at, new Intl.DateTimeFormat(LOCALE, { hour: 'numeric', minute: '2-digit' }).format(new Date(AT)));
  assert.deepEqual(screen({ state: 'locked', as_of: yesterday }).lines, [`Your vault was locked at ${shown}. This desktop can't reach it now to check.`]);
  assert.deepEqual(screen({ state: 'held', waiting: null, idle_lock_at: yesterday }).lines.at(-1), `Your vault locks itself at ${shown} unless you do your daily check.`);
});

test('Held and locked are "suspended", never "expired" (which offers Start New Session)', () => {
  assert.equal(notLiveState({ state: 'held' }), 'suspended');
  assert.equal(notLiveState({ state: 'locked' }), 'suspended');
  assert.equal(notLiveState({ state: 'unknown' }), 'expired');
  assert.equal(notLiveState({ state: 'open' }), 'expired');
  assert.equal(notLiveState(null), 'expired');
});
