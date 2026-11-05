// A pending end and an open End confirmation through a screen swap (#77,
// VAULT-LOCK-PLAN §3.2): src/lib/endConfirm.js with endState.js. Run with
// `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CLOSED, openEnd, answer } from '../src/lib/endConfirm.js';
import { afterRead, readIsStale } from '../src/lib/endState.js';
import { vaultScreen } from '../src/lib/vaultState.js';

const NOT_SENT = "This desktop couldn't reach your vault to end the session, so it may still be open.";

test('an open End confirmation, answered after swaps to held, locked and unknown, runs End', () => {
  // The confirmation lives in the store, above the views; no read touches
  // it, so a screen swap (Start coming and going) leaves it as opened.
  const confirm = openEnd();
  for (const state of ['held', 'locked', 'unknown', 'open']) {
    vaultScreen({ state });
  }
  assert.deepEqual(confirm, { open: true, action: 'end' });
  assert.deepEqual(answer(confirm, true), { confirm: CLOSED, run: 'end' });
});

test('a cancelled confirmation runs nothing; a closed one never runs', () => {
  assert.deepEqual(answer(openEnd(), false), { confirm: CLOSED, run: null });
  assert.deepEqual(answer(CLOSED, true), { confirm: CLOSED, run: null });
});

test('#80, #85: a pending end and its notice survive a swap to held and to locked', () => {
  // End session returned still pending, with its notice; then reads come
  // in with the vault held, then locked: the end is still pending.
  let s = { pending: true, notice: NOT_SENT, endNotice: NOT_SENT };
  for (const state of ['held', 'locked']) {
    vaultScreen({ state });
    const r = afterRead({ wasPending: s.pending, nowPending: true, notice: s.notice, endNotice: s.endNotice });
    s = { pending: r.pending, notice: r.notice, endNotice: r.endNotice };
    assert.deepEqual(s, { pending: true, notice: NOT_SENT, endNotice: NOT_SENT }, state);
  }
  // A read with no link (the vault view gone too) changes nothing of it.
  const r = afterRead({ wasPending: s.pending, nowPending: null, notice: s.notice, endNotice: s.endNotice });
  assert.deepEqual(r, { notice: NOT_SENT, endNotice: NOT_SENT, pending: true });
});

test('#80 (L4): readIsStale keeps dropping a read begun before an End press, whatever the vault state', () => {
  for (const state of ['open', 'held', 'locked', 'unknown']) {
    vaultScreen({ state });
    assert.equal(readIsStale(1, 2), true, state);
    assert.equal(readIsStale(2, 2), false, state);
  }
});
