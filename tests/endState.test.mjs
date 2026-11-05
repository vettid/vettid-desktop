// The End-session state rule (src/lib/endState.js). Run with `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { afterRead } from '../src/lib/endState.js';

const NOT_CONFIRMED = "This desktop couldn't reach your vault to end the session, so it may still be open.";
const OTHER = 'Some other notice.';

test('#80: the not-confirmed notice goes once the vault answers the end', () => {
  const r = afterRead({ wasPending: true, nowPending: false, notice: NOT_CONFIRMED, endNotice: NOT_CONFIRMED });
  assert.deepEqual(r, { notice: null, endNotice: null, pending: false });
});

test('#80: it stays while the end is still pending', () => {
  const r = afterRead({ wasPending: true, nowPending: true, notice: NOT_CONFIRMED, endNotice: NOT_CONFIRMED });
  assert.deepEqual(r, { notice: NOT_CONFIRMED, endNotice: NOT_CONFIRMED, pending: true });
});

test('#80: another notice on screen is left alone', () => {
  const r = afterRead({ wasPending: true, nowPending: false, notice: OTHER, endNotice: NOT_CONFIRMED });
  assert.deepEqual(r, { notice: OTHER, endNotice: null, pending: false });
});

test('#80: never cleared on a read that could not tell', () => {
  const r = afterRead({ wasPending: true, nowPending: null, notice: NOT_CONFIRMED, endNotice: NOT_CONFIRMED });
  assert.equal(r.notice, NOT_CONFIRMED);
  assert.equal(r.endNotice, NOT_CONFIRMED);
});

test('#80: nothing to clear without an end notice; pending follows the read', () => {
  assert.deepEqual(afterRead({ wasPending: false, nowPending: true, notice: null, endNotice: null }), { notice: null, endNotice: null, pending: true });
  assert.deepEqual(afterRead({ wasPending: true, nowPending: false, notice: null, endNotice: null }), { notice: null, endNotice: null, pending: false });
});
