// The End-session state rule (src/lib/endState.js). Run with `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { afterRead } from '../src/lib/endState.js';

const NOT_SENT = "This desktop couldn't reach your vault to end the session, so it may still be open.";
const UNCONFIRMED = "Your vault didn't confirm that the session ended.";
const OTHER = 'Some other notice.';
const ended = (over) => afterRead({ wasPending: true, nowPending: false, notice: NOT_SENT, endNotice: NOT_SENT, ...over });

test('#80: the not-confirmed notice goes once the vault confirms the end', () => {
  assert.deepEqual(ended({ confirmed: true }), { notice: null, endNotice: null, pending: false });
});

test('#80 (review H1): an end that stops being pending without a confirmation is never shown as ended', () => {
  // Settled unconfirmed (an old vault, an error answer): the backend's notice replaces ours.
  assert.deepEqual(ended({ settledNotice: UNCONFIRMED }), { notice: UNCONFIRMED, endNotice: null, pending: false });
  // Gone with no outcome at all: our notice stays.
  assert.deepEqual(ended({}), { notice: NOT_SENT, endNotice: null, pending: false });
});

test('#80 (re-review M1): an end gone with nothing on screen and no confirmation says so', () => {
  // After a restart only the spinner showed; the backend says "not confirmed".
  const r = afterRead({ wasPending: true, nowPending: false, notice: null, endNotice: null, settledNotice: UNCONFIRMED });
  assert.deepEqual(r, { notice: UNCONFIRMED, endNotice: null, pending: false });
});

test('#80: it stays while the end is still pending', () => {
  const r = afterRead({ wasPending: true, nowPending: true, notice: NOT_SENT, endNotice: NOT_SENT, confirmed: true });
  assert.deepEqual(r, { notice: NOT_SENT, endNotice: NOT_SENT, pending: true });
});

test('#80: another notice on screen is left alone', () => {
  assert.equal(ended({ notice: OTHER, confirmed: true }).notice, OTHER);
  assert.equal(ended({ notice: OTHER, settledNotice: UNCONFIRMED }).notice, OTHER);
});

test('#80 (review M1): a read that could not tell changes nothing, pending included', () => {
  const r = afterRead({ wasPending: true, nowPending: null, notice: NOT_SENT, endNotice: NOT_SENT, confirmed: true });
  assert.deepEqual(r, { notice: NOT_SENT, endNotice: NOT_SENT, pending: true });
  assert.equal(afterRead({ wasPending: false, nowPending: null, notice: null, endNotice: null }).pending, false);
});

test('#80: a confirmation with no notice of ours clears nothing; pending follows the read', () => {
  assert.deepEqual(ended({ notice: null, endNotice: null, confirmed: true }), { notice: null, endNotice: null, pending: false });
  assert.deepEqual(afterRead({ wasPending: false, nowPending: true, notice: null, endNotice: null }), { notice: null, endNotice: null, pending: true });
});

test('#80: End session returning still pending keeps its notice as its own; otherwise final', async () => {
  const { afterEnd } = await import('../src/lib/endState.js');
  assert.deepEqual(afterEnd({ notice: NOT_SENT, pending: true }), { endNotice: NOT_SENT, pending: true });
  // Answered, or no link (lead review L5): nothing left pending or to clear.
  assert.deepEqual(afterEnd({ notice: UNCONFIRMED, pending: false }), { endNotice: null, pending: false });
  assert.deepEqual(afterEnd({ notice: null, pending: false }), { endNotice: null, pending: false });
});

test('#80 (lead review L4): a read begun before an End press is dropped', async () => {
  const { readIsStale } = await import('../src/lib/endState.js');
  assert.equal(readIsStale(3, 4), true);
  assert.equal(readIsStale(4, 4), false);
});
