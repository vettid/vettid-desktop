// Overlapping reads of the backend (src/lib/readOrder.js, #77). Run with
// `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createReadOrder } from '../src/lib/readOrder.js';

/** A read whose answer comes when the test says. */
function deferred() {
  let resolve;
  const p = new Promise((r) => (resolve = r));
  return { p, resolve };
}

test('two reads resolving out of order: the older answer is dropped', async () => {
  const order = createReadOrder();
  const applied = [];
  async function read(answer) {
    const n = order.begin();
    const info = await answer.p;
    if (order.accept(n, info.seq)) applied.push(info.state);
  }
  // A poll begins before the lock (the backend's snapshot 5: active)...
  const before = deferred();
  const poll = read(before);
  // ... the lock is published (6: locked), its event reads at once and
  // answers first ...
  const after = deferred();
  const onEvent = read(after);
  after.resolve({ seq: 6, state: 'suspended' });
  await onEvent;
  // ... and the poll's answer, from before the lock, comes last.
  before.resolve({ seq: 5, state: 'active' });
  await poll;
  assert.deepEqual(applied, ['suspended'], 'the store isn\'t put back to active');
});

test('in order, and the same snapshot twice, both apply', () => {
  const order = createReadOrder();
  const a = order.begin();
  const b = order.begin();
  assert.equal(order.accept(a, 5), true);
  assert.equal(order.accept(b, 5), true);
  assert.equal(order.accept(order.begin(), 7), true);
});

test('a failed read (no link, no counter) is ordered by when it began', () => {
  const order = createReadOrder();
  const early = order.begin(); // a read of the live session, still on its way
  const lockRead = order.begin(); // after this desktop's own Lock: no link
  assert.equal(order.accept(lockRead, null), true);
  assert.equal(order.accept(early, 5), false, 'begun before the failure that was applied');
  // The link opens again: a later read applies, and orders by its counter.
  assert.equal(order.accept(order.begin(), 9), true);
  const stale = order.begin();
  const fresh = order.begin();
  assert.equal(order.accept(fresh, 11), true);
  assert.equal(order.accept(stale, 10), false);
});
