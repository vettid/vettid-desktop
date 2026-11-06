// The #96 banner's rule (src/lib/declined.js): never shown unless the session it names is active and not past
// its time, and once it has gone it doesn't come back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { declinedStep } from '../src/lib/declined.js';

const until = 1000;
const fresh = { text: 'Declined.', until, seen: false };

test('#96: shown while the session is active and before its end', () => {
  const r = declinedStep(fresh, 'active', 900);
  assert.equal(r.show, 'Declined.');
  assert.deepEqual(r.next, { ...fresh, seen: true });
  const again = declinedStep(r.next, 'active', 950);
  assert.equal(again.show, 'Declined.');
  assert.equal(again.next, r.next, 'unchanged once seen, so the app writes nothing');
});

test('#96: waits, hidden, until the app reads the live session', () => {
  const r = declinedStep(fresh, 'expired', 900);
  assert.equal(r.show, null);
  assert.equal(r.next, fresh);
  assert.equal(declinedStep(r.next, 'active', 901).show, 'Declined.');
});

test('#96: gone for good once the session stops being active after it was shown', () => {
  const seen = { ...fresh, seen: true };
  for (const s of ['expired', 'suspended', 'revoked', 'inactive']) {
    assert.deepEqual(declinedStep(seen, s, 900), { show: null, next: null }, s);
  }
});

test('#96: never shown at or after the time it names', () => {
  assert.deepEqual(declinedStep(fresh, 'active', until), { show: null, next: null });
  assert.deepEqual(declinedStep({ ...fresh, seen: true }, 'active', until + 60), { show: null, next: null });
  assert.deepEqual(declinedStep(fresh, 'expired', until + 1), { show: null, next: null });
});

test('#96: nothing to show without a notice', () => {
  assert.deepEqual(declinedStep(null, 'active', 900), { show: null, next: null });
});
