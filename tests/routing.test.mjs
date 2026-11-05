// The routing rule (src/lib/routing.js). Run with `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nextView } from '../src/lib/routing.js';

const at = (current, session, isRegistered, pairingHeld = false) =>
  nextView({ current, session, isRegistered, pairingHeld });

test('#79: a pairing under way keeps the pairing view, whatever the poll says', () => {
  // The pending device.enc made the poll report "registered": before the
  // fix this went to "expired" ("Your pairing is in place").
  assert.equal(at('pairing', 'inactive', true, true), 'pairing');
  // A session the approval granted doesn't skip "Desktop paired!".
  assert.equal(at('pairing', 'active', true, true), 'pairing');
  assert.equal(at('pairing', 'expired', true, true), 'pairing');
  assert.equal(at('pairing', 'revoked', false, true), 'pairing');
});

test('#79: once the person leaves the result, routing applies again', () => {
  assert.equal(at('pairing', 'inactive', true), 'expired');
  assert.equal(at('pairing', 'active', true), 'connections');
  assert.equal(at('pairing', 'inactive', false), 'pairing');
});

test('the hold only applies on the pairing view', () => {
  assert.equal(at('connections', 'expired', true, true), 'expired');
  assert.equal(at('loading', 'active', true, true), 'connections');
});

test('the rule as before #79', () => {
  for (const v of ['loading', 'pairing', 'expired']) assert.equal(at(v, 'active', true), 'connections');
  for (const v of ['vault', 'connections', 'settings', 'session-detail']) assert.equal(at(v, 'active', true), v);
  for (const s of ['expired', 'suspended']) {
    assert.equal(at('connections', s, true), 'expired');
    assert.equal(at('settings', s, true), 'settings');
  }
  assert.equal(at('connections', 'revoked', true), 'pairing');
  assert.equal(at('settings', 'revoked', true), 'settings');
  assert.equal(at('vault', 'inactive', true), 'expired');
  assert.equal(at('settings', 'inactive', true), 'settings');
  assert.equal(at('settings', 'inactive', false), 'pairing');
  assert.equal(at('loading', 'inactive', false), 'pairing');
});
