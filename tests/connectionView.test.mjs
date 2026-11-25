// The connection views' rules (src/lib/connectionView.js, DESKTOP-REWORK-PLAN Phase 5, 5.2): the §10.8
// title, the request rows, and when the views read again or drop a batch. Run with `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  NAME_NOT_SHARED,
  cleanOneLine,
  isEmptyText,
  connectionTitle,
  secondaryNames,
  requestTitle,
  requestSecondary,
  relayHeldText,
  ANSWERED_ON_PHONE,
  inboundAction,
  livenessChanged,
  UNREADABLE_REQUEST,
  UNREADABLE_CONNECTIONS,
  requestRow,
  hasUnreadableConnections,
} from '../src/lib/connectionView.js';

const FSI = '\u2068';
const PDI = '\u2069';
const ada = { first_name: 'Ada', last_name: 'King', name: 'Ada', version: 1, ik: 'x', items: [] };

test('§10.8: the placeholder text, word for word', () => {
  assert.equal(NAME_NOT_SHARED, 'Name not shared yet');
});

test('§10.8: titled first_name, one space, last_name, from the profile', () => {
  assert.equal(connectionTitle({ alias: '', name: 'Ada', profile: ada }), 'Ada King');
});

test('§10.8: the owner alias replaces the title; the names are still shown with it', () => {
  const c = { alias: 'Aunt Ada', name: 'Ada', profile: ada };
  assert.equal(connectionTitle(c), 'Aunt Ada');
  assert.deepEqual(secondaryNames(c), ['Ada King', 'Ada']);
});

test('§10.4: never titled from name alone; no profile yet is the placeholder', () => {
  assert.equal(connectionTitle({ alias: '', name: 'Ada' }), NAME_NOT_SHARED);
  assert.equal(connectionTitle({ alias: '', name: 'Ada', profile: null }), NAME_NOT_SHARED);
  assert.deepEqual(secondaryNames({ alias: '', name: 'Ada' }), ['Ada']);
});

test('§10.8: the display name is secondary only when non-empty and different', () => {
  assert.deepEqual(secondaryNames({ alias: '', name: 'Ada', profile: ada }), ['Ada']);
  assert.deepEqual(secondaryNames({ alias: '', name: 'Ada King', profile: ada }), []);
  assert.deepEqual(secondaryNames({ alias: '', name: '', profile: ada }), []);
  assert.deepEqual(secondaryNames({ alias: '', profile: { ...ada, name: 'Countess' } }), ['Countess']);
});

test('§10.8 step 4: names that clean to nothing are the placeholder, never a blank', () => {
  const blank = { first_name: '\u200B', last_name: ' \u2800 ', version: 1, ik: 'x', items: [] };
  assert.equal(connectionTitle({ alias: '\u202E', profile: blank }), NAME_NOT_SHARED);
  assert.equal(connectionTitle({ alias: '   ', profile: { ...blank, last_name: 'King' } }), 'King');
});

test('§10.8 steps 1-3: breaks and tabs become spaces, controls go, ZWJ stays, ends trimmed', () => {
  assert.equal(cleanOneLine(' A\r\nB\tC\u2028D '), 'A B C D');
  assert.equal(cleanOneLine('Ad\u202Ea\u200B'), 'Ada');
  assert.equal(cleanOneLine('a\u200Db'), 'a\u200Db');
  assert.equal(cleanOneLine('x\uD800y'), 'x\uFFFDy');
  assert.equal(cleanOneLine(undefined), '');
  assert.ok(isEmptyText('\u3164\u2800 '));
  assert.ok(!isEmptyText('a'));
});

test('requests: titled from the profile names, display name secondary', () => {
  assert.equal(requestTitle({ profile: ada }), 'Ada King');
  assert.deepEqual(requestSecondary({ profile: ada }), ['Ada']);
  // An outgoing request has only the bundle's hint.name.
  assert.equal(requestTitle({ name: 'Shop' }), NAME_NOT_SHARED);
  assert.deepEqual(requestSecondary({ name: 'Shop' }), ['Shop']);
  assert.deepEqual(requestSecondary({}), []);
});

test('relay_held: the owner-approved text, the title isolated inside it', () => {
  assert.equal(relayHeldText('Ada King'), `Waiting to reach ${FSI}Ada King${PDI} at their vault's new address.`);
  assert.equal(relayHeldText(NAME_NOT_SHARED), "Waiting to reach a connection at their vault's new address.");
});

test('inbound: dropped while not live, whatever it carries', () => {
  assert.equal(inboundAction({ messages: [], resync: true }, false), 'drop');
  const ev = { type: 'sync.event', body: { kind: 'connection.changed', members: {} } };
  assert.equal(inboundAction({ messages: [ev], resync: false }, false), 'drop');
});

test('inbound: reload on resync and on the connection kinds only', () => {
  assert.equal(inboundAction({ messages: [], resync: true }, true), 'reload');
  for (const kind of ['connection.changed', 'connection.request', 'block.added', 'block.removed']) {
    assert.equal(inboundAction({ messages: [{ type: 'sync.event', body: { kind, members: {} } }], resync: false }, true), 'reload', kind);
  }
  for (const kind of ['message.receipt', 'message.read', 'feed.updated']) {
    assert.equal(inboundAction({ messages: [{ type: 'sync.event', body: { kind, members: {} } }], resync: false }, true), 'none', kind);
  }
  const msg = { type: 'message.new', body: { connection_id: 'c', kind: 'connection.changed' } };
  assert.equal(inboundAction({ messages: [msg], resync: false }, true), 'none');
  assert.equal(inboundAction(null, true), 'none');
});

test('liveness: a change either way reads again; no change does not', () => {
  assert.ok(livenessChanged('expired', 'active'));
  assert.ok(livenessChanged(undefined, 'active'));
  assert.ok(livenessChanged('active', 'suspended'));
  assert.ok(!livenessChanged('active', 'active'));
  assert.ok(!livenessChanged('expired', 'suspended'));
});

test('unreadable request: its own title, no profile fields, still listed', () => {
  assert.equal(UNREADABLE_REQUEST, 'Unreadable request');
  const inc = { pending_id: 'p1', unreadable: true };
  assert.deepEqual(requestRow(inc), { unreadable: true, title: 'Unreadable request', secondary: [] });
  const out = { connection_id: 'c1', unreadable: true };
  assert.deepEqual(requestRow(out), { unreadable: true, title: 'Unreadable request', secondary: [] });
  // Never the placeholder, even if other fields came with it.
  assert.equal(requestRow({ pending_id: 'p2', unreadable: true, profile: ada, name: 'Ada' }).title, UNREADABLE_REQUEST);
  assert.notEqual(requestRow(inc).title, NAME_NOT_SHARED);
});

test('readable request: titled and described as before', () => {
  assert.deepEqual(requestRow({ pending_id: 'p', profile: ada }), { unreadable: false, title: 'Ada King', secondary: ['Ada'] });
  assert.deepEqual(requestRow({ connection_id: 'c', name: 'Bob' }), { unreadable: false, title: NAME_NOT_SHARED, secondary: ['Bob'] });
});

test('unreadable connections: one line, only when the count is above 0', () => {
  assert.equal(UNREADABLE_CONNECTIONS, "Some connections couldn't be shown: your vault sent them in a form this desktop can't read.");
  assert.ok(hasUnreadableConnections(1));
  assert.ok(hasUnreadableConnections(3));
  assert.ok(!hasUnreadableConnections(0));
  assert.ok(!hasUnreadableConnections(undefined));
  assert.ok(!hasUnreadableConnections('2'));
});

test('requests: answered on the phone, said once', () => {
  assert.equal(ANSWERED_ON_PHONE, 'This is done on your phone.');
});
