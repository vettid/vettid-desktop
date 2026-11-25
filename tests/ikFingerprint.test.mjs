// The `ik` fingerprint (src/lib/ikFingerprint.js) against VAULT-MESSAGING §16's vector, which is also
// src-tauri/crates/vettid-vms/tests/vectors/keys.json's `ik_fingerprint`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decodeIk, ikFingerprint } from '../src/lib/ikFingerprint.js';

const keys = JSON.parse(readFileSync(new URL('../src-tauri/crates/vettid-vms/tests/vectors/keys.json', import.meta.url), 'utf8'));
const vector = keys.ik_fingerprint;

test('§16 vector: the vault ik', async () => {
  assert.equal(vector.ik_b64, 'ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=');
  assert.equal(await ikFingerprint(vector.ik_b64), '9a1f bb7d 873e eafb 494b ef94 f072 7b25');
  assert.equal(await ikFingerprint(vector.ik_b64), vector.shown);
  assert.ok(vector.sha256_hex.startsWith(vector.shown.replaceAll(' ', '')));
});

test('decodes the 32 raw bytes', () => {
  assert.deepEqual(decodeIk(vector.ik_b64), new Uint8Array(Buffer.from(vector.ik_b64, 'base64')));
  assert.deepEqual(decodeIk('A'.repeat(43) + '='), new Uint8Array(32));
  assert.deepEqual(decodeIk('/'.repeat(42) + '8='), new Uint8Array(32).fill(0xff));
});

test('no fingerprint for anything but the standard base64 of 32 bytes', async () => {
  const bad = [
    undefined, null, 42, '',
    vector.ik_b64.slice(0, -1), // no padding
    vector.ik_b64.replace('/', '_'), // base64url
    vector.ik_b64.slice(0, 42) + 'x=', // non-canonical: padding bits set
    'A'.repeat(42) + 'B=',
    vector.ik_b64 + '\n',
    ' ' + vector.ik_b64,
    'A'.repeat(44), // 33 bytes
    'A'.repeat(40) + '==', // 31 bytes
  ];
  for (const b of bad) {
    assert.equal(decodeIk(b), null, String(b));
    assert.equal(await ikFingerprint(b), null, String(b));
  }
});
