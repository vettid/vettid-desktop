// The too-soon notice's time follows the locale (src/lib/tooSoon.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tooSoonNotice } from '../src/lib/tooSoon.js';

const lead = 'Your vault asks this desktop to wait before asking again. You can ask again at';
// 2026-11-05 10:48 in the process's own timezone, as the computer shows it.
const at = Math.floor(new Date(2026, 10, 5, 10, 48, 0).getTime() / 1000);
// ICU puts a narrow no-break space before AM/PM; compare with plain spaces.
const plain = (s) => s.replace(/ | /g, ' ');

test('#83: US English is 12-hour', () => {
  assert.equal(plain(tooSoonNotice(at, 'en-US')), `${lead} 10:48 AM.`);
  const pm = Math.floor(new Date(2026, 10, 5, 13, 5, 0).getTime() / 1000);
  assert.equal(plain(tooSoonNotice(pm, 'en-US')), `${lead} 1:05 PM.`);
});

test('#83: German and British English are 24-hour', () => {
  assert.equal(plain(tooSoonNotice(at, 'de-DE')), `${lead} 10:48.`);
  const pm = Math.floor(new Date(2026, 10, 5, 13, 5, 0).getTime() / 1000);
  assert.equal(plain(tooSoonNotice(pm, 'en-GB')), `${lead} 13:05.`);
});

test('#83: both screens take the same notice from a response', async () => {
  const { noticeOf } = await import('../src/lib/tooSoon.js');
  assert.equal(plain(noticeOf({ retry_at: at, error: 'x' }, '', 'en-US')), `${lead} 10:48 AM.`);
  assert.equal(noticeOf({ retry_at: null, error: 'The error.' }), 'The error.');
  assert.equal(noticeOf({ error: '' }, 'Pairing failed'), 'Pairing failed');
});
