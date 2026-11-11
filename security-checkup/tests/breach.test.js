import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { RANGE_URL, sha1Hex, checkBreach } from '../js/breach.js';

const HASH = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'; // SHA-1 of "password"
const SUFFIX = HASH.slice(5);
const other = (n) => `${String(n).padStart(35, '0')}:${n + 1}`;
const reply = (body, status = 200) => async () => new Response(body, { status });

test('sha1Hex matches the known value', async () => assert.equal(await sha1Hex('password'), HASH));
test('sha1Hex hashes UTF-8 bytes', async () => {
  for (const s of ['пароль', 'pässwörd', '🔑 key'])
    assert.equal(await sha1Hex(s), createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase());
});
test('sends only the 5-character prefix, no extra headers', async () => {
  const calls = [];
  await checkBreach('password', async (url, init) => { calls.push([String(url), init]); return new Response(other(1)); });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], RANGE_URL + '5BAA6');
  assert.equal(calls[0][0].includes(SUFFIX), false);
  assert.deepEqual(Object.keys(calls[0][1]?.headers ?? {}), []);
});
test('found returns the count', async () =>
  assert.deepEqual(await checkBreach('password', reply(`${other(1)}\r\n${SUFFIX}:52256179\r\n${other(2)}`)),
    { status: 'found', count: 52256179 }));
test('suffix match is case-insensitive', async () =>
  assert.equal((await checkBreach('password', reply(`${SUFFIX.toLowerCase()}:7`))).status, 'found'));
test('absent suffix is clear', async () =>
  assert.deepEqual(await checkBreach('password', reply(`${other(1)}\r\n${other(2)}`)), { status: 'clear' }));
test('a padded zero-count entry is clear', async () =>
  assert.deepEqual(await checkBreach('password', reply(`${SUFFIX}:0\r\n${other(1)}`)), { status: 'clear' }));
for (const [name, impl] of [
  ['HTTP 429', reply('slow down', 429)],
  ['HTTP 500', reply('', 500)],
  ['network error', async () => { throw new TypeError('Failed to fetch'); }],
  ['HTML instead of hashes', reply('<html><body>Sign in to Wi-Fi</body></html>')],
  ['empty body', reply('')],
])
  test(`${name} is unavailable`, async () =>
    assert.deepEqual(await checkBreach('password', impl), { status: 'unavailable' }));
test('timeout is unavailable and aborts the request', async () => {
  let aborted = false;
  const hang = (url, { signal }) => new Promise((_, reject) =>
    signal.addEventListener('abort', () => { aborted = true; reject(new DOMException('aborted', 'AbortError')); }));
  assert.deepEqual(await checkBreach('password', hang, { timeoutMs: 20 }), { status: 'unavailable' });
  assert.equal(aborted, true);
});
test('a body that stalls after the headers also times out', async () => {
  const stalled = async (url, { signal }) => ({
    ok: true,
    status: 200,
    text: () => new Promise((_, reject) =>
      signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))),
  });
  assert.deepEqual(await checkBreach('password', stalled, { timeoutMs: 20 }), { status: 'unavailable' });
});
test('empty password makes no request', async () => {
  let called = false;
  assert.deepEqual(await checkBreach('', async () => { called = true; }), { status: 'unavailable' });
  assert.equal(called, false);
});

// ---- Found in final review ----
test('a body mixing junk with hash lines is unavailable, never clear', async () => {
  assert.deepEqual(await checkBreach('password', reply(`<html>\n${other(1)}\n</html>`)), { status: 'unavailable' });
  assert.deepEqual(await checkBreach('password', reply(`${other(1)}\r\n\r\n${other(2)}\r\n`)), { status: 'clear' });
});
test('hashing unavailable (insecure page) is unavailable, not a hang, and sends nothing', async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  Object.defineProperty(globalThis, 'crypto', { value: {}, configurable: true });
  let called = false;
  try {
    assert.deepEqual(await checkBreach('password', async () => { called = true; return new Response(other(1)); }),
      { status: 'unavailable' });
  } finally {
    Object.defineProperty(globalThis, 'crypto', original);
  }
  assert.equal(called, false);
});
