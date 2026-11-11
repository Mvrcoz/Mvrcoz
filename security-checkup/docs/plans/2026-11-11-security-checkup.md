# Security Checkup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build version 1 of Security Checkup, a static, no-backend web app with a password check, link checker, generator, and daily checkup.

**Architecture:** One HTML page with four tab views. Logic lives in small ES modules that never touch the DOM and take `fetch`, randomness, dates, and storage as parameters; `js/app.js` is the only module that touches the page. A service worker makes it installable and usable offline.

**Tech Stack:** Plain HTML, CSS, JavaScript ES modules. Node 22 built-in test runner (`node --test`). Playwright (already installed in the build environment) for one browser smoke test. No runtime or dev dependencies in `package.json`.

**Spec:** `security-checkup/docs/specs/2026-11-11-security-checkup-design.md`

## Global Constraints

- All paths below are relative to `security-checkup/`. The repo-root `README.md` must not change.
- Zero entries under `dependencies` and `devDependencies` in `package.json`; `"type": "module"`.
- Logic modules (`strength`, `breach`, `linkcheck`, `generator`, `checkup`, `storage`, `features`) never reference `document`, `window`, `localStorage`, `Date.now()`, global `fetch`, or `Math.random`. Those arrive as parameters.
- User-supplied text reaches the page only through `textContent` or input `.value`. Never `innerHTML`.
- No inline `<script>` or `style` attributes/blocks (the Content Security Policy forbids them).
- CSP meta tag, exactly: `default-src 'self'; connect-src https://api.pwnedpasswords.com; img-src 'self' data:; base-uri 'none'; form-action 'none'`.
- The only cross-origin request the app ever makes is `GET https://api.pwnedpasswords.com/range/{5 hex chars}`. No `Add-Padding` header.
- Passwords, links, and generated values are never written to storage or logged.
- Commit after every task; end commit messages with the session's attribution trailer.

## Review Focus

Inputs the spec implies but does not spell out. Each has a test in the task named.

1. **Breach API answers 200 with a body that is not hash lines** (captive-portal HTML, empty body). Expected: `unavailable`, never a false `clear`. → Task 3.
2. **Non-ASCII passwords** (accents, Cyrillic, emoji). Expected: hashed as UTF-8, strength does not throw. → Tasks 2 and 3.
3. **Links pasted messily**: surrounding whitespace, upper-case scheme or host, no scheme at all (`PayPal.com/login`). Expected: analysed normally; a missing scheme is not reported as "no HTTPS". → Task 4.
4. **Saved data that is valid JSON but the wrong shape** (`null`, `[]`, `{"version":1,"streak":"x"}`), or a save that throws (quota). Expected: clean state, no exception. → Task 1.
5. **Streak across calendar edges and odd clocks**: month and year rollover, a gap of several days, a saved date later than today. Expected: consecutive days count, anything else restarts at 1, and a broken streak displays as 0. → Task 6.

---

### Task 1: Scaffold, `features.js`, `storage.js`

**Files:**
- Create: `package.json`, `.gitignore`, `js/features.js`, `js/storage.js`
- Test: `tests/features.test.js`, `tests/storage.test.js`

**Interfaces:**
- Produces:
  - `FEATURES: Record<string,'free'>` with keys `password-check`, `breach-lookup`, `link-check`, `generator`, `daily-checkup`
  - `hasFeature(id: string): boolean` — `true` for a key whose tier is `free`, `false` for an unknown id
  - `STORAGE_KEY = 'security-checkup:state'`
  - `freshState(): State` → `{ version: 1, checklist: {}, lastDoneDate: null, streak: 0, bestStreak: 0 }`
  - `loadState(storage: Storage|null): { state: State, persistent: boolean }`
  - `saveState(storage: Storage|null, state: State): boolean`

- [ ] **Step 1: Create `package.json` and `.gitignore`**

`package.json`: `name` `security-checkup`, `private: true`, `type: module`, `engines.node` `>=22`, scripts `test` → `node --test tests/*.test.js`, `test:e2e` → `node tests/e2e/smoke.cjs`, `start` → `node serve.cjs`. `.gitignore`: `node_modules/`.

- [ ] **Step 2: Write the failing tests**

```js
// tests/features.test.js
import test from 'node:test';
import assert from 'node:assert/strict';
import { FEATURES, hasFeature } from '../js/features.js';

test('every v1 feature is free and allowed', () => {
  assert.deepEqual(Object.keys(FEATURES).sort(),
    ['breach-lookup', 'daily-checkup', 'generator', 'link-check', 'password-check']);
  for (const id of Object.keys(FEATURES)) assert.equal(hasFeature(id), true);
});
test('unknown feature is not allowed', () => assert.equal(hasFeature('nope'), false));
```

```js
// tests/storage.test.js
import test from 'node:test';
import assert from 'node:assert/strict';
import { STORAGE_KEY, freshState, loadState, saveState } from '../js/storage.js';

const fake = (initial) => {
  const m = new Map(initial ? [[STORAGE_KEY, initial]] : []);
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v) };
};
const throwing = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('quota'); } };

test('missing data gives a fresh, persistent state', () =>
  assert.deepEqual(loadState(fake()), { state: freshState(), persistent: true }));
test('round trip', () => {
  const s = fake();
  const state = { version: 1, checklist: { mfa: true }, lastDoneDate: '2026-11-11', streak: 3, bestStreak: 5 };
  assert.equal(saveState(s, state), true);
  assert.deepEqual(loadState(s).state, state);
});
for (const bad of ['not json', 'null', '[]', '42', '{"version":2}', '{"version":1,"streak":"x"}',
  '{"version":1,"checklist":[],"lastDoneDate":5,"streak":-1,"bestStreak":1.5}'])
  test(`bad saved data ${bad} falls back to fresh`, () =>
    assert.deepEqual(loadState(fake(bad)).state, freshState()));
test('unknown checklist values are dropped, known shape kept', () =>
  assert.deepEqual(loadState(fake('{"version":1,"checklist":{"a":true,"b":"yes"},"lastDoneDate":"2026-01-02","streak":2,"bestStreak":2}')).state,
    { version: 1, checklist: { a: true }, lastDoneDate: '2026-01-02', streak: 2, bestStreak: 2 }));
test('blocked storage: fresh state, not persistent, save returns false', () => {
  assert.deepEqual(loadState(throwing), { state: freshState(), persistent: false });
  assert.deepEqual(loadState(null), { state: freshState(), persistent: false });
  assert.equal(saveState(throwing, freshState()), false);
  assert.equal(saveState(null, freshState()), false);
});
```

- [ ] **Step 3: Run `npm test`** — expected: FAIL, modules not found.

- [ ] **Step 4: Implement `js/features.js` and `js/storage.js`**

Validation in `loadState`: the parsed value must be a plain object with `version === 1`; `streak` and `bestStreak` non-negative integers; `lastDoneDate` `null` or a `YYYY-MM-DD` string; `checklist` a plain object, keeping only entries whose value is exactly `true`. Any other failure returns `freshState()`.

- [ ] **Step 5: Run `npm test`** — expected: PASS.
- [ ] **Step 6: Commit** — `feat(security-checkup): scaffold, feature seam, and storage`

---

### Task 2: `strength.js`

**Files:**
- Create: `js/strength.js`
- Test: `tests/strength.test.js`

**Interfaces:**
- Produces:
  - `LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong']`
  - `estimateStrength(password: string): { score: 0|1|2|3|4, label: string, warnings: string[], suggestions: string[] }`

- [ ] **Step 1: Write the failing tests**

```js
// tests/strength.test.js
import test from 'node:test';
import assert from 'node:assert/strict';
import { LABELS, estimateStrength } from '../js/strength.js';

const score = (p) => estimateStrength(p).score;

test('empty input: score 0, no messages', () =>
  assert.deepEqual(estimateStrength(''), { score: 0, label: 'Very weak', warnings: [], suggestions: [] }));
test('label matches score', () => {
  for (const p of ['password', 'Tr0ub4dor', 'kV9#mQ2$xL7!pR4z']) {
    const r = estimateStrength(p);
    assert.equal(r.label, LABELS[r.score]);
  }
});
for (const p of ['password', 'PASSWORD', 'P@ssw0rd', '12345678', 'qwerty', 'aaaaaaaaaaaa', 'abcabcabcabc', 'short1!'])
  test(`${p} is Very weak`, () => assert.equal(score(p), 0));
for (const p of ['Password123!', 'qwertyuiop12', '19901990', 'abcdefghijkl'])
  test(`${p} is at most Weak`, () => assert.ok(score(p) <= 1));
test('under 12 characters is capped at Fair', () => assert.ok(score('Tr0ub4d&3x') <= 2));
test('12 random lowercase letters is Strong', () => assert.equal(score('xkqzvmwpbtjh'), 3));
for (const p of ['kV9#mQ2$xL7!pR4z', 'correct-horse-battery-staple'])
  test(`${p} is Very strong`, () => assert.equal(score(p), 4));
test('weak results explain themselves', () => {
  const r = estimateStrength('password');
  assert.ok(r.warnings.length > 0 && r.suggestions.length > 0);
});
test('non-ASCII input does not throw', () => {
  for (const p of ['пароль-пароль-пароль', 'pässwörd', '🔑🔑🔑🔑🔑🔑🔑🔑'])
    assert.ok(Number.isInteger(score(p)));
});
test('a 10,000 character paste returns within 200 ms', () => {
  const t = performance.now();
  estimateStrength('aB3$'.repeat(2500));
  assert.ok(performance.now() - t < 200);
});
```

- [ ] **Step 2: Run `npm test`** — expected: FAIL, module not found.

- [ ] **Step 3: Implement `estimateStrength`**

The algorithm (signature and tests do not determine it):

1. Work on code points (`[...password]`). Empty → the fixed empty result.
2. **Common-password check.** Bundle about 100 very common passwords as a `Set`. Lower-case the input and undo letter swaps (`@`→`a`, `4`→`a`, `0`→`o`, `1`→`l`, `!`→`i`, `3`→`e`, `$`→`s`, `5`→`s`, `7`→`t`). Exact match on either form → score 0. Otherwise strip leading and trailing non-letters; if what remains is in the set → final score capped at 1.
3. **Repeats.** Entirely one character, or a chunk of 1–4 characters repeated to fill the whole password → score 0. Check chunk lengths 1–4 only, so cost stays linear.
4. **Effective length.** Start at the code-point count. For every run of 4 or more sequential characters (ascending or descending in the alphabet or digits, or along a keyboard row `qwertyuiop`, `asdfghjkl`, `zxcvbnm`, `1234567890`, in either direction, case-insensitive) subtract `runLength − 1`. For every 4-digit year `19xx` or `20xx` not already inside such a run, subtract 3.
5. **Pool.** Sum 26 for any lower-case ASCII letter, 26 upper, 10 digits, 33 for ASCII symbols or space, 100 for anything else.
6. `guessesLog10 = max(effectiveLength, 0) × log10(pool)`. Score: `< 8` → 0, `< 10` → 1, `< 14` → 2, `< 18` → 3, else 4.
7. **Caps.** Digits only → at most 1. Fewer than 8 code points → 0. Fewer than 12 → at most 2. Then apply the cap from step 2.
8. One warning and one suggestion per weakness found, in plain English (for example warning "This is one of the most commonly used passwords.", suggestion "Use a passphrase of four or more unrelated words."). A score of 3 or 4 with no weakness returns empty arrays.

- [ ] **Step 4: Run `npm test`** — expected: PASS. If a "random-looking" fixture fails because it happens to contain a run, fix the algorithm, not the fixture, unless the fixture really does contain a 4-character sequence.
- [ ] **Step 5: Commit** — `feat(security-checkup): password strength estimate`

---

### Task 3: `breach.js`

**Files:**
- Create: `js/breach.js`
- Test: `tests/breach.test.js`

**Interfaces:**
- Produces:
  - `RANGE_URL = 'https://api.pwnedpasswords.com/range/'`
  - `sha1Hex(text: string): Promise<string>` — 40 upper-case hex characters, UTF-8 input
  - `checkBreach(password: string, fetchImpl: typeof fetch, opts?: { timeoutMs?: number }): Promise<{status:'found',count:number} | {status:'clear'} | {status:'unavailable'}>` — `timeoutMs` defaults to `8000`

- [ ] **Step 1: Write the failing tests**

```js
// tests/breach.test.js
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
test('empty password makes no request', async () => {
  let called = false;
  assert.deepEqual(await checkBreach('', async () => { called = true; }), { status: 'unavailable' });
  assert.equal(called, false);
});
```

- [ ] **Step 2: Run `npm test`** — expected: FAIL, module not found.

- [ ] **Step 3: Implement `sha1Hex` and `checkBreach`**

`sha1Hex`: `TextEncoder` then `crypto.subtle.digest('SHA-1', bytes)` (global in browsers and Node 22). `checkBreach`: call `fetchImpl(RANGE_URL + prefix, { signal })` with an `AbortController` timer; clear the timer in `finally`. Split the body on line breaks and keep only lines matching `/^[0-9A-F]{35}:\d+$/i`. Zero valid lines → `unavailable`. A matching suffix with count > 0 → `found`; otherwise `clear`.

- [ ] **Step 4: Run `npm test`** — expected: PASS.
- [ ] **Step 5: Commit** — `feat(security-checkup): breach lookup via k-anonymity range API`

---

### Task 4: `linkcheck.js`

**Files:**
- Create: `js/linkcheck.js`
- Test: `tests/linkcheck.test.js`

**Interfaces:**
- Produces: `analyzeUrl(input: string): { valid: boolean, host: string|null, flags: Flag[], verdict: string }` where `Flag = { id: string, severity: 'high'|'medium'|'low', message: string }`
- Flag ids and severities: `not-web` high, `userinfo` high, `ip-host` high, `lookalike` high, `brand-mismatch` high, `no-https` medium, `deep-subdomains` medium, `executable` medium, `shortener` low, `port` low, `pressure-words` low, `odd-shape` low
- Verdicts: `Likely dangerous` (any high), `Be careful` (any medium), `Minor concerns` (only low), `No red flags found` (none), `Not a link` (`valid: false`)

- [ ] **Step 1: Write the failing tests**

```js
// tests/linkcheck.test.js
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl } from '../js/linkcheck.js';

const ids = (u) => analyzeUrl(u).flags.map((f) => f.id).sort();

for (const u of ['https://www.wikipedia.org/wiki/Phishing', 'https://accounts.google.com/signin',
  'https://www.paypal.co.uk/signin', 'https://login.microsoftonline.com/', 'https://googleapis.com/x',
  'https://pineapple.com/', 'https://www.amazon.com.au/dp/B000'])
  test(`clean: ${u}`, () => {
    const r = analyzeUrl(u);
    assert.deepEqual(r.flags, []);
    assert.equal(r.verdict, 'No red flags found');
    assert.equal(r.valid, true);
  });

const cases = [
  ['javascript:alert(1)', ['not-web'], 'Likely dangerous'],
  ['data:text/html,<h1>hi</h1>', ['not-web'], 'Likely dangerous'],
  ['https://paypal.com@evil.example/login', ['userinfo'], 'Likely dangerous'],
  ['https://192.168.1.10/login', ['ip-host'], 'Likely dangerous'],
  ['https://[2001:db8::1]/', ['ip-host'], 'Likely dangerous'],
  ['https://xn--pypal-4ve.com/', ['lookalike'], 'Likely dangerous'],
  ['https://pаypal.com/', ['lookalike'], 'Likely dangerous'], // Cyrillic a
  ['https://paypal.com.billing-check.example/', ['brand-mismatch'], 'Likely dangerous'],
  ['https://my-paypal.example/', ['brand-mismatch'], 'Likely dangerous'],
  ['http://example.com/', ['no-https'], 'Be careful'],
  ['https://a.b.c.d.example.com/', ['deep-subdomains'], 'Be careful'],
  ['https://example.com/files/Invoice.PDF.exe', ['executable'], 'Be careful'],
  ['https://bit.ly/3abcd', ['shortener'], 'Minor concerns'],
  ['https://example.com:8443/', ['port'], 'Minor concerns'],
  ['https://account-verify.example/', ['pressure-words'], 'Minor concerns'],
  ['https://my-very-long-site-name.example/', ['odd-shape'], 'Minor concerns'],
  ['https://example.com/' + 'a'.repeat(200), ['odd-shape'], 'Minor concerns'],
  ['http://paypal.com@203.0.113.9:8080/a.exe', ['executable', 'ip-host', 'no-https', 'port', 'userinfo'], 'Likely dangerous'],
];
for (const [u, expected, verdict] of cases)
  test(`${u.slice(0, 60)} → ${expected}`, () => {
    assert.deepEqual(ids(u), expected);
    assert.equal(analyzeUrl(u).verdict, verdict);
  });

test('flags carry severity and a message', () => {
  const [f] = analyzeUrl('http://example.com/').flags;
  assert.equal(f.severity, 'medium');
  assert.ok(f.message.length > 10);
});
test('host is reported in lower case', () => assert.equal(analyzeUrl('HTTPS://Example.COM/Path').host, 'example.com'));
test('surrounding whitespace is ignored', () => assert.deepEqual(ids('  \n https://example.com/ \t'), []));
test('a missing scheme is assumed https and not flagged', () => {
  const r = analyzeUrl('PayPal.com/login');
  assert.equal(r.valid, true);
  assert.equal(r.host, 'paypal.com');
  assert.deepEqual(r.flags, []);
  assert.deepEqual(ids('example.com:8443/x'), ['port']); // "example.com:" is not a scheme
});
for (const bad of ['', '   ', 'hello world', 'not a link', 'https://', 'localhost', 'just-a-word'])
  test(`not a link: "${bad}"`, () =>
    assert.deepEqual(analyzeUrl(bad), { valid: false, host: null, flags: [], verdict: 'Not a link' }));
```

- [ ] **Step 2: Run `npm test`** — expected: FAIL, module not found.

- [ ] **Step 3: Implement `analyzeUrl`**

Decisions the tests do not fully determine:

- **Parsing.** Trim. Input containing internal whitespace → not a link. It "has a scheme" only if it matches `/^[a-z][a-z0-9+.-]*:\/\//i` or starts with one of `javascript: data: vbscript: file: blob: about: mailto: tel: sms:` (case-insensitive); otherwise prepend `https://`, so `example.com:8443/x` is read as a host and port. Parse with `new URL`; failure → not a link. A scheme other than `http:`/`https:` → `valid: true`, `host: null`, the single flag `not-web`. A host that is neither an IP address nor contains a dot → not a link.
- **Registrable domain.** Last two labels, or last three when the last two are in `TWO_PART_SUFFIXES` (`co.uk`, `org.uk`, `ac.uk`, `gov.uk`, `com.au`, `net.au`, `org.au`, `co.nz`, `co.jp`, `co.kr`, `co.in`, `co.za`, `com.br`, `com.mx`, `com.ar`, `com.cn`, `com.tr`, `com.sg`, `com.hk`). Its first label is the "main name".
- **`lookalike`.** Any host label starts with `xn--` (the URL parser converts non-ASCII hosts to this form).
- **`brand-mismatch`.** `BRANDS` = `paypal, apple, google, microsoft, amazon, netflix, facebook, instagram, whatsapp, chase, wellsfargo, bankofamerica, usps, fedex, ups, dhl, irs, coinbase, binance`. Split every host label on `-`; flag when any piece equals a brand and the main name is not itself a brand.
- **`deep-subdomains`.** Five or more labels, IP hosts excluded.
- **`executable`.** Lower-cased path ends with `.exe .scr .msi .apk .bat .cmd .vbs .jar`.
- **`shortener`.** Host is one of `bit.ly, tinyurl.com, t.co, goo.gl, ow.ly, is.gd, buff.ly, rebrand.ly, cutt.ly, shorturl.at, tiny.cc, rb.gy`.
- **`port`.** `url.port !== ''` (the parser already drops default ports).
- **`pressure-words`.** The main name, split on `-`, contains `login, signin, verify, secure, account, update`. Subdomains are not checked, so `accounts.google.com` stays clean.
- **`odd-shape`.** Three or more hyphens in the host (not counting labels that start with `xn--`, which `lookalike` already covers), or trimmed input longer than 200 characters.
- Messages are one plain-English sentence each, for example `userinfo`: "The real destination is the part after the @ sign, not the name shown before it."

- [ ] **Step 4: Run `npm test`** — expected: PASS.
- [ ] **Step 5: Commit** — `feat(security-checkup): link red-flag checker`

---

### Task 5: `generator.js` and `wordlist.js`

**Files:**
- Create: `js/generator.js`, `js/wordlist.js`
- Test: `tests/generator.test.js`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces:
  - `WORDS: string[]` (7,776 entries) from `js/wordlist.js`
  - `SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?'`
  - `randomInt(max: number, randomValues: (a: Uint32Array) => Uint32Array): number` — uniform in `[0, max)`
  - `randomPassword(opts, randomValues): string` — opts `{ length = 20, upper = true, lower = true, digits = true, symbols = true }`
  - `passphrase(opts, randomValues): string` — opts `{ words = 5, separator = '-', capitalize = false, addNumber = false }`
  - `passwordEntropyBits(opts): number`, `passphraseEntropyBits({ words, addNumber }): number`

- [ ] **Step 1: Generate `js/wordlist.js`**

In a scratch directory outside the repo: `npm pack diceware-wordlist-en-eff@1.0.1`, extract it, and write a throwaway script that `require`s `package/index.js` (an object mapping dice rolls to words), takes `Object.values`, sorts them, and writes `export const WORDS = [...]` with a header comment crediting "EFF Large Wordlist for Passphrases, Electronic Frontier Foundation, CC BY 4.0, https://www.eff.org/dice". Commit only `js/wordlist.js`.

- [ ] **Step 2: Write the failing tests**

```js
// tests/generator.test.js
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { WORDS } from '../js/wordlist.js';
import { SYMBOLS, randomInt, randomPassword, passphrase,
  passwordEntropyBits, passphraseEntropyBits } from '../js/generator.js';

const real = (a) => webcrypto.getRandomValues(a);
const queue = (values) => { let i = 0; return (a) => { for (let j = 0; j < a.length; j++) a[j] = values[i++ % values.length]; return a; }; };

test('word list is the EFF large list', () => {
  assert.equal(WORDS.length, 7776);
  assert.equal(new Set(WORDS).size, 7776);
  for (const w of WORDS) assert.match(w, /^[a-z]+(-[a-z]+)*$/);
  assert.ok(WORDS.includes('abacus') && WORDS.includes('zoom'));
});
test('randomInt stays in range and rejects biased values', () => {
  for (let i = 0; i < 2000; i++) { const n = randomInt(7, real); assert.ok(n >= 0 && n < 7 && Number.isInteger(n)); }
  // 2^32 is not a multiple of 7; 0xFFFFFFFF falls in the rejected tail, so the next value is used
  assert.equal(randomInt(7, queue([0xFFFFFFFF, 3])), 3);
});
test('randomInt rejects a bad max', () => {
  for (const m of [0, -1, 1.5, 2 ** 32 + 1]) assert.throws(() => randomInt(m, real), RangeError);
});
test('default password: 20 characters with every class', () => {
  for (let i = 0; i < 200; i++) {
    const p = randomPassword({}, real);
    assert.equal(p.length, 20);
    assert.match(p, /[a-z]/); assert.match(p, /[A-Z]/); assert.match(p, /[0-9]/);
    assert.ok([...p].some((c) => SYMBOLS.includes(c)));
  }
});
test('only selected classes appear', () =>
  assert.match(randomPassword({ length: 64, upper: false, symbols: false }, real), /^[a-z0-9]{64}$/));
test('password limits', () => {
  for (const length of [7, 65, 12.5, NaN]) assert.throws(() => randomPassword({ length }, real), RangeError);
  assert.throws(() => randomPassword({ upper: false, lower: false, digits: false, symbols: false }, real), RangeError);
  assert.equal(randomPassword({ length: 8 }, real).length, 8);
});
test('default passphrase: 5 list words joined by hyphens', () => {
  const p = passphrase({ separator: ' ' }, real).split(' ');
  assert.equal(p.length, 5);
  for (const w of p) assert.ok(WORDS.includes(w));
  assert.equal(passphrase({}, queue([0])), Array(5).fill(WORDS[0]).join('-'));
});
test('passphrase options', () => {
  assert.match(passphrase({ words: 3, separator: '.', capitalize: true, addNumber: true }, real), /^[A-Z][a-z-]*\.[A-Z][a-z-]*\.[A-Z][a-z-]*[0-9]$/);
  for (const words of [2, 11, 4.5]) assert.throws(() => passphrase({ words }, real), RangeError);
});
test('entropy', () => {
  assert.ok(Math.abs(passphraseEntropyBits({ words: 5 }) - 5 * Math.log2(7776)) < 1e-9);
  assert.ok(Math.abs(passphraseEntropyBits({ words: 5, addNumber: true }) - (5 * Math.log2(7776) + Math.log2(10))) < 1e-9);
  assert.ok(Math.abs(passwordEntropyBits({ length: 20, upper: true, lower: true, digits: true, symbols: true })
    - 20 * Math.log2(62 + SYMBOLS.length)) < 1e-9);
  assert.equal(passwordEntropyBits({ length: 20, upper: false, lower: false, digits: false, symbols: false }), 0);
});
```

- [ ] **Step 3: Run `npm test`** — expected: FAIL, `generator.js` not found.

- [ ] **Step 4: Implement `js/generator.js`**

`randomInt`: draw one `Uint32`; reject and redraw while the value is `>= 2**32 − (2**32 % max)`; return `value % max`. `randomPassword`: one character from each selected class, the rest from the union of selected classes, then a Fisher–Yates shuffle driven by `randomInt`. `passphrase`: `addNumber` appends one random digit to the last word; `capitalize` upper-cases each word's first letter. `passwordEntropyBits` reports `length × log2(pool)` (a slight overestimate, since one of each class is forced; the UI rounds down to a whole number).

- [ ] **Step 5: Run `npm test`** — expected: PASS.
- [ ] **Step 6: Commit** — `feat(security-checkup): password and passphrase generator`

---

### Task 6: `checkup.js`

**Files:**
- Create: `js/checkup.js`
- Test: `tests/checkup.test.js`

**Interfaces:**
- Consumes: `State` and `freshState()` from Task 1
- Produces:
  - `CHECKLIST: { id: string, title: string, why: string }[]` — exactly 12 items, ids unique
  - `DAILY_TASKS: { id: string, text: string }[]` — exactly 30 items, ids unique
  - `toDateKey(date: Date): string` — local `YYYY-MM-DD`
  - `previousDateKey(key: string): string`
  - `taskForDate(key: string): { id, text }`
  - `checklistScore(checklist: Record<string, true>): number` — integer 0–100
  - `toggleChecklistItem(state, id: string, done: boolean): State`
  - `isDoneToday(state, todayKey: string): boolean`
  - `currentStreak(state, todayKey: string): number`
  - `completeToday(state, todayKey: string): State`

- [ ] **Step 1: Write the failing tests**

```js
// tests/checkup.test.js
import test from 'node:test';
import assert from 'node:assert/strict';
import { freshState } from '../js/storage.js';
import { CHECKLIST, DAILY_TASKS, toDateKey, previousDateKey, taskForDate, checklistScore,
  toggleChecklistItem, isDoneToday, currentStreak, completeToday } from '../js/checkup.js';

test('content sizes and unique ids', () => {
  assert.equal(CHECKLIST.length, 12);
  assert.equal(DAILY_TASKS.length, 30);
  assert.equal(new Set(CHECKLIST.map((c) => c.id)).size, 12);
  assert.equal(new Set(DAILY_TASKS.map((t) => t.id)).size, 30);
});
test('toDateKey uses the local calendar date', () => {
  assert.equal(toDateKey(new Date(2026, 0, 5, 23, 59)), '2026-01-05');
  assert.equal(toDateKey(new Date(2026, 10, 11, 0, 0)), '2026-11-11');
});
test('previousDateKey crosses month, year, and leap-day edges', () => {
  assert.equal(previousDateKey('2026-11-11'), '2026-11-10');
  assert.equal(previousDateKey('2026-03-01'), '2026-02-28');
  assert.equal(previousDateKey('2028-03-01'), '2028-02-29');
  assert.equal(previousDateKey('2027-01-01'), '2026-12-31');
});
test('daily task is stable within a day and cycles through all 30', () => {
  assert.deepEqual(taskForDate('2026-11-11'), taskForDate('2026-11-11'));
  const seen = new Set();
  let key = '2026-12-15';
  for (let i = 0; i < 30; i++) { seen.add(taskForDate(key).id); key = previousDateKey(key); }
  assert.equal(seen.size, 30);
});
test('checklist score', () => {
  assert.equal(checklistScore({}), 0);
  assert.equal(checklistScore({ [CHECKLIST[0].id]: true }), 8);
  assert.equal(checklistScore(Object.fromEntries(CHECKLIST.slice(0, 6).map((c) => [c.id, true]))), 50);
  assert.equal(checklistScore(Object.fromEntries(CHECKLIST.map((c) => [c.id, true]))), 100);
  assert.equal(checklistScore({ 'not-a-real-item': true }), 0);
});
test('toggling returns a new state and ignores unknown ids', () => {
  const a = freshState();
  const b = toggleChecklistItem(a, CHECKLIST[0].id, true);
  assert.deepEqual(a, freshState());
  assert.deepEqual(b.checklist, { [CHECKLIST[0].id]: true });
  assert.deepEqual(toggleChecklistItem(b, CHECKLIST[0].id, false).checklist, {});
  assert.deepEqual(toggleChecklistItem(a, 'nope', true), a);
});
test('streak rules', () => {
  let s = completeToday(freshState(), '2026-12-30');
  assert.deepEqual([s.streak, s.bestStreak, s.lastDoneDate], [1, 1, '2026-12-30']);
  assert.deepEqual(completeToday(s, '2026-12-30'), s);            // twice in a day: unchanged
  s = completeToday(s, '2026-12-31');
  s = completeToday(s, '2027-01-01');                               // year rollover
  assert.deepEqual([s.streak, s.bestStreak], [3, 3]);
  s = completeToday(s, '2027-01-05');                               // gap: restart, best kept
  assert.deepEqual([s.streak, s.bestStreak], [1, 3]);
  s = completeToday(s, '2027-01-03');                               // clock moved back: restart
  assert.deepEqual([s.streak, s.bestStreak, s.lastDoneDate], [1, 3, '2027-01-03']);
});
test('displayed streak and done-today', () => {
  const s = { ...freshState(), lastDoneDate: '2026-11-10', streak: 4, bestStreak: 4 };
  assert.equal(currentStreak(s, '2026-11-10'), 4);
  assert.equal(currentStreak(s, '2026-11-11'), 4);                  // still alive today
  assert.equal(currentStreak(s, '2026-11-12'), 0);                  // missed a day
  assert.equal(currentStreak(s, '2026-11-09'), 0);                  // saved date is in the future
  assert.equal(isDoneToday(s, '2026-11-10'), true);
  assert.equal(isDoneToday(s, '2026-11-11'), false);
  assert.equal(currentStreak(freshState(), '2026-11-11'), 0);
});
```

- [ ] **Step 2: Run `npm test`** — expected: FAIL, module not found.

- [ ] **Step 3: Implement `js/checkup.js`**

Date-key arithmetic uses `Date.UTC` on the parsed key so daylight-saving changes cannot shift a day. `taskForDate` index = (days since 1970-01-01 for that key) mod 30. `checklistScore` counts only ids present in `CHECKLIST` and rounds to the nearest integer.

Content — `CHECKLIST` ids, in order: `mfa-email`, `mfa-bank`, `password-manager`, `unique-passwords`, `auto-updates`, `screen-lock`, `backups`, `find-my-device`, `recovery-info`, `browser-updated`, `router-password`, `breach-alerts`. Each gets a short `title` and one-sentence `why`. `DAILY_TASKS`: 30 distinct five-minute actions with ids `task-01` … `task-30` (for example "Review which apps can see your location.", "Check your email account's list of signed-in devices and remove any you don't recognise."). Advice must be standard, uncontroversial practice; nothing that names a specific commercial product.

- [ ] **Step 4: Run `npm test`** — expected: PASS.
- [ ] **Step 5: Commit** — `feat(security-checkup): daily checkup, streaks, and score`

---

### Task 7: Interface — `index.html`, `styles.css`, `app.js`, local server, smoke test

**Files:**
- Create: `index.html`, `styles.css`, `js/app.js`, `serve.cjs`, `tests/e2e/smoke.cjs`

**Interfaces:**
- Consumes: everything produced by Tasks 1–6, with the exact names in their Interfaces blocks
- Produces:
  - `serve.cjs`: `startServer(rootDir: string, port = 0): Promise<{ url: string, close(): Promise<void> }>`; run directly, serves its own directory on port `8080` (or `process.argv[2]`) and prints the URL
  - Element ids used by the smoke test (below)

Element ids:

| View | Ids |
|---|---|
| Navigation | `tab-password`, `tab-link`, `tab-generator`, `tab-checkup` (`role="tab"`); panels `view-password`, `view-link`, `view-generator`, `view-checkup` (`role="tabpanel"`, inactive ones `hidden`) |
| Password | `password-input`, `password-show`, `strength-label`, `strength-meter`, `strength-warnings`, `strength-suggestions`, `breach-button`, `breach-result` |
| Link | `link-input`, `link-button`, `link-verdict`, `link-host`, `link-flags` |
| Generator | `gen-mode-password`, `gen-mode-passphrase`, `gen-length`, `gen-upper`, `gen-lower`, `gen-digits`, `gen-symbols`, `gen-words`, `gen-separator`, `gen-capitalize`, `gen-number`, `gen-button`, `gen-output`, `gen-entropy`, `gen-copy`, `gen-message` |
| Checkup | `daily-task`, `daily-done`, `streak-current`, `streak-best`, `score-value`, `checklist` (one `input[type=checkbox][data-id]` per item), `storage-notice` |
| About | `about` |

- [ ] **Step 1: Write `serve.cjs`**

Node `http` only. Serves files under `rootDir`; `/` → `index.html`. Resolve the requested path and reject (404) anything that does not stay inside `rootDir` after `path.resolve`, and any path segment starting with `.`. Content types for `.html .css .js .cjs .json .webmanifest .png .svg .ico`; `X-Content-Type-Options: nosniff`; `Cache-Control: no-cache`. GET and HEAD only.

- [ ] **Step 2: Write the failing smoke test `tests/e2e/smoke.cjs`**

CommonJS (so `require('playwright')` resolves the globally installed copy). Starts `startServer` on port 0, launches Chromium, and intercepts `https://api.pwnedpasswords.com/range/*`. Any page error, console error, or request to an origin other than the local server or that API fails the run. Checks, each a named step that prints `ok` or throws:

1. Page loads; `#view-password` visible, other three panels hidden.
2. Type `password` → `#strength-label` reads `Very weak`; `#strength-warnings` non-empty.
3. With the route returning `1E4C9B93F3F0682250B6CF8331B7EE68FD8:52256179`, click `#breach-button` → `#breach-result` contains `52,256,179`. The intercepted URL ends in `/range/5BAA6`.
4. With the route aborted, click again → `#breach-result` contains `Couldn't check right now`; `#strength-label` still reads `Very weak`.
5. `#tab-link` → enter `https://paypal.com@evil.example/login` → `#link-verdict` reads `Likely dangerous`; `#link-flags` has one item.
6. Enter `<img src=x onerror=alert(1)>` → verdict `Not a link`; no `img` element exists inside `#view-link`.
7. `#tab-generator` → click `#gen-button` → `#gen-output` value has length 20. Switch to passphrase → generate → value splits into 5 hyphen-separated parts (words containing a hyphen aside, assert `>= 5`). Untick all four classes in password mode → `#gen-button` disabled.
8. `#tab-checkup` → `#daily-task` non-empty; `#score-value` reads `0`; tick the first checkbox → `8`; click `#daily-done` → `#streak-current` reads `1` and the button is disabled. Reload → score still `8`, streak still `1`.
9. Viewport 375×700: `document.documentElement.scrollWidth <= 375` on each of the four views.
10. Keyboard: focus `#tab-password`, press ArrowRight → `#tab-link` is selected and focused.

Run: `npm run test:e2e` — expected: FAIL at step 1 (no `index.html`).

- [ ] **Step 3: Build `index.html`, `styles.css`, `js/app.js`**

- `index.html`: the CSP meta tag from Global Constraints; `<script type="module" src="js/app.js">`; a `<noscript>` message; every input has a `<label>`; result containers have `aria-live="polite"`; password input has `autocomplete="off"`, `autocapitalize="off"`, `spellcheck="false"`. The About section states: only the first 5 characters of a hashed password leave the device; each tool's limits as worded in the spec; credits to Have I Been Pwned and EFF.
- `styles.css`: mobile-first, CSS custom properties, `prefers-color-scheme` light and dark, visible focus rings, text contrast at least 4.5:1, strength meter coloured by `data-score` plus the text label (never colour alone).
- `js/app.js` behaviour:
  - Tabs follow the URL hash (`#password` default, `#link`, `#generator`, `#checkup`); ArrowLeft/ArrowRight move between tabs.
  - Strength updates on every keystroke; an empty field clears the result area and disables `#breach-button`. Editing the password clears `#breach-result`.
  - Breach lookup runs only on button press, through `hasFeature('breach-lookup')`. Copy, exactly: found → `This password has appeared in known data breaches {count} times. Don't use it anywhere.` (count via `toLocaleString('en-US')`); clear → `Not found in known breaches. That doesn't prove it's safe, only that it isn't on this list.`; unavailable → `Couldn't check right now. Your strength result above is still valid.` plus the button relabelled `Try again`.
  - Link view: verdict text from `analyzeUrl`; `Not a link` shows `That doesn't look like a web link. Paste the full address, starting with https://`. Every non-invalid result ends with `This checks how the link is written, not what is on the site.`
  - Generator: output in a read-only input; `#gen-copy` uses `navigator.clipboard.writeText`, and on failure shows `Couldn't copy automatically. Select the text and copy it yourself.` in `#gen-message`; entropy shown as `About {floor(bits)} bits`.
  - Checkup: state from `loadState(safeLocalStorage)`, where reading `window.localStorage` is wrapped in `try`; when `persistent` is false, or a save returns false, `#storage-notice` shows `Your browser is blocking saved data, so progress won't be kept after you close this page.`
  - Service worker registration is added in Task 8, not here.

- [ ] **Step 4: Run `npm test` and `npm run test:e2e`** — expected: both PASS, all 10 smoke steps `ok`.
- [ ] **Step 5: Look at it.** Take screenshots of all four views at 375 px and 1280 px in light and dark, review them, and fix layout or contrast problems.
- [ ] **Step 6: Commit** — `feat(security-checkup): user interface and browser smoke test`

---

### Task 8: Install and offline, icons, README

**Files:**
- Create: `sw.js`, `manifest.webmanifest`, `icons/icon.svg`, `icons/icon-192.png`, `icons/icon-512.png`, `README.md`
- Modify: `index.html` (manifest link, theme colour, icons), `js/app.js` (register the service worker), `tests/e2e/smoke.cjs` (offline step)
- Test: `tests/sw.test.js`

**Interfaces:**
- Consumes: `startServer` from Task 7
- Produces: `sw.js` containing `const CACHE = 'security-checkup-v1';` and `const PRECACHE = [ ... ];` as a JSON-compatible array of relative paths on one statement

- [ ] **Step 1: Write the failing tests**

```js
// tests/sw.test.js
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const sw = readFileSync(new URL('sw.js', root), 'utf8');
const precache = JSON.parse(sw.match(/const PRECACHE = (\[[^\]]*\]);/)[1].replaceAll("'", '"'));
const list = (dir) => readdirSync(new URL(dir, root)).map((f) => `${dir}${f}`);

test('every shipped file is precached, and nothing else', () => {
  const expected = ['./', 'index.html', 'styles.css', 'manifest.webmanifest', ...list('js/'), ...list('icons/')];
  assert.deepEqual([...precache].sort(), expected.sort());
});
test('cache name is versioned', () => assert.match(sw, /const CACHE = 'security-checkup-v\d+';/));
test('manifest is installable', () => {
  const m = JSON.parse(readFileSync(new URL('manifest.webmanifest', root), 'utf8'));
  assert.equal(m.display, 'standalone');
  assert.equal(m.start_url, './');
  assert.deepEqual(m.icons.map((i) => i.sizes).sort(), ['192x192', '512x512']);
  assert.ok(m.name && m.short_name && m.theme_color && m.background_color);
});
```

Add smoke step 11 to `tests/e2e/smoke.cjs`: wait for `navigator.serviceWorker.ready`, reload once so the worker controls the page, `context.setOffline(true)`, reload → `#view-password` visible; type `password` → `Very weak`; `#tab-link` works; click `#breach-button` → `Couldn't check right now`.

- [ ] **Step 2: Run `npm test` and `npm run test:e2e`** — expected: FAIL (`sw.js` missing; step 11 fails).

- [ ] **Step 3: Implement**

- `sw.js`: `install` precaches `PRECACHE` and calls `skipWaiting()`; `activate` deletes every cache whose name is not `CACHE` and calls `clients.claim()`; `fetch` handles only same-origin GET requests, cache-first with a network fallback, and answers navigations from the cached `index.html`. Requests to other origins are left alone (no `respondWith`).
- `js/app.js`: register `sw.js` when `'serviceWorker' in navigator`, after `load`; a failed registration is ignored silently.
- Icons: draw `icons/icon.svg` (a simple shield with a check mark, original artwork), then render the 192 and 512 PNGs from it with a throwaway Playwright script (transparent-free, solid background so it also works as a maskable icon).
- `README.md` sections: what it is; privacy promise; run locally (`npm start`, then open the printed address; opening the file directly will not work); tests (`npm test`, `npm run test:e2e` and its Playwright requirement); **Check the live breach lookup yourself** (type `password`, press Check, expect a count in the tens of millions; this could not be tested in the build environment); publishing on GitHub Pages (owner's steps; note that updating the app means bumping the `CACHE` version in `sw.js`); known limits copied from the spec (strength is an estimate; link checker reads the address only; brand list is short; no `frame-ancestors` on basic static hosts; no `Add-Padding`); credits and licences (Have I Been Pwned; EFF word list, CC BY 4.0); the note that "Security Checkup" is a working name.

- [ ] **Step 4: Run `npm test` and `npm run test:e2e`** — expected: both PASS including step 11.
- [ ] **Step 5: Final checks**

Run `git diff --stat origin/main -- README.md` from the repo root — expected: no output (profile README untouched). Run `grep -rnE "innerHTML|Math\.random|eval\(" js/ sw.js` — expected: no output. Confirm `package.json` has no dependencies.

- [ ] **Step 6: Commit and push** — `feat(security-checkup): offline support, icons, and README`, then `git push -u origin claude/funny-noether-fb4qoe`.
