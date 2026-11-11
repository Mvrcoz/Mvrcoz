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
for (const bad of ['', '   ', 'hello world', 'not a link', 'https://', 'localhost', 'just-a-word', 'someone@example.com'])
  test(`not a link: "${bad}"`, () =>
    assert.deepEqual(analyzeUrl(bad), { valid: false, host: null, flags: [], verdict: 'Not a link' }));
test('flags are listed most serious first', () =>
  assert.deepEqual(analyzeUrl('http://paypal.com@203.0.113.9:8080/a.exe').flags.map((f) => f.severity),
    ['high', 'high', 'medium', 'medium', 'low']));
test('a javascript: link with spaces is still reported as dangerous', () =>
  assert.equal(analyzeUrl('javascript:alert( 1 )').verdict, 'Likely dangerous'));
test('country domains outside the common list are not mistaken for impersonation', () => {
  assert.deepEqual(ids('https://www.google.com.pk/'), []);
  assert.deepEqual(ids('https://www.amazon.co.il/'), []);
});
test('a trailing dot on the host changes nothing', () => assert.deepEqual(ids('https://www.paypal.com./'), []));
