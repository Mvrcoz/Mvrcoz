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
