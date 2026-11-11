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
test('every result below Strong carries a warning and a suggestion', () => {
  for (const p of ['Tr0ub4d&3x', 'hgjtkrlwq', '19901990', 'zzzzzzzzzzzzzz', 'abcdefghijkl', 'short1!']) {
    const r = estimateStrength(p);
    assert.ok(r.score < 3, p);
    assert.ok(r.warnings.length > 0 && r.suggestions.length > 0, p);
  }
});
test('a strong password with no weakness has no messages', () => {
  const r = estimateStrength('kV9#mQ2$xL7!pR4z');
  assert.deepEqual([r.warnings, r.suggestions], [[], []]);
});
test('non-ASCII input does not throw', () => {
  for (const p of ['пароль-пароль-пароль', 'pässwörd', '🔑🔑🔑🔑🔑🔑🔑🔑'])
    assert.ok(Number.isInteger(score(p)));
});
test('a 10,000 character paste returns within 200 ms', () => {
  const t = performance.now();
  estimateStrength('aB3$'.repeat(2500));
  estimateStrength('qwertyuiop'.repeat(999) + 'x');
  assert.ok(performance.now() - t < 200);
});
