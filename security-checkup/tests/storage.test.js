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
