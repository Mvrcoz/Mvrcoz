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
