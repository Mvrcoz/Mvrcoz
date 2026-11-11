// Saved progress for the daily checkup. Nothing else is ever stored:
// no passwords, no links, no generated values.

export const STORAGE_KEY = 'security-checkup:state';

const DATE_KEY = /^\d{4}-\d{2}-\d{2}$/;

export function freshState() {
  return { version: 1, checklist: {}, lastDoneDate: null, streak: 0, bestStreak: 0 };
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isCount = (v) => Number.isInteger(v) && v >= 0;

// Returns a clean copy of `raw` if it is a valid saved state, otherwise null.
function sanitize(raw) {
  if (!isPlainObject(raw) || raw.version !== 1) return null;
  if (!isCount(raw.streak) || !isCount(raw.bestStreak)) return null;
  if (raw.lastDoneDate !== null && !(typeof raw.lastDoneDate === 'string' && DATE_KEY.test(raw.lastDoneDate))) return null;
  if (!isPlainObject(raw.checklist)) return null;
  const checklist = {};
  for (const [id, done] of Object.entries(raw.checklist)) {
    if (done === true) checklist[id] = true;
  }
  return {
    version: 1,
    checklist,
    lastDoneDate: raw.lastDoneDate,
    streak: raw.streak,
    bestStreak: raw.bestStreak,
  };
}

// `storage` is a localStorage-like object, or null when none is available.
export function loadState(storage) {
  if (!storage) return { state: freshState(), persistent: false };
  let text;
  try {
    text = storage.getItem(STORAGE_KEY);
  } catch {
    return { state: freshState(), persistent: false };
  }
  if (text === null) return { state: freshState(), persistent: true };
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { state: freshState(), persistent: true };
  }
  return { state: sanitize(parsed) ?? freshState(), persistent: true };
}

// Returns true only if the state was actually written.
export function saveState(storage, state) {
  if (!storage) return false;
  try {
    storage.setItem(STORAGE_KEY, JSON.stringify(state));
    return true;
  } catch {
    return false;
  }
}
