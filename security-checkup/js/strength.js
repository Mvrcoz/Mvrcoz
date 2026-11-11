// Password strength estimate. A heuristic, not a guarantee: it spots the
// weaknesses attackers try first and scores what is left by length and variety.

export const LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];

const COMMON = new Set([
  '123456', 'password', '123456789', '12345678', '12345', '1234567', '1234567890',
  'qwerty', 'abc123', '111111', '123123', 'password1', 'iloveyou', 'admin', 'welcome',
  'monkey', 'dragon', 'letmein', 'football', 'baseball', 'master', 'sunshine',
  'princess', 'qwertyuiop', 'login', 'starwars', 'hello', 'freedom', 'whatever',
  'trustno1', 'shadow', 'superman', 'michael', 'jordan', 'batman', '000000', '654321',
  '1q2w3e4r', '1qaz2wsx', 'qazwsx', 'zxcvbnm', 'asdfghjkl', 'passw0rd', 'charlie',
  'donald', 'ashley', 'bailey', 'flower', 'loveme', 'jesus', 'ninja', 'mustang',
  'access', 'summer', 'winter', 'spring', 'autumn', 'secret', 'computer', 'internet',
  'killer', 'pepper', 'cheese', 'soccer', 'hockey', 'harley', 'ranger', 'buster',
  'thomas', 'robert', 'jennifer', 'jessica', 'daniel', 'andrew', 'joshua', 'hunter',
  'george', 'matthew', 'michelle', 'nicole', 'purple', 'orange', 'banana', 'cookie',
  'chocolate', 'family', 'lovely', 'qwerty123', '1q2w3e', '123qwe', '666666', '888888',
  '121212', '112233', '7777777', '555555', 'test', 'guest', 'root', 'changeme',
  'default', 'administrator', 'google', 'samsung', 'pokemon',
]);

const LEET = { '@': 'a', '4': 'a', '0': 'o', '1': 'l', '!': 'i', '3': 'e', '$': 's', '5': 's', '7': 't' };

// Alphabet, digits, and keyboard rows. A run along any of these, in either
// direction, is one of the first things a guessing tool tries.
const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890']
  .map((s) => new Map([...s].map((c, i) => [c, i])));

const MESSAGES = {
  common: ['This is one of the most commonly used passwords.',
    'Use a passphrase of four or more unrelated words instead.'],
  commonBase: ['This is a very common password with extra characters added.',
    'Adding numbers or symbols to a common word does not help. Start from something unrelated.'],
  repeat: ['This repeats the same character or short pattern.',
    'Avoid repeated characters and patterns.'],
  sequence: ['This contains a run like "abcd", "1234" or "qwerty".',
    'Avoid sequences and keyboard patterns.'],
  year: ['This contains a year, which is easy to guess.',
    'Leave out years and dates.'],
  digits: ['This is made of numbers only.',
    'Mix in letters, or use a passphrase of several words.'],
  tooShort: ['This is shorter than 8 characters.',
    'Use at least 12 characters. Longer is better.'],
  short: ['This is shorter than 12 characters.',
    'Use at least 12 characters. Longer is better.'],
  generic: ['This would not take long for a guessing tool to try.',
    'Make it longer, or use a passphrase of four or more unrelated words.'],
};

const undoLeet = (text) => [...text].map((c) => LEET[c] ?? c).join('');
const stripEnds = (text) => text.replace(/^[^a-z]+|[^a-z]+$/g, '');

function isRepeatedChunk(chars) {
  for (let size = 1; size <= 4; size++) {
    if (chars.length < size * 2) break;
    let repeats = true;
    for (let i = size; i < chars.length; i++) {
      if (chars[i] !== chars[i % size]) { repeats = false; break; }
    }
    if (repeats) return true;
  }
  return false;
}

// Length of the longest sequential run starting at `start`.
function runLengthAt(chars, start) {
  let best = 1;
  for (const index of SEQUENCES) {
    const first = index.get(chars[start]);
    if (first === undefined) continue;
    for (const step of [1, -1]) {
      let length = 1;
      while (index.get(chars[start + length]) === first + step * length) length++;
      if (length > best) best = length;
    }
  }
  return best;
}

const isDigit = (c) => c >= '0' && c <= '9';

// Returns { effectiveLength, hasSequence, hasYear }.
function analysePatterns(chars) {
  let effectiveLength = chars.length;
  let hasSequence = false;
  let hasYear = false;
  let i = 0;
  while (i < chars.length) {
    const run = runLengthAt(chars, i);
    if (run >= 4) {
      effectiveLength -= run - 1;
      hasSequence = true;
      i += run;
      continue;
    }
    const century = chars[i] + chars[i + 1];
    if ((century === '19' || century === '20') && isDigit(chars[i + 2] ?? '') && isDigit(chars[i + 3] ?? '')) {
      effectiveLength -= 3;
      hasYear = true;
      i += 4;
      continue;
    }
    i++;
  }
  return { effectiveLength, hasSequence, hasYear };
}

function poolSize(chars) {
  let lower = false, upper = false, digit = false, symbol = false, other = false;
  for (const c of chars) {
    if (c >= 'a' && c <= 'z') lower = true;
    else if (c >= 'A' && c <= 'Z') upper = true;
    else if (isDigit(c)) digit = true;
    else if (c >= ' ' && c <= '~') symbol = true;
    else other = true;
  }
  return (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 33 : 0) + (other ? 100 : 0);
}

function scoreFromGuesses(guessesLog10) {
  if (guessesLog10 < 8) return 0;
  if (guessesLog10 < 10) return 1;
  if (guessesLog10 < 14) return 2;
  if (guessesLog10 < 18) return 3;
  return 4;
}

export function estimateStrength(password) {
  const chars = [...password];
  if (chars.length === 0) return { score: 0, label: LABELS[0], warnings: [], suggestions: [] };

  const found = [];
  const lowered = password.toLowerCase();
  const lowerChars = [...lowered];
  const { effectiveLength, hasSequence, hasYear } = analysePatterns(lowerChars);
  const digitsOnly = chars.every(isDigit);

  let score = scoreFromGuesses(Math.max(effectiveLength, 0) * Math.log10(poolSize(chars)));

  if (hasSequence) found.push('sequence');
  if (hasYear) found.push('year');
  if (digitsOnly) { score = Math.min(score, 1); found.push('digits'); }
  if (chars.length < 8) { score = 0; found.push('tooShort'); }
  else if (chars.length < 12) { score = Math.min(score, 2); found.push('short'); }

  const base = stripEnds(lowered);
  if (COMMON.has(lowered) || COMMON.has(undoLeet(lowered))) {
    score = 0;
    found.unshift('common');
  } else if (base !== '' && (COMMON.has(base) || COMMON.has(undoLeet(base)))) {
    score = Math.min(score, 1);
    found.unshift('commonBase');
  }
  if (isRepeatedChunk(lowerChars)) {
    score = 0;
    found.unshift('repeat');
  }

  if (score < 3 && found.length === 0) found.push('generic');

  return {
    score,
    label: LABELS[score],
    warnings: found.map((key) => MESSAGES[key][0]),
    suggestions: [...new Set(found.map((key) => MESSAGES[key][1]))],
  };
}
