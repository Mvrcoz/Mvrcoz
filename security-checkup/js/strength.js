// Password strength estimate. A heuristic, not a guarantee.
//
// The password is read left to right and split into the pieces a guessing tool
// would try first: very common passwords, dictionary words, keyboard and
// alphabet runs, repeated characters, and years. Each such piece is cheap to
// guess however long it is. Whatever is left over is scored by length and
// variety. The total is an estimate of the number of guesses needed, as a
// power of ten.

import { WORDS } from './wordlist.js';

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
  'world', 'helloworld', 'love', 'money', 'angel',
  'azerty', 'qwertz', 'passwort', 'motdepasse', 'пароль', 'йцукен', 'привет',
]);
const MAX_COMMON_LENGTH = Math.max(...[...COMMON].map((entry) => [...entry].length));

// Ordinary words: the same list the passphrase generator uses.
const DICTIONARY = new Set(WORDS.filter((word) => word.length >= 4));
const MAX_WORD_LENGTH = 9;
const MIN_TOKEN_LENGTH = 4;

const LEET = { '@': 'a', '4': 'a', '0': 'o', '1': 'l', '!': 'i', '3': 'e', '$': 's', '5': 's', '7': 't' };

// Alphabet, digits, keyboard rows and keyboard columns. A run along any of
// these, in either direction, is one of the first things a guessing tool tries.
const SEQUENCES = [
  'abcdefghijklmnopqrstuvwxyz', '0123456789', '1234567890',
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
  'azertyuiop', 'qsdfghjklm', 'wxcvbn', 'qwertzuiop',
  'йцукенгшщзхъ', 'фывапролджэ', 'ячсмитьбю',
  'qazwsxedcrfvtgbyhnujmikolp', '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p',
].map((s) => new Map([...s].map((c, i) => [c, i])));

// Cost of each kind of piece, as a power of ten of guesses.
const COST = {
  commonPart: 2,                 // one of roughly a hundred very common passwords
  word: Math.log10(WORDS.length), // one word from a list of several thousand
  sequence: 2,
  repeatRun: 1.5,
  year: 2,
};
const VARIATION_COST = 0.3;      // a capital letter or a letter swap roughly doubles the guesses
const WHOLE_REPEAT_COST = 0.5;   // typing the same thing again adds almost nothing
const ANALYSE_LIMIT = 4096;      // code points looked at; plenty for any real password

const MESSAGES = {
  common: ['This is one of the most commonly used passwords.',
    'Use a passphrase of four or more unrelated words instead.'],
  commonBase: ['This is a very common password with extra characters added.',
    'Adding numbers or symbols to a common word does not help. Start from something unrelated.'],
  commonPart: ['This contains a very common password or word.',
    'Adding to a common password does not help. Start from something unrelated.'],
  word: ['This relies on an ordinary word, which guessing tools try early.',
    'Use four or more unrelated words, or a random password from the generator.'],
  repeat: ['This repeats the same character or pattern.',
    'Avoid repeated characters and patterns. Repeating something adds almost no strength.'],
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
// Shown only when the result is below Strong; a long passphrase is made of
// words on purpose and should not be scolded for it.
const ONLY_WHEN_WEAK = new Set(['commonPart', 'word', 'repeatRun']);

const isDigit = (c) => c >= '0' && c <= '9';
const undoLeet = (text) => [...text].map((c) => LEET[c] ?? c).join('');
const stripEnds = (text) => text.replace(/^[^\p{L}]+|[^\p{L}]+$/gu, '');

function firstCodePoints(text, limit) {
  const chars = [];
  for (const c of text) {
    if (chars.length === limit) break;
    chars.push(c);
  }
  return chars;
}

// Smallest p such that the whole sequence repeats every p characters, if it
// repeats at least (nearly) twice; otherwise 0. Linear time (prefix function).
function repeatPeriod(chars) {
  const n = chars.length;
  if (n < 2) return 0;
  const border = new Array(n).fill(0);
  for (let i = 1, k = 0; i < n; i++) {
    while (k > 0 && chars[i] !== chars[k]) k = border[k - 1];
    if (chars[i] === chars[k]) k++;
    border[i] = k;
  }
  const period = n - border[n - 1];
  return period * 2 <= n + 1 ? period : 0;
}

function sequenceRunAt(chars, start) {
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

function sameCharRunAt(chars, start) {
  let length = 1;
  while (chars[start + length] === chars[start]) length++;
  return length;
}

// Longest entry of `set` starting at `start`, or null. Looks at the text both
// as typed and with letter swaps undone.
function longestListedAt(set, maxLength, original, lower, undone, start) {
  for (let length = Math.min(maxLength, lower.length - start); length >= MIN_TOKEN_LENGTH; length--) {
    const end = start + length;
    const typed = lower.slice(start, end).join('');
    const swapped = undone.slice(start, end).join('');
    const viaTyped = set.has(typed);
    if (!viaTyped && !set.has(swapped)) continue;
    const varied = !viaTyped || original.slice(start, end).some((c, i) => c !== lower[start + i]);
    return { length, varied };
  }
  return null;
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
  // 40 for other alphabets: about one alphabet's worth. Deliberately modest.
  return (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 33 : 0) + (other ? 40 : 0);
}

// Splits `original` into guessable pieces and returns the estimated guesses
// (as a power of ten) plus the kinds of weakness found.
function analyse(original, perChar) {
  const lower = original.map((c) => c.toLowerCase());
  const undone = lower.map((c) => LEET[c] ?? c);
  const kinds = new Set();
  let guessesLog10 = 0;
  let i = 0;

  while (i < lower.length) {
    let best = null;
    const consider = (length, cost, kind) => {
      if (!best || length > best.length || (length === best.length && cost < best.cost)) {
        best = { length, cost, kind };
      }
    };

    const run = sequenceRunAt(lower, i);
    if (run >= 4) consider(run, COST.sequence, 'sequence');

    const same = sameCharRunAt(lower, i);
    if (same >= 3) consider(same, COST.repeatRun, 'repeatRun');

    const common = longestListedAt(COMMON, MAX_COMMON_LENGTH, original, lower, undone, i);
    if (common) consider(common.length, COST.commonPart + (common.varied ? VARIATION_COST : 0), 'commonPart');

    const word = longestListedAt(DICTIONARY, MAX_WORD_LENGTH, original, lower, undone, i);
    if (word) consider(word.length, COST.word + (word.varied ? VARIATION_COST : 0), 'word');

    const century = lower[i] + lower[i + 1];
    if ((century === '19' || century === '20') && isDigit(lower[i + 2] ?? '') && isDigit(lower[i + 3] ?? '')) {
      consider(4, COST.year, 'year');
    }

    if (best) {
      // A piece is never worth more than its characters would be on their own.
      guessesLog10 += Math.min(best.cost, best.length * perChar);
      kinds.add(best.kind);
      i += best.length;
    } else {
      guessesLog10 += perChar;
      i++;
    }
  }
  return { guessesLog10, kinds };
}

function scoreFromGuesses(guessesLog10) {
  if (guessesLog10 < 8) return 0;
  if (guessesLog10 < 10) return 1;
  if (guessesLog10 < 14) return 2;
  if (guessesLog10 < 18) return 3;
  return 4;
}

export function estimateStrength(password) {
  const chars = firstCodePoints(password, ANALYSE_LIMIT);
  if (chars.length === 0) return { score: 0, label: LABELS[0], warnings: [], suggestions: [] };

  const lowerChars = chars.map((c) => c.toLowerCase());
  const lowered = lowerChars.join('');
  const perChar = Math.log10(poolSize(chars));
  const found = [];

  // Something typed two or more times is only as strong as one copy of it.
  const period = repeatPeriod(lowerChars);
  const unit = period > 0 ? chars.slice(0, period) : chars;
  const { guessesLog10, kinds } = analyse(unit, perChar);

  let score = scoreFromGuesses(guessesLog10 + (period > 0 ? WHOLE_REPEAT_COST : 0));
  if (period > 0) {
    if (period <= 4) score = 0;
    found.push('repeat');
  }
  for (const kind of ['commonPart', 'word', 'repeatRun', 'sequence', 'year']) {
    if (kinds.has(kind)) found.push(kind);
  }

  if (chars.every(isDigit)) { score = Math.min(score, 1); found.push('digits'); }
  if (unit.length < 8) { score = 0; found.push('tooShort'); }
  else if (unit.length < 12) { score = Math.min(score, 2); found.push('short'); }

  const base = stripEnds(lowered);
  if (COMMON.has(lowered) || COMMON.has(undoLeet(lowered))) {
    score = 0;
    found.unshift('common');
  } else if (base !== '' && (COMMON.has(base) || COMMON.has(undoLeet(base)))) {
    score = Math.min(score, 1);
    found.unshift('commonBase');
  }

  const shown = [];
  for (const key of found) {
    if (ONLY_WHEN_WEAK.has(key) && score >= 3) continue;
    const name = key === 'repeatRun' ? 'repeat' : key;
    // "common" and "commonBase" already say what "commonPart" would.
    if (name === 'commonPart' && (shown.includes('common') || shown.includes('commonBase'))) continue;
    if (!shown.includes(name)) shown.push(name);
  }
  if (score < 3 && shown.length === 0) shown.push('generic');

  return {
    score,
    label: LABELS[score],
    warnings: shown.map((key) => MESSAGES[key][0]),
    suggestions: [...new Set(shown.map((key) => MESSAGES[key][1]))],
  };
}
