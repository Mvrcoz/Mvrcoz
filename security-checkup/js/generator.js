// Password and passphrase generation. Randomness always comes from the
// caller-supplied `randomValues` (crypto.getRandomValues in the browser);
// Math.random is never used.

import { WORDS } from './wordlist.js';

export const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';

const TWO_32 = 2 ** 32;

// Uniform integer in [0, max). Values in the uneven tail of the 32-bit range
// are thrown away and redrawn, so no result is more likely than another.
export function randomInt(max, randomValues) {
  if (!Number.isInteger(max) || max < 1 || max > TWO_32) {
    throw new RangeError('max must be a whole number from 1 to 2^32');
  }
  const limit = TWO_32 - (TWO_32 % max);
  const buffer = new Uint32Array(1);
  let value;
  do {
    value = randomValues(buffer)[0];
  } while (value >= limit);
  return value % max;
}

const pick = (text, randomValues) => text[randomInt(text.length, randomValues)];

function selectedClasses({ upper = true, lower = true, digits = true, symbols = true }) {
  return [upper && UPPER, lower && LOWER, digits && DIGITS, symbols && SYMBOLS].filter(Boolean);
}

export function randomPassword(options = {}, randomValues) {
  const { length = 20 } = options;
  if (!Number.isInteger(length) || length < 8 || length > 64) {
    throw new RangeError('length must be a whole number from 8 to 64');
  }
  const classes = selectedClasses(options);
  if (classes.length === 0) throw new RangeError('select at least one kind of character');

  const all = classes.join('');
  const chars = classes.map((set) => pick(set, randomValues));
  while (chars.length < length) chars.push(pick(all, randomValues));

  // Fisher–Yates shuffle, so the guaranteed characters are not always first.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1, randomValues);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

export function passphrase(options = {}, randomValues) {
  const { words = 5, separator = '-', capitalize = false, addNumber = false } = options;
  if (!Number.isInteger(words) || words < 3 || words > 10) {
    throw new RangeError('words must be a whole number from 3 to 10');
  }
  const chosen = [];
  for (let i = 0; i < words; i++) {
    const word = WORDS[randomInt(WORDS.length, randomValues)];
    chosen.push(capitalize ? word[0].toUpperCase() + word.slice(1) : word);
  }
  if (addNumber) chosen[chosen.length - 1] += pick(DIGITS, randomValues);
  return chosen.join(separator);
}

export function passwordEntropyBits(options) {
  const pool = selectedClasses(options).join('').length;
  return pool === 0 ? 0 : options.length * Math.log2(pool);
}

export function passphraseEntropyBits({ words, addNumber = false }) {
  return words * Math.log2(WORDS.length) + (addNumber ? Math.log2(10) : 0);
}
