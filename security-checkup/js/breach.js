// Breach lookup against Have I Been Pwned's Pwned Passwords range API.
// The password is hashed here; only the first 5 characters of the hash are
// sent, and the matching is done on this device (k-anonymity).

export const RANGE_URL = 'https://api.pwnedpasswords.com/range/';

const HASH_LINE = /^([0-9A-F]{35}):(\d+)$/i;

// SHA-1 of the UTF-8 bytes of `text`, as 40 upper-case hex characters.
export async function sha1Hex(text) {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Resolves to { status: 'found', count }, { status: 'clear' } or
// { status: 'unavailable' }. Never rejects, and never reports 'clear' unless
// the reply really was a list of hashes.
export async function checkBreach(password, fetchImpl, { timeoutMs = 8000 } = {}) {
  if (password === '') return { status: 'unavailable' };

  // Hashing needs a secure page (https or localhost). Without it, say so
  // rather than leave the caller waiting.
  let hash;
  try {
    hash = await sha1Hex(password);
  } catch {
    return { status: 'unavailable' };
  }
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let body;
  try {
    const response = await fetchImpl(RANGE_URL + prefix, { signal: controller.signal });
    if (!response.ok) return { status: 'unavailable' };
    body = await response.text();
  } catch {
    return { status: 'unavailable' };
  } finally {
    clearTimeout(timer);
  }

  // Every non-blank line must be a hash line. Anything else (a Wi-Fi sign-in
  // page, an error page) means the reply cannot be trusted to say "clear".
  let validLines = 0;
  let count = 0;
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '') continue;
    const match = HASH_LINE.exec(line);
    if (!match) return { status: 'unavailable' };
    validLines++;
    if (match[1].toUpperCase() === suffix) count = Number(match[2]);
  }
  if (validLines === 0) return { status: 'unavailable' };
  return count > 0 ? { status: 'found', count } : { status: 'clear' };
}
