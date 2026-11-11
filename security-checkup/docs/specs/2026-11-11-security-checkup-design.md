# Security Checkup — Design Spec

Date: 2026-11-11
Status: approved; sections 5.1, 5.2, 5.3 and 5.9 revised after the final code review

## 1. Purpose

A free, private, everyday security tool for non-technical people. It answers four
questions someone can have on any given day:

1. Is this password any good, and has it leaked?
2. Is this link suspicious?
3. Can you give me a strong password or passphrase?
4. What one thing should I do today to be safer?

Business goal: a product that costs close to nothing to run, so that a low-priced
paid tier can be profitable with few customers. The pricing model is deliberately
undecided; version 1 ships with everything free and one seam where paid features
plug in later.

"Security Checkup" is a working name. The owner picks the final name and checks it
for trademark conflicts before launch.

## 2. Decisions already made

| Decision | Choice |
|---|---|
| Product | Personal security checkup web app |
| Revenue model | Decide later; build the free core with a plug-in point |
| Code location | `security-checkup/` in this repo; profile `README.md` untouched |
| Architecture | Static web app: plain HTML, CSS, JavaScript modules. No framework, no build step, no runtime dependencies |

## 3. Scope

### In version 1

- Password check: local strength estimate plus breach lookup
- Link checker: offline heuristic red flags
- Generator: random passwords and passphrases
- Daily checkup: daily task, streak, checklist score
- Installable (PWA) and usable offline, except the breach lookup
- Automated tests for all logic; browser smoke test

### Not in version 1

- Payments, licence keys, accounts, sign-in
- Email-address breach search (needs a paid Have I Been Pwned key and a server to hide it)
- Deployment. Publishing is the owner's decision; the README will list the steps
- Analytics, ads, translations

## 4. Architecture

One HTML page with four views, switched by tabs (URL hash: `#password`, `#link`,
`#generator`, `#checkup`). Logic lives in small modules with no DOM access, so each
can be tested in Node. One module, `app.js`, connects them to the page.

```
security-checkup/
  index.html              page shell, four views
  styles.css              all styling (light and dark)
  manifest.webmanifest    install metadata
  sw.js                   service worker: offline app shell
  icons/                  app icons
  js/
    app.js                DOM wiring and tab navigation (only module that touches the DOM)
    strength.js           password strength estimate
    breach.js             SHA-1 hashing and Pwned Passwords range lookup
    linkcheck.js          URL red-flag rules
    generator.js          password and passphrase generation
    wordlist.js           EFF large word list (7,776 words)
    checkup.js            daily task, streak, and score rules
    storage.js            versioned localStorage read/write
    features.js           the paid-feature seam
  tests/
    *.test.js             unit tests, run with `node --test`
    e2e/smoke.mjs         browser smoke test (Playwright)
  package.json            `"type": "module"`, test script, zero dependencies
  README.md               what it is, how to run, test, and publish
  docs/specs/             this document
```

Dependency rule: logic modules import nothing from `app.js` and never touch
`document`, `window`, or `localStorage` directly. Randomness, `fetch`, the clock,
and storage are passed in as parameters, which is what makes them testable.

## 5. Components

### 5.1 `strength.js` — password strength estimate

`estimateStrength(password)` returns
`{ score, label, warnings, suggestions }`.

- `score` is 0–4, mapped to labels Very weak, Weak, Fair, Strong, Very strong.
- Method: read the password left to right and split it into the pieces a
  guessing tool tries first. Each piece costs a small fixed number of guesses
  however long it is; whatever is left over is scored by length and variety.
  - a very common password (a bundled list of about 110, checked as typed and
    after undoing letter swaps such as `@`→`a`, `0`→`o`), anywhere in the text
  - an ordinary word of four or more letters (the generator's word list)
  - a run along the alphabet, digits, a keyboard row or a keyboard column
    (`abcd`, `4321`, `qwerty`, `1qaz2wsx`), including common non-US layouts
  - three or more of the same character in a row
  - a year (`19xx`, `20xx`)
- Something typed two or more times (`passwordpassword`) is scored as one copy.
- Caps: digits only → at most Weak; fewer than 8 characters → Very weak; fewer
  than 12 → at most Fair; exactly a common password → Very weak; a common
  password with characters added at the ends → at most Weak.
- `warnings` say what is wrong; `suggestions` say what to do. Plain English.
- The UI labels the result an estimate. It makes no claim about time to crack.

This is a self-written heuristic, not a research-grade estimator. Its word list
is a few thousand words, not a full dictionary, so it can still rate a password
built from names, places or short words too generously (`Liverpool1892`). That
is one reason the breach lookup exists alongside it.

### 5.2 `breach.js` — breach lookup

- `sha1Hex(text)` hashes with the Web Crypto API (`crypto.subtle.digest('SHA-1', …)`),
  available in browsers and in Node 22.
- `checkBreach(password, fetchImpl)`:
  1. Hash the password; uppercase hex.
  2. Send only the first 5 characters: `GET https://api.pwnedpasswords.com/range/{prefix}`.
  3. Search the response lines (`SUFFIX:COUNT`) for the remaining 35 characters.
     Every non-blank line must have that shape; if any does not, the reply is
     treated as untrustworthy and the result is `unavailable`, never `clear`.
  4. Return `{ status: 'found', count }`, `{ status: 'clear' }`, or
     `{ status: 'unavailable' }` on network error, non-200 response, or an 8-second timeout.
- Runs only when the user presses "Check for breaches", never per keystroke.
- Confirmed from the Have I Been Pwned API documentation on 2026-11-11: this
  endpoint needs no API key, has no rate limit, accepts browser requests from any
  origin, and has no licence or attribution requirement. Attribution is included anyway.
- The optional `Add-Padding` request header is **not** sent in version 1. It is a
  non-standard header, so browsers first ask the server for permission to send it,
  and that could not be tested from the build environment (its network policy
  blocks the API host). If the server refused, the whole lookup would fail. Adding
  padding is a follow-up once it has been tested in a real browser.

### 5.3 `linkcheck.js` — link red flags

`analyzeUrl(input)` returns `{ valid, host, flags, verdict }`, where each flag is
`{ id, severity, message }` and severity is `high`, `medium`, or `low`. No network access.
A link pasted without `https://` in front is read as if it had it.

| Rule | Severity |
|---|---|
| Not a web link (`javascript:`, `data:`, `file:` and similar) | high |
| Username or password part before the host (`https://bank.com@evil.example`) | high |
| Host is a raw public IP address | high |
| Another site's ending (`com`, `net`, `org`) sits in front of the real domain (`linkedin.com.evil.example`) | high |
| Host uses lookalike encoding (`xn--` label or non-ASCII characters) | high |
| A well-known brand name appears in the host, but the address is not one that brand normally uses (a different site, an unusual ending such as `paypal.xyz`, or a free hosting service) | high |
| A brand name of six or more letters glued to another word (`paypalsecure.com`), other than a short list of known brand-owned domains | medium |
| Plain `http://`, not `https://` | medium |
| Three or more subdomains in front of the site's own name (deep nesting) | medium |
| Path ends in an executable or installer type (`.exe`, `.scr`, `.msi`, `.apk`, `.bat`, `.cmd`, `.vbs`, `.jar`) | medium |
| Known link shortener: the real destination is hidden | low |
| Address on a private or home network (`192.168.x.x`, `10.x.x.x` and similar), such as a router page. Replaces the IP-address and no-HTTPS flags | low |
| Site is on a free hosting service where anyone can publish | low |
| Non-standard port | low |
| Pressure words in the site's main domain name (`login`, `verify`, `secure`, `account`, `update`, `signin`). Subdomains are not checked, so genuine pages such as `accounts.google.com` stay clean | low |
| Three or more hyphens in the host (lookalike-encoded labels excluded), or URL longer than 200 characters | low |

Verdicts: any high flag → "Likely dangerous"; any medium → "Be careful"; only low
→ "Minor concerns"; none → "No red flags found", shown in a neutral colour, not
green. Email, phone and text links (`mailto:`, `tel:`, `sms:`), bare email
addresses and bare numbers are reported as "Not a link". A verdict is hidden as
soon as the text in the box changes.

Limits, stated in the UI: this checks how a link is written, not what is at the
other end. "No red flags found" never means "safe". The brand rule uses a short
built-in list of brands and of two-part country suffixes (`co.uk`, `com.au`, …)
rather than the full public suffix list, so it will miss some cases and can
misjudge unusual domains.

### 5.4 `generator.js` — passwords and passphrases

- `randomPassword({ length, upper, lower, digits, symbols }, randomValues)` —
  length 8–64 (default 20); at least one character from every selected class;
  rejects a request with no class selected.
- `passphrase({ words, separator, capitalize, addNumber }, randomValues)` —
  3–10 words (default 5) from the EFF large word list.
- Both use `crypto.getRandomValues` with rejection sampling, so every character
  or word is equally likely. `Math.random` is never used.
- `entropyBits(...)` reports the strength of the chosen settings (for example
  5 words × log2(7776) ≈ 64.6 bits).
- Generated values are shown with a copy button and are never stored.

Word list: the EFF large word list, 7,776 words. EFF's copyright policy
(checked 2026-11-11) releases original EFF material under Creative Commons
Attribution 4.0 unless noted otherwise; the word list page itself does not restate
a licence, so this relies on the site-wide policy. Attribution goes in the README
and the app's About text. The list is extracted once from the npm package
`diceware-wordlist-en-eff` (the build environment cannot reach eff.org) into
`js/wordlist.js`; a test asserts exactly 7,776 unique lowercase words. The npm
package is a one-time source, not a dependency.

### 5.5 `checkup.js` — daily checkup

- **Checklist**: about 12 lasting habits (two-factor on email, password manager in
  use, automatic updates on, screen lock, backups, and so on). Score = share of
  items ticked, shown as 0–100.
- **Daily task**: about 30 small tasks ("Review which apps can see your location").
  `taskForDate(date)` picks one deterministically from the local calendar date, so
  it is the same all day and changes at local midnight.
- **Streak**: `completeToday(state, today)` returns a new state. Done yesterday →
  streak + 1; already done today → unchanged; otherwise → streak restarts at 1.
  Best streak is kept.
- All functions are pure: state and date in, new state out.

### 5.6 `storage.js` — saved state

One localStorage key holding
`{ version: 1, checklist: { [id]: true }, lastDoneDate, streak, bestStreak }`.
Missing, corrupt, or unknown-version data falls back to a fresh state without
throwing. If storage is unavailable (private browsing), the app still works for
the session and says progress will not be saved. Passwords, links, and generated
values are never written to storage.

### 5.7 `features.js` — the paid-feature seam

`hasFeature(id)` is the only place the app asks whether something is allowed. In
version 1 every feature is tagged `free` and it always returns `true`. A later paid
tier changes this one module. No payment code, licence logic, or upsell UI ships
in version 1.

### 5.8 `app.js`, `index.html`, `styles.css` — interface

- Mobile-first layout, light and dark themes following the device setting.
- Every input has a visible label; results are announced to screen readers
  (`aria-live`); everything is operable by keyboard; text meets WCAG AA contrast.
- User-supplied text is only ever inserted with `textContent`, never as HTML.
- A short About section: what leaves the device (only the 5-character hash
  prefix), the limits of each tool, and credits (Have I Been Pwned, EFF).

### 5.9 `sw.js` and `manifest.webmanifest` — install and offline

- The service worker caches the app's own files under a versioned cache name and
  serves them cache-first; old caches are deleted on activation.
- Requests to other origins (the breach API) are never cached or intercepted.
- On update it deletes only its own old caches (names starting `security-checkup-`),
  because other apps can share the same web address.
- Service workers require HTTPS or `localhost`; opening `index.html` straight from
  disk will not work. The README says how to run a local server.

## 6. Security and privacy

- No accounts, analytics, cookies, third-party scripts, or fonts loaded from elsewhere.
- Content Security Policy set in a `<meta>` tag:
  `default-src 'self'; connect-src https://api.pwnedpasswords.com; img-src 'self' data:; base-uri 'none'; form-action 'none'`.
  No inline scripts or styles.
- Password fields use `autocomplete="off"`; values live only in memory and are
  never logged.
- Known limit: protection against the page being embedded in another site
  (`frame-ancestors`) cannot be set from a `<meta>` tag and needs a response header
  from the host. Basic static hosts such as GitHub Pages do not let you set it.
  This is recorded as a hosting consideration, not solved in version 1.

## 7. Error handling

| Situation | Behaviour |
|---|---|
| Breach lookup offline, slow, or erroring | "Couldn't check right now" with a retry button; the strength result stays visible |
| Empty input | Result area cleared; no error shown |
| Text that is not a link | "That doesn't look like a web link", with a hint to paste the full address |
| No character class selected in the generator | Generate button disabled, with an explanation |
| Clipboard copy refused by the browser | Message asking the user to select and copy manually |
| Saved data corrupt or storage blocked | Fresh state; notice that progress cannot be saved |

## 8. Testing

- **Unit tests** (`node --test`, Node 22, no dependencies) for `strength`, `breach`
  (with a stubbed `fetch`, including found / clear / error / timeout),
  `linkcheck` (one test per rule plus clean URLs), `generator` (with a
  deterministic random source; class guarantees; range limits; uniform sampling),
  `checkup` (date rollover, streak rules), `storage` (corrupt and missing data),
  and the word-list count.
- **Browser smoke test** with Playwright against a local server: each view loads,
  each tool produces a result, the checklist survives a reload, and the breach
  lookup works against a mocked response.
- **Not verifiable from the build environment:** a live call to the Pwned
  Passwords API (blocked by this environment's network policy). The owner
  confirms it once in a real browser; the README lists the test password to use.

## 9. Success criteria

1. All four tools work at phone and desktop widths. This is verified in Chromium
   during the build (the only browser available there); the code uses only
   long-standing web standards, and the owner spot-checks Firefox and Safari.
2. `node --test` passes with every logic module covered.
3. With the network off, everything except the breach lookup still works after the first visit.
4. Browser network inspection shows exactly one kind of outbound request: the 5-character range lookup.
5. The profile `README.md` is unchanged.

## 10. After version 1

- Choose the revenue model and implement it behind `features.js`.
- Publish (GitHub Pages or another static host) and consider moving to a dedicated repository.
- Test and enable `Add-Padding`.
- Replace the brand rule's short lists with the public suffix list.
