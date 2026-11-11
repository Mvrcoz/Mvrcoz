# Security Checkup

A private, everyday security tool that runs entirely in your browser.

"Security Checkup" is a working name. Choose a final name and check it for trademark conflicts before launching.

## What it does

| Tool | What you get |
|---|---|
| **Password** | A strength estimate as you type, and an optional check against passwords exposed in known data breaches |
| **Link** | Plain-English red flags for a link you are unsure about, without opening it |
| **Generate** | Strong random passwords and memorable passphrases |
| **Daily** | One five-minute security task a day, a streak, and a score from a 12-item habits checklist |

It installs like an app on phones and computers and, after the first visit, works offline (everything except the breach check).

## Privacy

- No accounts, no analytics, no ads, no cookies, no third-party scripts.
- Passwords, links, and generated values are never saved or sent anywhere.
- The only thing that ever leaves the device: when you press **Check for breaches**, the first 5 characters of the SHA-1 hash of your password are sent to the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) Pwned Passwords service. The rest of the comparison happens on your device. As with any web request, that service can also see the visitor's IP address and the address the app is hosted at.
- Daily progress is stored in the browser's local storage on that device only.

## Run it locally

You need [Node.js](https://nodejs.org) 22 or newer. There is nothing to install.

```bash
cd security-checkup
npm start
```

Open the address it prints (http://127.0.0.1:8080/). To use another port: `node serve.cjs 3000`.

Opening `index.html` directly from the file manager will not work; browsers only load this kind of app from a web address.

## Tests

```bash
npm test          # unit tests for all the logic, no dependencies
npm run test:e2e  # real-browser test of every tool, including offline
```

`npm run test:e2e` needs [Playwright](https://playwright.dev) with Chromium installed where Node can find it. It is not listed as a dependency, so the app itself stays dependency-free.

### One check to do yourself

The browser test replaces the breach service with a stand-in, and the environment this was built in could not reach the real service. So the live lookup has **not** been tested end to end. To confirm it:

1. Run the app and open the Password tab.
2. Type `password` and press **Check for breaches**.
3. You should see that it has appeared in breaches tens of millions of times.

If you instead see "Couldn't check right now", the request is being blocked somewhere (an ad blocker, a firewall, or a change at the service).

It has also only been run in Chromium. The code uses long-standing web standards, but give it a quick try in Firefox and Safari before launching.

## Publishing

The app is a folder of static files, so any static host works (GitHub Pages, Netlify, Cloudflare Pages, and similar). The host must serve it over HTTPS, or installing and offline use will not work.

For GitHub Pages, the usual route is: merge this folder into your default branch, then in the repository's **Settings → Pages** choose to deploy from that branch. The app is then served under the repository's Pages address in the `security-checkup/` path. GitHub changes these screens from time to time, so follow [their current guide](https://docs.github.com/en/pages).

**After every change to the app**, raise the version number in the `CACHE` line at the top of `sw.js` (for example `security-checkup-v1` to `security-checkup-v2`). Without that, people who have already visited keep seeing the old version. If you add or remove a file in `js/` or `icons/`, update the `PRECACHE` list there too; `npm test` fails if the list and the folder disagree.

## Known limits

- **Password strength is an estimate.** It is a home-made scoring method, not a research-grade one. It can rate a password too generously, especially one built from personal details it knows nothing about.
- **"Not found in known breaches" is not "safe".** It only means the password is not on that list.
- **The link checker reads the address only.** It cannot see what is on the site and does not know which sites are malicious. "No red flags found" never means "safe".
- **The brand-impersonation rules use short built-in lists** of brand names, free hosting services, and a simple rule for country domains such as `co.uk`. They will miss brands not on the list, lookalike spellings such as `paypa1`, short brand names glued to another word (`uspstracking`), and impersonation on a country ending (`paypal.com.ru`).
- **It can raise a false alarm on a genuine site.** Any site whose name contains accented or non-English letters is reported as "Likely dangerous", because those characters are also used to imitate ordinary letters. A brand name on a free hosting service is flagged even when it is genuine (`google.github.io`).
- **Clickjacking protection needs the host.** The `frame-ancestors` protection cannot be set from inside the page; it needs a response header, which basic static hosts such as GitHub Pages do not let you set.
- **No response padding.** Have I Been Pwned offers an optional `Add-Padding` header that hides the size of the reply. It is not sent, because it could not be tested from the build environment and a refusal would break the lookup.

## How the code is laid out

```
index.html, styles.css   the page
js/app.js                connects the page to the logic (the only file that touches the page)
js/strength.js           password strength estimate
js/breach.js             hashing and the breach lookup
js/linkcheck.js          link red-flag rules
js/generator.js          password and passphrase generation
js/wordlist.js           the EFF word list
js/checkup.js            daily task, streak, checklist score
js/storage.js            saved progress
js/features.js           the single place that decides what is free or paid
sw.js, manifest.webmanifest, icons/   install and offline support
serve.cjs                local server for `npm start`
tests/                   unit tests and the browser test
docs/                    design spec and implementation plan
```

### Adding a paid tier later

Everything is free in this version. `js/features.js` is the one place the app asks whether a feature is allowed, so a paid tier starts there. Bear in mind that anything enforced only in the browser can be bypassed by a determined user; that is usually acceptable for a low-priced unlock, but it is a business decision to make knowingly.

## Credits and licences

- Breach data: [Have I Been Pwned](https://haveibeenpwned.com/) Pwned Passwords, by Troy Hunt. The service states there are no licensing or attribution requirements for this API; credit is given anyway.
- Passphrase words: the [EFF Large Wordlist for Passphrases](https://www.eff.org/dice), © Electronic Frontier Foundation, used under the [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) licence, per EFF's site-wide copyright policy. The list was taken from the npm package `diceware-wordlist-en-eff` 1.0.1 and reformatted; it was not compared byte-for-byte against EFF's own file.
- No licence has been chosen for this project's own code yet. Until the owner adds one, others have no permission to reuse it.
