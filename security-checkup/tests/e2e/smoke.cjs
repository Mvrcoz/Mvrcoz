'use strict';
// Browser smoke test. Needs Playwright with Chromium available to `require`.
//   npm run test:e2e
// The breach API is always intercepted here; no real request leaves the machine.

const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const { startServer } = require('../../serve.cjs');

const API = 'https://api.pwnedpasswords.com/';
const SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8'; // rest of SHA-1("password") after 5BAA6
const VIEWS = ['password', 'link', 'generator', 'checkup'];

async function main() {
  const server = await startServer(path.resolve(__dirname, '../..'));
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();

  const problems = [];
  const apiCalls = [];
  let apiMode = 'found';

  page.on('pageerror', (error) => problems.push(`page error: ${error.message}`));
  page.on('dialog', (dialog) => { problems.push(`unexpected dialog: ${dialog.message()}`); dialog.dismiss(); });
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    // A failed breach lookup is logged by the browser itself; that one is expected.
    if (message.location().url.startsWith(API)) return;
    problems.push(`console error: ${message.text()}`);
  });
  page.on('request', (request) => {
    const url = request.url();
    if (url.startsWith(server.url)) return;
    if (/^https:\/\/api\.pwnedpasswords\.com\/range\/[0-9A-F]{5}$/.test(url)) return;
    problems.push(`unexpected request: ${url}`);
  });
  await context.route(`${API}**`, (route) => {
    apiCalls.push(route.request().url());
    if (apiMode === 'abort') return route.abort();
    return route.fulfill({
      status: 200,
      contentType: 'text/plain',
      headers: { 'access-control-allow-origin': '*' },
      body: `0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n${SUFFIX}:52256179\r\n`,
    });
  });

  const text = (selector) => page.locator(selector).innerText();
  const step = async (name, fn) => {
    try {
      await fn();
    } catch (error) {
      throw new Error(`step failed: ${name}\n${error.message}`);
    }
    assert.deepEqual(problems, [], `problems during: ${name}`);
    console.log(`ok - ${name}`);
  };

  try {
    await step('1 page loads on the password view', async () => {
      await page.goto(server.url);
      await page.locator('#view-password').waitFor({ state: 'visible' });
      for (const view of VIEWS.slice(1)) assert.equal(await page.locator(`#view-${view}`).isHidden(), true, view);
      assert.equal(await page.locator('#breach-button').isDisabled(), true);
    });

    await step('2 a common password is rated Very weak with a reason', async () => {
      await page.fill('#password-input', 'password');
      assert.equal(await text('#strength-label'), 'Very weak');
      assert.ok((await page.locator('#strength-warnings li').count()) > 0);
    });

    await step('3 breach lookup reports the count and sends only the prefix', async () => {
      await page.click('#breach-button');
      await page.locator('#breach-result:has-text("52,256,179")').waitFor();
      assert.deepEqual(apiCalls, [`${API}range/5BAA6`]);
    });

    await step('4 a failed lookup says so and keeps the strength result', async () => {
      apiMode = 'abort';
      await page.fill('#password-input', 'password1');
      assert.equal(await text('#breach-result'), '');
      await page.click('#breach-button');
      await page.locator('#breach-result:has-text("Couldn\'t check right now")').waitFor();
      assert.equal(await text('#strength-label'), 'Very weak');
      assert.equal(await text('#breach-button'), 'Try again');
      apiMode = 'found';
    });

    await step('5 a link with a hidden destination is Likely dangerous', async () => {
      await page.click('#tab-link');
      await page.locator('#view-link').waitFor({ state: 'visible' });
      assert.equal(await page.locator('#view-password').isHidden(), true);
      await page.fill('#link-input', 'https://paypal.com@evil.example/login');
      await page.click('#link-button');
      assert.equal(await text('#link-verdict'), 'Likely dangerous');
      assert.equal(await page.locator('#link-flags li').count(), 1);
      assert.match(await text('#link-host'), /evil\.example/);
    });

    await step('5b editing the link clears the old verdict', async () => {
      await page.fill('#link-input', 'https://www.wikipedia.org/');
      assert.equal(await page.locator('#link-result').isHidden(), true);
      await page.click('#link-button');
      assert.equal(await text('#link-verdict'), 'No red flags found');
      assert.equal(await page.getAttribute('#link-verdict', 'data-level'), 'neutral');
      await page.type('#link-input', 'x');
      assert.equal(await page.locator('#link-result').isHidden(), true);
    });

    await step('6 pasted HTML is shown as text, never run', async () => {
      await page.fill('#link-input', '<img src=x onerror=alert(1)>');
      await page.press('#link-input', 'Enter');
      assert.equal(await text('#link-verdict'), 'Not a link');
      assert.equal(await page.locator('#view-link img').count(), 0);
    });

    await step('7 generator makes passwords and passphrases', async () => {
      await page.click('#tab-generator');
      await page.click('#gen-button');
      const password = await page.inputValue('#gen-output');
      assert.equal(password.length, 20);
      await page.check('#gen-mode-passphrase');
      await page.click('#gen-button');
      const phrase = await page.inputValue('#gen-output');
      assert.ok(phrase.split('-').length >= 5, phrase);
      assert.match(await text('#gen-entropy'), /^About \d+ bits/);
      assert.doesNotMatch(await text('#gen-entropy'), /70/);
      assert.match(await text('#about'), /IP address/);
      await page.check('#gen-mode-password');
      for (const id of ['upper', 'lower', 'digits', 'symbols']) await page.uncheck(`#gen-${id}`);
      assert.equal(await page.locator('#gen-button').isDisabled(), true);
    });

    await step('8 checkup score and streak update and survive a reload', async () => {
      await page.click('#tab-checkup');
      assert.ok((await text('#daily-task')).length > 10);
      assert.equal(await text('#score-value'), '0');
      assert.equal(await page.locator('#checklist input[type=checkbox]').count(), 12);
      await page.locator('#checklist input[type=checkbox]').first().check();
      assert.equal(await text('#score-value'), '8');
      await page.click('#daily-done');
      assert.equal(await text('#streak-current'), '1');
      assert.equal(await page.locator('#daily-done').isDisabled(), true);
      await page.reload();
      await page.locator('#view-checkup').waitFor({ state: 'visible' });
      assert.equal(await text('#score-value'), '8');
      assert.equal(await text('#streak-current'), '1');
      assert.equal(await page.locator('#storage-notice').isHidden(), true);
    });

    await step('9 nothing overflows sideways on a phone', async () => {
      await page.setViewportSize({ width: 375, height: 700 });
      for (const view of VIEWS) {
        await page.click(`#tab-${view}`);
        const width = await page.evaluate(() => document.documentElement.scrollWidth);
        assert.ok(width <= 375, `${view} view is ${width}px wide`);
      }
      await page.setViewportSize({ width: 1280, height: 800 });
    });

    await step('10 arrow keys move between tabs', async () => {
      await page.click('#tab-password');
      await page.keyboard.press('ArrowRight');
      assert.equal(await page.getAttribute('#tab-link', 'aria-selected'), 'true');
      assert.equal(await page.evaluate(() => document.activeElement.id), 'tab-link');
      await page.keyboard.press('ArrowLeft');
      await page.keyboard.press('ArrowLeft');
      assert.equal(await page.getAttribute('#tab-checkup', 'aria-selected'), 'true');
    });

    await step('11 works offline after the first visit', async () => {
      const ready = await page.evaluate(() => Promise.race([
        navigator.serviceWorker.ready.then(() => true),
        new Promise((resolve) => setTimeout(() => resolve(false), 10000)),
      ]));
      assert.equal(ready, true, 'service worker did not become ready');
      await page.reload();
      assert.equal(await page.evaluate(() => navigator.serviceWorker.controller !== null), true);
      apiMode = 'abort';
      await context.setOffline(true);
      await page.goto(server.url);
      await page.locator('#view-password').waitFor({ state: 'visible' });
      await page.fill('#password-input', 'password');
      assert.equal(await text('#strength-label'), 'Very weak');
      await page.click('#breach-button');
      await page.locator('#breach-result:has-text("Couldn\'t check right now")').waitFor();
      await page.click('#tab-link');
      await page.fill('#link-input', 'http://example.com/');
      await page.click('#link-button');
      assert.equal(await text('#link-verdict'), 'Be careful');
      await page.click('#tab-generator');
      await page.click('#gen-button');
      assert.equal((await page.inputValue('#gen-output')).length, 20);
      await context.setOffline(false);
    });

    console.log('\nAll smoke steps passed.');
  } finally {
    await browser.close();
    await server.close();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
