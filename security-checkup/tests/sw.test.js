import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const sw = readFileSync(new URL('sw.js', root), 'utf8');
const precache = JSON.parse(sw.match(/const PRECACHE = (\[[^\]]*\]);/)[1].replaceAll("'", '"'));
const list = (dir) => readdirSync(new URL(dir, root)).map((f) => `${dir}${f}`);

test('every shipped file is precached, and nothing else', () => {
  const expected = ['./', 'index.html', 'styles.css', 'manifest.webmanifest', ...list('js/'), ...list('icons/')];
  assert.deepEqual([...precache].sort(), expected.sort());
});
test('cache name is versioned', () => assert.match(sw, /const CACHE = 'security-checkup-v\d+';/));
test('manifest is installable', () => {
  const m = JSON.parse(readFileSync(new URL('manifest.webmanifest', root), 'utf8'));
  assert.equal(m.display, 'standalone');
  assert.equal(m.start_url, './');
  assert.deepEqual(m.icons.map((i) => i.sizes).sort(), ['192x192', '512x512']);
  assert.ok(m.name && m.short_name && m.theme_color && m.background_color);
});
