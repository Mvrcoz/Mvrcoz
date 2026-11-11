import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const { startServer, resolveFile } = createRequire(import.meta.url)('../serve.cjs');
const root = path.resolve(fileURLToPath(new URL('../', import.meta.url)));

test('hidden files, encoded traversal, and malformed paths are refused', () => {
  for (const bad of ['/..%2f..%2fetc/passwd', '/js/..%2f..%2f..%2fetc%2fpasswd', '/.gitignore', '/.git/config',
    '/js/%00.js', '/js/%5c..%5c..%5cx', '/%E0%A4%A'])
    assert.equal(resolveFile(root, bad), null, bad);
});
test('dot segments can never resolve outside the folder', () => {
  for (const tricky of ['/../README.md', '/%2e%2e/README.md', '/js/../../README.md', '/../../../../etc/passwd', '/js\\..\\..\\x']) {
    const file = resolveFile(root, tricky);
    assert.ok(file === null || file.startsWith(root + path.sep), `${tricky} -> ${file}`);
  }
});
test('ordinary paths resolve inside the folder', () => {
  assert.equal(resolveFile(root, '/'), path.join(root, 'index.html'));
  assert.equal(resolveFile(root, '/js/app.js?x=1'), path.join(root, 'js', 'app.js'));
});
test('serves files with a content type, and refuses other methods', async () => {
  const server = await startServer(root);
  try {
    const ok = await fetch(server.url + 'package.json');
    assert.equal(ok.status, 200);
    assert.match(ok.headers.get('content-type'), /^application\/json/);
    assert.equal(ok.headers.get('x-content-type-options'), 'nosniff');
    assert.equal((await fetch(server.url + 'nope.txt')).status, 404);
    assert.equal((await fetch(server.url + '.gitignore')).status, 404);
    assert.equal((await fetch(server.url + 'package.json', { method: 'POST' })).status, 405);
  } finally {
    await server.close();
  }
});
