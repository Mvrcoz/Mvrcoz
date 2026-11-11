'use strict';
// Tiny static file server for running Security Checkup locally.
//   node serve.cjs [port]      (default 8080)
// It listens on this computer only (127.0.0.1) and has no dependencies.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.cjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

// Maps a request path to a file inside `root`, or null if it must not be served.
function resolveFile(root, requestUrl) {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(requestUrl, 'http://localhost').pathname);
  } catch {
    return null;
  }
  if (pathname.includes('\0') || pathname.includes('\\')) return null;
  if (pathname.endsWith('/')) pathname += 'index.html';
  const segments = pathname.split('/').filter(Boolean);
  if (segments.some((segment) => segment.startsWith('.'))) return null;
  const file = path.resolve(root, ...segments);
  if (!file.startsWith(root + path.sep)) return null;
  return file;
}

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', 'X-Content-Type-Options': 'nosniff' });
  res.end(body);
}

function startServer(rootDir, port = 0) {
  const root = path.resolve(rootDir);
  const server = http.createServer((req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
    const file = resolveFile(root, req.url);
    if (!file) return send(res, 404, 'Not found');
    fs.stat(file, (error, stats) => {
      if (error || !stats.isFile()) return send(res, 404, 'Not found');
      res.writeHead(200, {
        'Content-Type': TYPES[path.extname(file).toLowerCase()] ?? 'application/octet-stream',
        'Content-Length': stats.size,
        'Cache-Control': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
      });
      if (req.method === 'HEAD') return res.end();
      fs.createReadStream(file).pipe(res);
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      resolve({
        url: `http://127.0.0.1:${server.address().port}/`,
        close: () => new Promise((done) => {
          server.closeAllConnections();
          server.close(() => done());
        }),
      });
    });
  });
}

module.exports = { startServer, resolveFile };

if (require.main === module) {
  const port = Number(process.argv[2] ?? 8080);
  startServer(__dirname, port).then(
    ({ url }) => console.log(`Security Checkup is running at ${url}\nPress Ctrl+C to stop.`),
    (error) => { console.error(`Could not start: ${error.message}`); process.exit(1); },
  );
}
