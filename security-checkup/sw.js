// Service worker: keeps a copy of the app's own files so it opens offline.
// It never touches requests to other sites, so the breach lookup is never
// cached or intercepted.
//
// When any app file changes, raise the number in CACHE so browsers fetch the
// new version. tests/sw.test.js checks PRECACHE against the files on disk.

const CACHE = 'security-checkup-v1';
const PRECACHE = [
  './',
  'index.html',
  'styles.css',
  'manifest.webmanifest',
  'icons/icon.svg',
  'icons/icon-192.png',
  'icons/icon-512.png',
  'js/app.js',
  'js/breach.js',
  'js/checkup.js',
  'js/features.js',
  'js/generator.js',
  'js/linkcheck.js',
  'js/storage.js',
  'js/strength.js',
  'js/wordlist.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE)
      .then((cache) => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) => Promise.all(names.filter((name) => name !== CACHE).map((name) => caches.delete(name))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;
  if (new URL(request.url).origin !== self.location.origin) return;

  event.respondWith(
    caches.open(CACHE)
      .then((cache) => cache.match(request, { ignoreSearch: true }))
      .then((cached) => cached ?? fetch(request)),
  );
});
