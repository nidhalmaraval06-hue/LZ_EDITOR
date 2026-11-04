'use strict';
// Never cache authenticated HTML or API responses. This avoids stale installed-PWA auth pages.
const CACHE = 'lz-editors-static-v3';
const STATIC = ['/manifest.webmanifest', '/logo.png'];
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(STATIC)).catch(() => {}));
  self.skipWaiting();
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', event => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;
  if (req.mode === 'navigate' || /\.html$/.test(url.pathname) || url.pathname === '/') {
    event.respondWith(fetch(req, {cache:'no-store'}));
    return;
  }
  if (STATIC.includes(url.pathname)) {
    event.respondWith(caches.match(req).then(hit => hit || fetch(req)));
  }
});
