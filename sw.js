'use strict';
// Network-first for HTML/auth pages so the installed app does not reuse stale login state.
const CACHE = 'lz-editors-static-v1';
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
  if (req.mode === 'navigate' || /\.html$/.test(url.pathname)) {
    event.respondWith(fetch(req).catch(() => caches.match(req).then(hit => hit || caches.match('/login-dashboard.html'))));
    return;
  }
  if (STATIC.includes(url.pathname)) {
    event.respondWith(caches.match(req).then(hit => hit || fetch(req)));
  }
});
