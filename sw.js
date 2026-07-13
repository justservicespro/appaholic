// AppAholic Service Worker — v4 (subscriptions + pricing)
const CACHE_NAME    = 'appaholic-v4';
const STATIC_CACHE  = 'appaholic-static-v4';
const DYNAMIC_CACHE = 'appaholic-dynamic-v4';

const PRE_CACHE = [
  '/',
  '/marketplace',
  '/pricing',
  '/auth',
  '/request',
  '/contact',
  '/offline',
  '/manifest.json',
  '/assets/theme.css',
  '/assets/app.js',
];

const PAGE_ROUTES = ['/', '/marketplace', '/pricing', '/auth', '/dashboard', '/about', '/privacy', '/terms', '/request', '/contact', '/quicknote', '/invoicekit'];

self.addEventListener('install', function (e) {
  self.skipWaiting();
  e.waitUntil(
    caches.open(STATIC_CACHE).then(function (cache) {
      return cache.addAll(PRE_CACHE).catch(function () { /* tolerate individual failures */ });
    })
  );
});

self.addEventListener('activate', function (e) {
  e.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.filter(function (k) { return k !== STATIC_CACHE && k !== DYNAMIC_CACHE; })
            .map(function (k) { return caches.delete(k); })
      );
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (e) {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return; // never intercept cross-origin (API) requests
  if (e.request.method !== 'GET') return;

  const isPage = PAGE_ROUTES.some(function (r) { return url.pathname === r || url.pathname === r + '.html'; });

  if (isPage) {
    // Network-first for pages, fallback to cache, then offline page.
    e.respondWith(
      fetch(e.request).then(function (res) {
        const clone = res.clone();
        caches.open(DYNAMIC_CACHE).then(function (c) { c.put(e.request, clone); });
        return res;
      }).catch(function () {
        return caches.match(e.request).then(function (cached) { return cached || caches.match('/offline'); });
      })
    );
    return;
  }

  // Cache-first for static assets.
  e.respondWith(
    caches.match(e.request).then(function (cached) {
      if (cached) return cached;
      return fetch(e.request).then(function (res) {
        if (res && res.status === 200) {
          const clone = res.clone();
          caches.open(STATIC_CACHE).then(function (c) { c.put(e.request, clone); });
        }
        return res;
      }).catch(function () { /* offline and not cached — let it fail naturally for non-page assets */ });
    })
  );
});
