/**
 * AppAholic Service Worker
 * Caches HTML pages and assets for offline use.
 * Strategy: Cache-first for static assets, Network-first for pages.
 */

const CACHE_NAME    = 'appaholic-v1';
const STATIC_CACHE  = 'appaholic-static-v1';
const DYNAMIC_CACHE = 'appaholic-dynamic-v1';

// Pages and assets to pre-cache on install
const PRE_CACHE = [
  '/',
  '/marketplace',
  '/auth',
  '/about',
  '/offline',
  '/manifest.json',
];

// Pages — network first, fallback to cache
const PAGE_ROUTES = ['/', '/marketplace', '/auth', '/dashboard', '/about', '/privacy', '/terms', '/admin', '/invoicekit'];

// ── INSTALL ───────────────────────────────────────────────────
self.addEventListener('install', function(e){
  e.waitUntil(
    caches.open(STATIC_CACHE).then(function(cache){
      return cache.addAll(PRE_CACHE);
    }).catch(function(err){
      console.warn('Pre-cache failed (some URLs may not exist yet):', err.message);
    })
  );
  self.skipWaiting();
});

// ── ACTIVATE ──────────────────────────────────────────────────
self.addEventListener('activate', function(e){
  e.waitUntil(
    caches.keys().then(function(keys){
      return Promise.all(
        keys.filter(function(k){ return k !== STATIC_CACHE && k !== DYNAMIC_CACHE; })
            .map(function(k){ return caches.delete(k); })
      );
    })
  );
  self.clients.claim();
});

// ── FETCH ─────────────────────────────────────────────────────
self.addEventListener('fetch', function(e){
  var url = new URL(e.request.url);

  // Skip non-GET and cross-origin (API calls etc.)
  if(e.request.method !== 'GET') return;
  if(url.origin !== self.location.origin) return;

  // Skip Vercel internals
  if(url.pathname.startsWith('/_next') || url.pathname.startsWith('/_vercel')) return;

  var isPage = PAGE_ROUTES.some(function(r){ return url.pathname === r || url.pathname === r + '.html'; });

  if(isPage){
    // Network-first for HTML pages
    e.respondWith(
      fetch(e.request)
        .then(function(res){
          var clone = res.clone();
          caches.open(DYNAMIC_CACHE).then(function(c){ c.put(e.request, clone); });
          return res;
        })
        .catch(function(){
          return caches.match(e.request)
            .then(function(cached){ return cached || caches.match('/offline'); });
        })
    );
  } else {
    // Cache-first for static assets (fonts, images, icons)
    e.respondWith(
      caches.match(e.request).then(function(cached){
        if(cached) return cached;
        return fetch(e.request).then(function(res){
          if(res && res.status === 200){
            var clone = res.clone();
            caches.open(STATIC_CACHE).then(function(c){ c.put(e.request, clone); });
          }
          return res;
        });
      })
    );
  }
});

// ── BACKGROUND SYNC (app request form retry) ──────────────────
self.addEventListener('sync', function(e){
  if(e.tag === 'sync-app-request'){
    e.waitUntil(syncAppRequests());
  }
});

async function syncAppRequests(){
  try {
    var cache = await caches.open('appaholic-pending');
    var keys  = await cache.keys();
    for(var req of keys){
      var pending = await cache.match(req);
      var data    = await pending.json();
      var res = await fetch('https://api.appaholic.justservices.pro/api/request-app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      if(res.ok) await cache.delete(req);
    }
  } catch(err){
    console.warn('Background sync failed:', err);
  }
}

// ── PUSH NOTIFICATIONS (future) ───────────────────────────────
self.addEventListener('push', function(e){
  if(!e.data) return;
  var data = e.data.json();
  e.waitUntil(
    self.registration.showNotification(data.title || 'AppAholic', {
      body:    data.body    || 'New update from AppAholic',
      icon:    '/icons/icon-192.png',
      badge:   '/icons/icon-72.png',
      vibrate: [100, 50, 100],
      data:    { url: data.url || '/' },
      actions: [
        { action: 'open',    title: 'Open App' },
        { action: 'dismiss', title: 'Dismiss'  }
      ]
    })
  );
});

self.addEventListener('notificationclick', function(e){
  e.notification.close();
  if(e.action === 'dismiss') return;
  var target = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(list){
      for(var c of list){
        if(c.url === target && 'focus' in c) return c.focus();
      }
      if(clients.openWindow) return clients.openWindow(target);
    })
  );
});
