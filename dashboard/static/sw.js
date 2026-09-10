// OptiGate dashboard service worker.
//
// Served at /sw.js (not /static/sw.js -- see the dedicated Flask route in
// dashboard.py) so its default scope is the whole app, not just /static/.
//
// This exists to satisfy PWA installability (a registered service worker
// with a fetch handler), not to provide real offline use: this is an admin
// tool that approves/blocks a child's actual internet access, so serving a
// stale cached page while "offline" would be actively misleading, not a
// convenience. Every dashboard page and every form submission always goes
// to the network, no exceptions.
//
// Our own static assets (CSS/JS/icons) are network-FIRST, not cache-first:
// this app's CSS and JS change as it's developed/redeployed, and a
// cache-first strategy silently served a stale app.css during development
// (caught by hand, not by a test -- there's no automated check for "does
// the deployed CSS match what's on disk"). Network-first always fetches
// the current version when online (the normal case for a LAN admin tool)
// and only falls back to whatever's cached if the network request itself
// fails, so there's no scenario where a real update goes unseen while the
// network is actually up.
// Bumped v2 -> v3 (2026-09-10): force every browser to fetch this file,
// install this worker (skipWaiting below makes it active immediately),
// and -- via the activate handler -- delete every older cache. Some
// browsers were still running a much earlier revision of this worker
// that cache-first'd whole PAGES, so a stale /report (missing a column
// that has in fact always been there) survived even Ctrl+Shift+R: the
// old worker kept serving its own cache and stayed the active worker
// until every tab closed. This revision, once active, only ever touches
// /static/ (see the fetch handler) and never a navigation.
const CACHE = "pp-static-v3";
const STATIC_ASSETS = [
  "/static/css/app.css",
  "/static/vendor/chart.umd.min.js",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(STATIC_ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin === self.location.origin && url.pathname.startsWith("/static/")) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE).then((cache) => cache.put(event.request, copy));
          return response;
        })
        .catch(() => caches.match(event.request))
    );
  }
  // Everything else (every page, every POST) is left to the browser's
  // normal network handling -- deliberately no offline fallback.
});
