// Service worker: keeps the app shell available offline. Network first, so updates apply on the
// next load when online; the cache is the fallback. Cross-origin requests (ntfy) are never cached.

const CACHE = "yessh-shell-v1";
const SHELL = [
  "./",
  "index.html",
  "styles.css",
  "manifest.webmanifest",
  "icons/icon.svg",
  "icons/icon-192.png",
  "icons/icon-512.png",
  "src/app.js",
  "src/crypto.js",
  "src/encoding.js",
  "src/ntfy.js",
  "src/protocol.js",
  "src/sshcert.js",
  "src/store.js",
  "src/ui.js",
  "vendor/qrcode.mjs",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== self.location.origin) return;
  event.respondWith(
    (async () => {
      const cache = await caches.open(CACHE);
      try {
        const res = await fetch(req, { cache: "no-cache" });
        if (res.ok) cache.put(req, res.clone());
        return res;
      } catch {
        const hit = await cache.match(req, { ignoreSearch: true });
        if (hit) return hit;
        if (req.mode === "navigate") return (await cache.match("index.html")) ?? Response.error();
        return Response.error();
      }
    })(),
  );
});
