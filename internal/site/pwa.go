// SPDX-License-Identifier: AGPL-3.0-only

package site

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func WebManifest() []byte {
	assets := AssetPaths()
	return []byte(fmt.Sprintf(`{"id":"/app/","name":"Gamertan Observatory","short_name":"Observatory","description":"A self-hosted, organization-aware observability workshop.","start_url":"/app/","scope":"/","display":"standalone","background_color":"#111715","theme_color":"#111715","icons":[{"src":%q,"sizes":"any","type":"image/svg+xml","purpose":"any maskable"}]}`+"\n", assets.IconPath))
}

func ServiceWorker() []byte {
	assets := AssetPaths()
	revisionSource := append(append(append([]byte(nil), style...), script...), icon...)
	revision := sha256.Sum256(revisionSource)
	return []byte(fmt.Sprintf(`/* SPDX-License-Identifier: AGPL-3.0-only */
"use strict";
const SHELL_CACHE = %q;
const PRIVATE_CACHE = "observatory-private-v1";
const PUSH_MESSAGE = %q;
const PUSH_ICON = %q;
const SHELL = [%q,%q,%q,%q];
self.addEventListener("install", event => {
  event.waitUntil(caches.open(SHELL_CACHE).then(cache => cache.addAll(SHELL)));
  self.skipWaiting();
});
self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    for (const name of await caches.keys()) {
      if (name.startsWith("observatory-shell-") && name !== SHELL_CACHE) await caches.delete(name);
    }
    await self.clients.claim();
  })());
});
self.addEventListener("fetch", event => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (request.mode === "navigate") {
    event.respondWith((async () => {
      try {
        const response = await fetch(request);
        if (response.status < 500) return response;
        const saved = await caches.open(PRIVATE_CACHE).then(cache => cache.match(request));
        return saved || response;
      } catch (_) {
        const saved = await caches.open(PRIVATE_CACHE).then(cache => cache.match(request));
        return saved || await caches.match("/offline/");
      }
    })());
    return;
  }
  if (SHELL.includes(url.pathname)) {
    event.respondWith(caches.match(request).then(saved => saved || fetch(request)));
  }
});
self.addEventListener("message", event => {
  const reply = value => { if (event.ports[0]) event.ports[0].postMessage(value); };
  if (!event.data || typeof event.data.type !== "string") return;
  if (event.data.type === "clear-private") {
    event.waitUntil(caches.delete(PRIVATE_CACHE).then(() => reply({ok:true})));
    return;
  }
  if (event.data.type !== "cache-inbox") return;
  event.waitUntil((async () => {
    try {
      const source = new URL(event.data.source, self.location.origin);
      const target = new URL(event.data.target, self.location.origin);
      const valid = source.origin === self.location.origin && target.origin === self.location.origin &&
        source.pathname === "/app/incidents/offline/" && target.pathname === "/app/incidents/" &&
        source.search === target.search && source.searchParams.size === 1 && source.searchParams.has("organization");
      if (!valid) throw new Error("invalid inbox cache request");
      const response = await fetch(source.href, {credentials:"include",cache:"no-store"});
      if (!response.ok || !(response.headers.get("content-type") || "").startsWith("text/html")) throw new Error("offline inbox unavailable");
      const cache = await caches.open(PRIVATE_CACHE);
      await cache.put(new Request(target.href, {method:"GET"}), response);
      reply({ok:true});
    } catch (_) { reply({ok:false}); }
  })());
});
self.addEventListener("push", event => {
  event.waitUntil(self.registration.showNotification(PUSH_MESSAGE, {icon:PUSH_ICON,badge:PUSH_ICON,tag:"observatory-attention",renotify:true,data:{url:"/app/"}}));
});
self.addEventListener("notificationclick", event => {
  event.notification.close();
  event.waitUntil((async () => {
    for (const client of await self.clients.matchAll({type:"window",includeUncontrolled:true})) {
      if (new URL(client.url).origin === self.location.origin) {
        await client.navigate("/app/");
        return client.focus();
      }
    }
    return self.clients.openWindow("/app/");
  })());
});
`, "observatory-shell-"+hex.EncodeToString(revision[:8]), "Gamertan Observatory needs your attention.", assets.IconPath, "/offline/", assets.StylePath, assets.ScriptPath, assets.IconPath))
}
