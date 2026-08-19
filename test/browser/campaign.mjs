// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { chromium } from "playwright";

const origin = process.env.OBSERVATORY_BROWSER_ORIGIN;
const certificateSPKI = process.env.OBSERVATORY_BROWSER_SPKI;
assert.match(origin || "", /^https:\/\/localhost:\d+$/);
assert.match(certificateSPKI || "", /^[A-Za-z0-9+/]{43}=$/);

const evidence = {
  version: 1,
  browser: "chromium",
  installable: false,
  offlineShell: false,
  privateInbox: false,
  privateCacheCleared: false,
  sseReconnected: false,
  genericNotification: false,
  notificationActivated: false,
  badge: false,
  accessibility: false,
  externalRequests: 0
};

const campaignTimeout = setTimeout(() => {
  console.error("stage=campaign-timeout");
  process.exit(124);
}, 120000);
const browser = await chromium.launch({headless: true, args: [`--ignore-certificate-errors-spki-list=${certificateSPKI}`]});
const context = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 320, height: 800}});
let intentionallyOffline = false;
const pageErrors = [];
const consoleErrors = [];
const externalRequests = [];
context.on("request", request => {
  const url = new URL(request.url());
  if (url.protocol === "http:" || url.protocol === "https:") {
    if (url.origin !== origin) externalRequests.push(url.origin + url.pathname);
  }
});
context.on("page", candidate => {
  candidate.on("pageerror", error => pageErrors.push(error.message));
  candidate.on("console", message => {
    if (message.type() === "error" && !intentionallyOffline) consoleErrors.push(message.text());
  });
});
await context.addInitScript(() => {
  Object.defineProperty(navigator, "setAppBadge", {configurable: true, value: async value => { globalThis.__observatoryBadge = value; }});
  Object.defineProperty(navigator, "clearAppBadge", {configurable: true, value: async () => { globalThis.__observatoryBadge = 0; }});
  globalThis.__observatoryPermissionRequests = 0;
  const requestPermission = Notification.requestPermission.bind(Notification);
  Notification.requestPermission = (...arguments_) => {
    globalThis.__observatoryPermissionRequests++;
    return requestPermission(...arguments_);
  };
});

const page = await context.newPage();
page.setDefaultTimeout(10000);
page.setDefaultNavigationTimeout(10000);
await page.goto(origin + "/", {waitUntil: "networkidle"});
console.error("stage=landing");
assert.equal(await page.locator("h1").textContent(), "Keep the evidence close.");
assert.equal(await page.evaluate(() => globalThis.__observatoryPermissionRequests), 0);
assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1), true);
await page.keyboard.press("Tab");
assert.equal((await page.locator(":focus").textContent()).trim(), "Skip to content");
await page.emulateMedia({forcedColors: "active", reducedMotion: "reduce"});
assert.equal(await page.evaluate(() => matchMedia("(forced-colors: active)").matches && matchMedia("(prefers-reduced-motion: reduce)").matches), true);
assert.equal(await page.locator("main").count(), 1);
assert.equal(await page.locator('nav[aria-label="Primary"]').count(), 1);
evidence.accessibility = true;

const cdp = await context.newCDPSession(page);
await cdp.send("Page.enable");
console.error("stage=manifest-request");
const manifest = await Promise.race([
  cdp.send("Page.getAppManifest"),
  new Promise((_, reject) => setTimeout(() => reject(new Error("manifest inspection timed out")), 5000))
]);
console.error("stage=manifest-response");
assert.equal(manifest.url, origin + "/manifest.webmanifest");
assert.equal((manifest.errors || []).length, 0);
const manifestBody = JSON.parse(manifest.data);
assert.equal(manifestBody.start_url, "/app/");
assert.equal(manifestBody.display, "standalone");
const workerProbe = await page.evaluate(async () => {
  try {
    const value = await navigator.serviceWorker.register("/service-worker.js", {scope: "/"});
    return {secure: isSecureContext, scope: value.scope, installing: value.installing?.state || "", waiting: value.waiting?.state || "", active: value.active?.state || ""};
  } catch (error) {
    return {secure: isSecureContext, error: `${error.name}: ${error.message}`};
  }
});
console.error(`stage=service-worker-probe ${JSON.stringify(workerProbe)}`);
assert.equal(workerProbe.secure, true);
assert.equal(workerProbe.error, undefined);
const registration = await page.evaluate(async () => {
  const ready = await Promise.race([
    navigator.serviceWorker.ready,
    new Promise((_, reject) => setTimeout(() => reject(new Error("service worker readiness timed out")), 5000))
  ]);
  return {scope: ready.scope, controlled: Boolean(navigator.serviceWorker.controller)};
});
assert.equal(registration.scope, origin + "/");
assert.equal(registration.controlled, true);
evidence.installable = true;
console.error("stage=installable");

await page.goto(origin + "/login/");
await page.locator("#identifier").fill("browser-operator");
await page.locator("#password").fill("browser-fixture-password");
const [loginResponse] = await Promise.all([
  page.waitForResponse(response => new URL(response.url()).pathname === "/login/" && response.request().method() === "POST"),
  page.getByRole("button", {name: "Sign in"}).click()
]);
const loginOrigin = await loginResponse.request().headerValue("origin");
const loginFetchSite = await loginResponse.request().headerValue("sec-fetch-site");
const loginFailure = loginResponse.status() === 303 ? "" : (await loginResponse.text()).slice(0, 256);
console.error(`stage=login-response status=${loginResponse.status()} origin=${loginOrigin || "missing"} fetch_site=${loginFetchSite || "missing"} body=${JSON.stringify(loginFailure)}`);
assert.equal(loginOrigin, "null");
assert.equal(loginFetchSite, "same-origin");
assert.equal(loginResponse.status(), 303);
await page.waitForURL(origin + "/app/");
await page.waitForLoadState("load");
assert.equal(await page.locator("h1").count(), 1);
console.error("stage=authenticated");

const overviewURL = page.url();
const exploreLink = page.getByRole("link", {name: "Explore", exact: true});
assert.match(await exploreLink.getAttribute("href"), /^\/app\/explore\/\?organization=/);
await exploreLink.click();
await page.getByRole("heading", {name: "Follow the evidence."}).waitFor();
assert.equal(await page.locator('nav[aria-label="Primary"] a[aria-current="page"]').textContent(), "Explore");
assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1), true);
await page.locator("#explore-query").fill("logs | window 1h | limit 10");
const [queryResponse] = await Promise.all([
  page.waitForResponse(response => new URL(response.url()).pathname === "/app/explore/" && response.request().method() === "POST"),
  page.getByRole("button", {name: "Run query"}).click()
]);
assert.equal(queryResponse.status(), 200);
assert.equal(new URL(page.url()).searchParams.has("query"), false);
await page.getByRole("heading", {name: "Query results"}).waitFor();
assert.equal(await page.locator(".query-stats dt").allTextContents().then(values => values.join("|")), "Scanned rows|Matched rows|Scanned bytes|Execution");
assert.ok(await page.locator(".query-results table tbody tr").count() >= 1);
await page.goto(overviewURL);
await page.locator("main h1").waitFor();
assert.equal(new URL(page.url()).pathname, "/app/");
console.error("stage=explore");

const inboxLink = page.getByRole("link", {name: "Open incident inbox"});
const inboxPath = await inboxLink.getAttribute("href");
assert.match(inboxPath, /^\/app\/incidents\/\?organization=/);
let eventRequests = 0;
page.on("request", request => {
  if (new URL(request.url()).pathname === "/app/events") eventRequests++;
});
await inboxLink.click();
await page.waitForURL(origin + inboxPath);
await page.getByRole("heading", {name: "What needs attention?"}).waitFor();
await page.locator('.incident-card[data-state="firing"] h3', {hasText: "Browser fixture incident"}).waitFor();
await page.waitForFunction(() => globalThis.__observatoryBadge === 1);
assert.equal(await page.evaluate(() => globalThis.__observatoryBadge), 1);
evidence.badge = true;
await page.waitForFunction(() => !document.querySelector("[data-cache-inbox]").disabled);
assert.equal(await page.evaluate(() => caches.has("observatory-private-v1")), false);
const cacheButton = page.locator("[data-cache-inbox]");
const cacheTarget = await cacheButton.getAttribute("data-offline-target");
await cacheButton.click();
await page.getByText("This incident inbox is available offline on this browser.", {exact: true}).waitFor();
const pushButton = page.locator("[data-push-toggle]");
await page.waitForFunction(() => !document.querySelector("[data-push-toggle]").disabled);
assert.equal(await page.evaluate(() => globalThis.__observatoryPermissionRequests), 0);
await pushButton.click();
await page.getByText("The browser push setting could not be changed.", {exact: true}).waitFor();
assert.equal(await page.evaluate(() => globalThis.__observatoryPermissionRequests), 1);
const cached = await page.evaluate(async target => {
  const cache = await caches.open("observatory-private-v1");
  const response = await cache.match(target);
  return {keys: (await cache.keys()).map(request => request.url), text: response ? await response.text() : ""};
}, cacheTarget);
assert.deepEqual(cached.keys, [origin + cacheTarget]);
assert.match(cached.text, /Browser fixture incident/);
for (const forbidden of ["csrf_token", "logs | window", "browser-project", "browser-service", "incident_"]) {
  assert.equal(cached.text.includes(forbidden), false, `private snapshot contained ${forbidden}`);
}

intentionallyOffline = true;
await context.setOffline(true);
await page.goto(origin + cacheTarget, {waitUntil: "domcontentloaded"});
await page.getByRole("heading", {name: "Saved incident inbox"}).waitFor();
await page.goto(origin + "/network-unavailable/", {waitUntil: "domcontentloaded"});
await page.getByRole("heading", {name: "The evidence is still safe."}).waitFor();
await context.setOffline(false);
intentionallyOffline = false;
evidence.offlineShell = true;
evidence.privateInbox = true;
console.error("stage=offline");

await page.goto(origin + inboxPath);
await page.waitForFunction(() => !document.querySelector(".live-status").hidden, null, {timeout: 5000});
const requestsBeforeDisconnect = eventRequests;
await page.evaluate(() => { document.querySelector(".live-status").hidden = true; });
const reconnectDeadline = Date.now() + 10000;
while (eventRequests <= requestsBeforeDisconnect && Date.now() < reconnectDeadline) {
  await page.waitForTimeout(250);
}
assert.ok(eventRequests > requestsBeforeDisconnect, `SSE requests did not reconnect: ${eventRequests} <= ${requestsBeforeDisconnect}`);
await page.waitForFunction(() => !document.querySelector(".live-status").hidden, null, {timeout: 5000});
evidence.sseReconnected = true;
console.error("stage=sse");

const workers = context.serviceWorkers();
assert.equal(workers.length, 1);
const worker = workers[0];
const notification = await worker.evaluate(async () => {
  let shown;
  const original = self.registration.showNotification;
  self.registration.showNotification = async (title, options) => { shown = {title, options}; };
  let completion;
  const event = new Event("push");
  Object.defineProperty(event, "data", {value: "telemetry that must be ignored"});
  Object.defineProperty(event, "waitUntil", {value: value => { completion = Promise.resolve(value); }});
  self.dispatchEvent(event);
  await completion;
  self.registration.showNotification = original;
  return shown;
});
assert.equal(notification.title, "Gamertan Observatory needs your attention.");
assert.equal(notification.options.tag, "observatory-attention");
assert.equal(notification.options.renotify, true);
assert.deepEqual(notification.options.data, {url: "/app/"});
assert.equal(notification.options.icon, notification.options.badge);
assert.match(notification.options.icon, /^\/assets\/observatory-[a-f0-9]{16}\.svg$/);
evidence.genericNotification = true;
const activation = await worker.evaluate(async () => {
  let navigated = "";
  let focused = false;
  const originalMatchAll = self.clients.matchAll;
  self.clients.matchAll = async () => [{
    url: self.location.origin + "/offline/",
    navigate: async target => { navigated = target; },
    focus: async () => { focused = true; }
  }];
  let completion;
  const event = new Event("notificationclick");
  Object.defineProperty(event, "notification", {value: {close() {}}});
  Object.defineProperty(event, "waitUntil", {value: value => { completion = Promise.resolve(value); }});
  self.dispatchEvent(event);
  await completion;
  self.clients.matchAll = originalMatchAll;
  return {navigated, focused};
});
assert.deepEqual(activation, {navigated: "/app/", focused: true});
evidence.notificationActivated = true;
console.error("stage=notification");

await page.goto(origin + "/app/");
await page.getByRole("button", {name: "Sign out"}).click();
await page.waitForURL(origin + "/login/");
assert.equal(await page.evaluate(() => caches.has("observatory-private-v1")), false);
evidence.privateCacheCleared = true;

assert.deepEqual(pageErrors, []);
assert.deepEqual(consoleErrors, []);
assert.deepEqual(externalRequests, []);
evidence.externalRequests = externalRequests.length;
console.log(JSON.stringify(evidence));
clearTimeout(campaignTimeout);
await browser.close();
