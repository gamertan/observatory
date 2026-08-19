// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  "use strict";
  const serviceWorker = "serviceWorker" in navigator
    ? navigator.serviceWorker.register("/service-worker.js", {scope: "/"})
    : Promise.reject(new Error("service workers unavailable"));

  const messageWorker = async message => {
    const registration = await serviceWorker;
    const worker = registration.active || registration.waiting || registration.installing;
    if (!worker) throw new Error("service worker unavailable");
    return await new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      const timeout = window.setTimeout(() => reject(new Error("service worker timeout")), 5000);
      channel.port1.onmessage = event => {
        window.clearTimeout(timeout);
        event.data && event.data.ok ? resolve(event.data) : reject(new Error("service worker request failed"));
      };
      worker.postMessage(message, [channel.port2]);
    });
  };

  const decodeURLBase64 = value => {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const decoded = window.atob(padded);
    return Uint8Array.from(decoded, character => character.charCodeAt(0));
  };

  const pushRequest = async (button, action, subscription) => {
	const serialized = subscription.toJSON();
	const status = action === "status";
	const response = await fetch(status ? "/api/v1/push/subscription/status" : "/api/v1/push/subscription", {
	  method: action === "delete" ? "DELETE" : "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": button.dataset.pushCsrf},
      body: JSON.stringify({
        organization_id: button.dataset.pushOrganization,
        endpoint: subscription.endpoint,
		keys: action === "save" ? serialized.keys : {p256dh: "", auth: ""}
	  })
	});
	if (!response.ok) throw new Error("push subscription request failed");
	return await response.json();
  };

  for (const button of document.querySelectorAll("[data-cache-inbox]")) {
    const status = document.querySelector("[data-cache-status]");
    serviceWorker.then(() => {
      button.disabled = false;
      if (status) status.textContent = "No private incident copy has been saved by this control yet.";
    }).catch(() => {
      if (status) status.textContent = "Offline saving is unavailable in this browser.";
    });
    button.addEventListener("click", async () => {
      button.disabled = true;
      if (status) status.textContent = "Saving a private, read-only incident snapshot…";
      try {
        await messageWorker({type: "cache-inbox", source: button.dataset.offlineSource, target: button.dataset.offlineTarget});
        if (status) status.textContent = "This incident inbox is available offline on this browser.";
      } catch (_) {
        if (status) status.textContent = "The offline incident snapshot could not be saved.";
      } finally {
        button.disabled = false;
      }
    });
  }

  for (const form of document.querySelectorAll('form[action="/logout/"]')) {
    form.addEventListener("submit", async event => {
      if (form.dataset.privateCacheCleared === "true") return;
      event.preventDefault();
      try { await messageWorker({type: "clear-private"}); } catch (_) {}
      form.dataset.privateCacheCleared = "true";
      form.requestSubmit();
    });
  }

  for (const button of document.querySelectorAll("[data-push-toggle]")) {
    const status = document.querySelector("[data-push-status]");
    const ready = serviceWorker.then(async registration => {
	  if (!("PushManager" in window) || !("Notification" in window)) throw new Error("push unavailable");
	  const existing = await registration.pushManager.getSubscription();
	  const registered = existing ? (await pushRequest(button, "status", existing)).subscribed === true : false;
	  button.dataset.pushRegistered = registered ? "true" : "false";
	  button.textContent = registered ? "Disable private incident nudges" : "Enable private incident nudges";
	  button.disabled = false;
	  if (status) status.textContent = registered ? "This browser is subscribed for this organization." : "This browser is not subscribed for this organization.";
      return registration;
    });
    ready.catch(() => { if (status) status.textContent = "Web Push is unavailable in this browser."; });
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const registration = await ready;
        let subscription = await registration.pushManager.getSubscription();
		if (subscription && button.dataset.pushRegistered === "true") {
		  const result = await pushRequest(button, "delete", subscription);
		  if (!result.remaining) await subscription.unsubscribe();
		  button.dataset.pushRegistered = "false";
		  button.textContent = "Enable private incident nudges";
		  if (status) status.textContent = "This browser is no longer subscribed for this organization.";
		} else {
		  let createdNow = false;
		  if (!subscription) {
			const permission = await Notification.requestPermission();
			if (permission !== "granted") throw new Error("notification permission not granted");
			subscription = await registration.pushManager.subscribe({userVisibleOnly: true, applicationServerKey: decodeURLBase64(button.dataset.pushPublicKey)});
			createdNow = true;
		  }
		  try {
			await pushRequest(button, "save", subscription);
		  } catch (error) {
			if (createdNow) await subscription.unsubscribe();
			throw error;
		  }
		  button.dataset.pushRegistered = "true";
          button.textContent = "Disable private incident nudges";
          if (status) status.textContent = "This browser will receive generic incident nudges.";
        }
      } catch (_) {
        if (status) status.textContent = "The browser push setting could not be changed.";
      } finally {
        button.disabled = false;
      }
    });
  }

  const incidentCount = document.querySelector("[data-open-incident-count]");
  if (incidentCount && "setAppBadge" in navigator) {
    const count = Number.parseInt(incidentCount.dataset.openIncidentCount, 10);
    if (Number.isSafeInteger(count) && count >= 0) {
      const update = count === 0 && "clearAppBadge" in navigator ? navigator.clearAppBadge() : navigator.setAppBadge(count);
      Promise.resolve(update).catch(() => {});
    }
  }

  for (const status of document.querySelectorAll(".live-status[data-events-url]")) {
    const source = new EventSource(status.dataset.eventsUrl);
    source.addEventListener("refresh", () => {
      status.hidden = false;
    });
    window.addEventListener("pagehide", () => source.close(), {once: true});
  }
})();
