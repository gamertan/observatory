<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Progressive web application boundary

Observatory's PWA support adds availability without turning browser storage
into an implicit telemetry replica.

The deterministic service worker precaches only:

- the public offline explanation;
- content-addressed CSS and JavaScript; and
- the content-addressed application icon.

It does not automatically cache authenticated navigation responses. On the
incident page, an authorized user may explicitly save a separate read-only
snapshot. The worker validates both same-origin URLs, requires one matching
organization selector, fetches with the current session, verifies a successful
HTML response, and stores that response under the ordinary inbox URL.

The saved page contains the organization name plus current incident titles,
states, severities, and times. It excludes incident identifiers, response
forms, CSRF tokens, saved-query text, telemetry values, actor identifiers, and
project, environment, and service identifiers. The page is not an authority
for response actions; reconnection is required.

Signing out sends a private-cache deletion request before submitting the
ordinary sign-out form. An expired server session cannot notify a disconnected
browser, so operators should treat saved incident snapshots like any other
explicitly downloaded sensitive material on that device.

The Badging API receives only the current open-incident count when supported.

## Optional Web Push

Web Push follows [RFC 8291](https://www.rfc-editor.org/rfc/rfc8291.html) message
encryption and [RFC 8292](https://www.rfc-editor.org/rfc/rfc8292.html) VAPID
authentication. It is disabled unless the server configuration names a VAPID
private-key file, contact subject, bounded queue, and request timeout. Create a
new private key without exposing it in command arguments or output:

```sh
observatory admin web-push generate-key \
  --output-file /etc/gamertan-observatory/web-push.json
```

The output is created exclusively as a mode-`0600` regular file. The installed
systemd unit copies that root-owned source into its private credential
directory as `web-push.json`, and the non-root server configuration references
only that runtime copy. Do not place the key value in configuration, process
arguments, deployment manifests, or source control:

```json
"web_push": {
  "private_key_file": "/run/credentials/gamertan-observatory.service/web-push.json",
  "subject": "mailto:security@sandwichhime.com",
  "queue_capacity": 64,
  "request_timeout": "10s"
}
```

The source key remains `/etc/gamertan-observatory/web-push.json`, owned by
root with mode `0600`. `LoadCredential=` makes the service-specific runtime
copy readable without granting the static service account access to `/etc` or
weakening the original file. A differently named service must update both the
unit and the credential-directory path explicitly; Observatory does not search
for secrets.

An authorized incident reader must press the browser control before
Observatory requests notification permission or creates a subscription.
One browser endpoint is owned by one user and may be mapped to several of that
user's organizations. Removing one organization keeps the browser subscribed
until its final mapping is removed. Authorization is checked again for every
delivery; revoked access retires only that organization's mapping.
Endpoints are accepted only as bounded HTTPS push-service URLs and delivery
uses a redirect-free client that rejects DNS results containing non-public IP
addresses.

Only a transition into `firing` enqueues a notification. The bounded queue is
best effort and never blocks alert evaluation or incident persistence. The
encrypted payload is always exactly:

> Gamertan Observatory needs your attention.

The service worker ignores incoming payload content and renders that same
fixed sentence. It includes no organization, host, service, severity, rule,
incident identifier, count, or telemetry text. Activating it opens `/app/`,
where the user must have a valid authenticated session before seeing details.
Browser-vendor push relays remain an explicit metadata boundary: they can
observe delivery timing, endpoint identity, and the fixed payload size even
though they cannot read its encrypted content.
