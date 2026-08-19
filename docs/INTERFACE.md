<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Sandwich Hime interface

Observatory's web interface is server-rendered with Hime-san
`v1.0.0-beta.2`. Generated `.sando.go` files are committed and verified for
two-pass byte and modification-time stability. The production binary links
only `gamertan.com/sandwich-hime/sando@v1.0.0-beta.1`; the compiler does not
enter the service dependency graph.

The current surface provides:

- a public project explanation;
- local session sign-in and CSRF-protected sign-out;
- selection among the authenticated user's active organizations;
- bounded one-hour tables for logs, metrics, traces, and deployment evidence;
- organization-authorized creation of persisted queries through typed text or
  the first assisted visual builder;
- one-panel dashboards, bounded panel execution, nonnegative numeric meter
  summaries with complete table alternatives, and strict JSON export;
- a progressive SSE notification when newer observations are available;
- an organization-scoped incident inbox with durable lifecycle state and
  ordinary acknowledge, silence, and resolve forms; and
- bounded alert-rule creation over an existing saved query;
- an installable manifest, deterministic service worker, and offline public
  shell; and
- explicit opt-in storage of a read-only incident snapshot with badge state.

Every organization selection is checked against both active membership and
the scoped `dashboards.read` grant. The query executor receives the authorized
organization separately from query text. No browser field can select a tenant
without that server-side decision.

The SSE stream is deliberately an invalidation hint rather than a telemetry
transport. It emits fixed `ready` and `refresh` events with `{}` payloads,
coalesces pending refreshes, caps total and per-organization subscribers, and
is authorized independently when the connection opens. If JavaScript is
disabled, disconnected, or blocked, the same HTML tables and ordinary refresh
links remain usable.

CSS and JavaScript are embedded, content-addressed, and served with immutable
cache policy. The application CSP permits only same-origin styles, scripts,
images, forms, and SSE connections; it does not use `unsafe-inline`.

The assisted builder deliberately produces one optional comparison and one
optional aggregate/group/bucket stage from fixed controls. It serializes that
selection into ordinary query text and submits it to the same parser used by
the text editor; it does not maintain a second query language. More complex
queries remain available through typed text.

Time-series panels render at most 48 finite, nonnegative points with native
`meter` elements. The complete result table is always rendered beside the
summary and remains the canonical accessible representation. Negative,
non-numeric, missing, or unsupported results simply omit the visual summary.

Alert evaluation counts bounded saved-query rows, requires a configured number
of consecutive matches before promotion from pending to firing, and never
resolves an existing incident when query execution itself fails. The incident
event trail records system transitions and authorized human responses without
copying query results or telemetry values into control state.

The service worker precaches only public content-addressed shell assets. It
stores no private response by default. An authorized user must activate the
offline control before the worker fetches a separate read-only incident page
and stores it under that organization's ordinary inbox URL. The snapshot has
no actions, CSRF material, query text, telemetry values, actors, or project,
environment, and service identifiers. Signing out asks the worker to delete
the complete private cache. Session expiry cannot itself reach an offline
browser, so this remains an explicit device-local privacy decision.

Dashboard metadata and panel editing use optimistic revisions, and the bounded
assisted query builder shares the same parser as the complete typed editor.
The incident inbox provides an installable shell, explicit read-only offline
copy, badge state, and optional generic Web Push without making JavaScript an
authority for incident response. Richer visual editing remains future work,
not an alternate query authority or a hidden first-preview gate.
