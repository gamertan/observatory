<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Gamertan Observatory

Gamertan Observatory is a self-hosted, organization-aware observability platform in active private development. It is being built for logs, metrics, traces, incidents, and deployment evidence on modest Linux servers.

This repository currently contains the first security and durability vertical slice. It is not a public preview yet.

## Current development surface

- strict, versioned server configuration;
- organization/project/environment/service-scoped ingestion sources;
- hashed, rotatable source credentials;
- bounded log, metric, trace, and deployment batches;
- immutable checksummed zstd raw segments committed before acknowledgement,
  with an atomic cold forensic tier instead of destructive hot-window expiry;
- SQLite control state and independently migratable per-organization projections;
- sequence deduplication, replay rejection, and crash recovery;
- enforced organization-aware hot/cold retention, crash-recoverable archival,
  indefinite forensic preservation by default, explicitly enabled final
  retirement, projection compaction, budgeted cold queries, and
  queryable five-minute metric rollups;
- an exact five-minute HTTP-status/normalized-route log projection for the
  common error-count view, with one bounded raw fragment at an unaligned time
  boundary rather than a whole-window rescan;
- an offline, explicitly approved per-organization projection rebuild that
  validates checksummed raw truth, rebuilds activated descriptors beside the
  live database, and atomically replaces only the disposable projection;
- pinned Web Foundations `v0.1.0-preview.3` users, secure sessions,
  personal organizations, teams, invitations, and scoped access grants;
- local single-use operator bootstrap with an application-generated one-time
  credential, mandatory password replacement, and transactional session
  revocation; platform operation remains deliberately separated from
  telemetry access;
- a typed, bounded query AST and parser;
- one validated AST shared by text and visual-builder inputs, including safe
  regular expressions, aggregates, grouping, windows, sorting, and limits;
- explain planning that injects resource scope independently, resolves field
  descriptors, reports indexes and estimated scan, enforces budgets, and
  requires a separate permission for sensitive or unknown fields;
- bounded typed execution over per-organization projections, including
  filters, safe regular expressions, lookback windows, aggregation buckets,
  grouping, exact raw-sample percentiles, explicitly marked approximate
  rollup percentiles, sorting, and stable tabular results;
- same-origin session, health, readiness, native ingestion, query-parse,
  query-explain, and authenticated query-execution HTTP endpoints;
- strict agent configuration, private outage spooling, and HTTPS delivery;
- continuous bounded file tailing with durable cursors, truncation/rename
  handling, independent stream ordering, and crash recovery from spool
  checkpoints;
- short-lived, single-use, scope-bound agent enrollment and self-revocation if
  a newly issued credential cannot be persisted;
- whitelist-only adapters for Caddy access JSON, Web Foundations requestlog
  JSONL, and Tend deployment events; minimized defaults omit queries,
  addresses, referrers, user agents, cookies, credentials, and arbitrary
  fields, while explicitly configured privacy-policy-backed fields remain
  bounded and individually selectable.
- authenticated OTLP/HTTP protobuf endpoints for logs, metrics, and traces,
  with bounded identity/gzip decoding, source-owned scope, secret-key
  deny rules, typed signal conversion, and automatic per-stream sequencing.
- unprivileged Linux host metrics from bounded `/proc`, cgroup v2, named
  filesystems, and explicitly selected PID files; no shell, root agent,
  Docker socket, environment read, or command-line capture is involved.
- idempotent per-organization descriptor proposals aggregated once per raw
  segment; unknown fields remain sensitive, high-cardinality, and unindexed
  until an organization owner reviews them;
- explicit descriptor activation from a strict private review file, with each
  custom index built beside the active per-organization version and switched
  atomically; prior index versions remain intact and later ingestion follows
  the active descriptor registry;
- versioned saved queries and dashboard definitions with organization-scoped
  panel references, optimistic revisions, server-generated identifiers, and a
  source-control export that omits tenant and operator runtime metadata;
- authorized CLI export and explicitly approved atomic import of those strict
  dashboard bundles, with all destination identities and resource scopes
  independently revalidated;
- a server-rendered Sandwich Hime interface for public orientation, local
  sign-in, organization selection, recent log/metric/trace/deployment tables,
  typed-text and assisted saved-query creation, one-panel dashboard creation,
  bounded dashboard execution, accessible visual summaries with full table
  alternatives, and strict source-control-safe JSON export;
- a bounded organization-authorized SSE invalidation channel that carries only
  generic refresh events; the interface, tables, navigation, and sign-out flow
  remain functional without JavaScript;
- durable organization-scoped alert rules that execute bounded saved-query
  ASTs, open incidents after configurable consecutive matches, and preserve
  pending, firing, acknowledged, silenced, and resolved lifecycle events;
- an accessible server-rendered incident inbox with ordinary CSRF-protected
  response forms and no telemetry or incident detail in SSE payloads;
- an installable PWA shell, application badge state, and an explicit opt-in
  read-only offline incident snapshot that excludes response capabilities and
  high-risk private fields;
- optional privacy-preserving Web Push with an explicit user gesture,
  organization-scoped subscriptions, delivery-time authorization, a bounded
  non-blocking queue, and one fixed generic encrypted message;
- content-addressed static assets and a strict CSP with no inline-style or
  inline-script exception; the production Sandwich Hime dependency boundary
  contains only the pinned Apache-2.0 Sando runtime, not the Hime-san compiler.
- a Tend schema-2 singleton deployment contract with a stateless, loopback-only
  candidate that cannot open or mutate Observatory data, followed by routed
  public-origin validation and automatic last-good restoration.

The server injects resource scope from an authenticated source. Payloads cannot select an organization or resource. Unknown fields remain stored in raw truth, but are not indexed by default.

## Deliberate current limits

Self-service invitation delivery is deliberately excluded from the first
preview, and the visual query builder remains deliberately smaller than the
complete typed query language. Tend activation, rollback, and identical-
artifact redeployment have been exercised against the live Observatory
service. The separate medium-fleet agent soak and browser-vendor Web Push
delivery evidence are not complete. No release tag should be created until the
published preview gates in `docs/ROADMAP.md` are satisfied.

## Development

```sh
./scripts/preview-gate.sh
```

Linux is the supported deployment platform. Development requires Go 1.26.6 with `GOTOOLCHAIN=local`.

The local first-operator procedure is documented in
[`docs/BOOTSTRAP.md`](docs/BOOTSTRAP.md). It is a development surface, not yet
a public-preview installation promise.

The typed text/builder query contract and authorized local workflow are
documented in [`docs/QUERY.md`](docs/QUERY.md).
Descriptor discovery and its current review boundary are documented in
[`docs/SCHEMA.md`](docs/SCHEMA.md).
Retention, approved per-organization overrides, quota enforcement, and metric
rollup behavior are documented in [`docs/RETENTION.md`](docs/RETENTION.md).
The bounded preview gate includes the complete verifier, short fuzz smoke, and
a development capacity proof. Extended security, release-scale capacity, fleet,
and soak campaigns remain explicit milestone evidence. See
[`docs/CAPACITY.md`](docs/CAPACITY.md).
The retained optimization ledger and ordered lower-level storage case studies
are documented in [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md).
The proposed raw-first, lazy/eager time-partitioned read model is documented as
an unimplemented design in
[`docs/ADAPTIVE_PROJECTIONS.md`](docs/ADAPTIVE_PROJECTIONS.md).
The persisted dashboard model and export boundary are documented in
[`docs/DASHBOARDS.md`](docs/DASHBOARDS.md).
The current Sandwich Hime interface and progressive-enhancement boundary are
documented in [`docs/INTERFACE.md`](docs/INTERFACE.md).
The bounded rule evaluator and durable response lifecycle are documented in
[`docs/INCIDENTS.md`](docs/INCIDENTS.md).
The installable shell and opt-in offline privacy boundary are documented in
[`docs/PWA.md`](docs/PWA.md).
The strict, non-authoritative Tend deployment-evidence boundary is documented
in [`docs/TEND.md`](docs/TEND.md).
The application deployment and isolated candidate boundary are documented in
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).
Offline corruption recovery and projection rebuild are documented in
[`docs/RECOVERY.md`](docs/RECOVERY.md).

## Licensing

Application, agent, query, storage, migration, and release code is AGPL-3.0-only. Copyable files under `examples/` are 0BSD. See `LICENSES.md`.
