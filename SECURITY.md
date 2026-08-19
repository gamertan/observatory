<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Security policy

Observatory is pre-release software and has no supported public version yet. Please report suspected vulnerabilities privately to `security@sandwichhime.com`. Do not include credentials, production telemetry, raw request bodies, personal data, or exploit traffic in an initial report.

The maintainer aims to acknowledge a report within three business days, provide an initial triage within seven business days, and send progress updates at least every fourteen days. These are best-effort targets, not a service-level agreement or bounty promise.

## Current trust boundary

Agents, server operators, enrolled source configuration, the host kernel, SQLite, and the pinned Go dependency graph are trusted. Telemetry payloads, compressed input, query text, files being tailed, archive paths, and network peers are untrusted.

Current demonstrated controls include:

- source scope is loaded from a hashed credential rather than payload fields;
- production configuration and credentials remain absolute, root-owned,
  mode-`0600` regular files; the unprivileged agent consumes systemd-provided
  runtime copies confined to `CREDENTIALS_DIRECTORY`;
- decompressed input, batches, records, attributes, query stages, rows, memory, time, and scanned bytes have explicit bounds;
- OTLP/HTTP authenticates a source before parsing, accepts protobuf over
  identity or gzip only, independently caps compressed and decompressed bytes,
  discards known credential-bearing attribute keys, and derives tenant scope
  exclusively from the enrolled source;
- raw segments are checksummed, compressed, synchronized, and atomically renamed before acknowledgement;
- sequence gaps, old replay, and altered duplicate sequences fail closed;
- organization projections are separate SQLite files;
- control and projection databases, SQLite sidecars, process locks, agent
  state, spool entries, tailed files, and reviewed descriptors reject
  symlinks; database and lock files also reject additional hard links;
- live commands hold a shared data-directory lock while offline migration and
  projection replacement require exclusive ownership;
- error responses do not echo source values;
- browser sessions use opaque digest-backed credentials in Secure, HttpOnly,
  `SameSite=Strict`, `__Host-` cookies. Ordinary HTML forms require a
  purpose-bound CSRF token; JSON and JavaScript endpoints independently
  require canonical same-origin evidence;
- platform operator permission grants no telemetry access; query planning
  separately checks an organization/resource-scoped grant and sensitive-field
  permission;
- invitations are single-use and expiring, team grants remain organization
  scoped, revoked bindings stop authorizing, and short-lived break-glass
  access creates an organization-visible append-only audit event;
- first-operator bootstrap is local and serialized by an OS lock. The primary
  flow generates a one-time credential into a new mode-`0600`, non-symlink
  file; the account cannot use application or API features until replacing
  that credential, which revokes every session and requires a fresh login;
- administrative credential recovery is local-only and creates a new private
  file rather than accepting a password argument. Credential replacement,
  mandatory rotation, all-session revocation, and a secret-free audit event
  commit atomically; Observatory exposes no public reset endpoint;
- every HTML form uses an ordinary server POST and a session- or cookie-bound
  purpose token as its primary CSRF proof. Origin and Fetch Metadata provide a
  second contradiction check: explicit cross-site evidence and tokenless
  requests fail closed, while absent or opaque browser metadata cannot strand
  a valid server-rendered form;
- initial file adapters use positive field whitelists and remove query strings,
  credentials, cookies, client addresses, bodies, and arbitrary headers before
  durable agent spooling;
- Linux metrics read a fixed bounded file set without shell execution,
  enumerate no processes, require explicit PID-file/cgroup/filesystem
  selectors, reject symlink sources, and retain stable configured names rather
  than local paths, command lines, environments, or raw PIDs;
- spool deletion requires the local content digest and a path beneath the
  private pending root.
- collected file records advance only after an envelope containing the next
  cursor is durably spooled; discarded complete records advance only after the
  cursor and bounded counters are saved, and startup repairs cursors from
  pending envelopes before reading more source bytes;
- collectors refuse symlink sources, cap one cycle's read work, preserve
  partial lines, and detect truncation and same-directory inode rotation;
- enrollment tokens are hashed, short-lived, scope-bound, single-use, and
  exchanged over a redirect-refusing HTTPS client; a source credential can
  revoke itself when local persistence fails;
- visual and textual queries share one validated AST; organization scope is a
  separate planner input, unknown fields require sensitive-data permission,
  projection files are opened in query-only mode, and execution enforces
  independent time, decoded-byte, memory, and result-row budgets.
- unknown fields generate only idempotent per-segment proposal counts, byte
  estimates, inferred types, and generic example queries; proposals retain no
  observed values, default to sensitive/unindexed, and require an independent
  organization-scoped schema-management permission to review; batches with
  more than 1,024 distinct attribute keys are rejected before raw commit.
- reviewed descriptor files are bounded, strict JSON held in private regular
  non-symlink files; activation caps the active descriptor registry, validates
  typed values without coercing failures, builds a new index beside the live
  version, and atomically switches only after the complete build succeeds;
  ingestion and activation coordinate per organization, and prior versions
  remain intact.
- saved query text is bounded and parsed before storage, its versioned typed
  AST is revalidated against the text on every read, and dashboard panel
  foreign keys include the organization boundary; optimistic revisions reject
  lost updates, and dashboard exports omit organization/operator runtime
  metadata.
- an approved offline rebuild reads every organization segment through the
  checksum-verifying raw store, reconstructs base and activated descriptor
  projections beside live, and atomically replaces only that organization's
  disposable projection; corrupt raw truth fails closed before activation.
- PWA offline incident snapshots require an explicit browser action and omit
  response capabilities and high-risk fields; optional Web Push reauthorizes
  at delivery and encrypts one fixed generic sentence through a bounded,
  non-blocking queue.

This is a maintainer self-assessment, not an independent audit. Invitation UI,
the real-browser PWA campaign, production deployment, and the capacity/fleet
soak remain unfinished and must not be described as supported yet. Bootstrap
is intentionally single-use; a storage failure after the user row is
committed but before all personal-organization grants complete currently
requires restoring the empty control database before retrying. The current
executable evidence map is in
[`docs/SECURITY_CAMPAIGN.md`](docs/SECURITY_CAMPAIGN.md).
