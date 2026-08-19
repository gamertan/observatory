<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Architecture

Observatory preserves three independent evidence layers:

1. an agent's local spool retains unacknowledged batches;
2. immutable raw segments are committed and checksummed before acknowledgement,
   then move unchanged from hot to cold forensic storage;
3. per-organization SQLite projections are disposable query accelerators.

Durable acceptance and query visibility are deliberately separate. A source
may receive an exact acknowledgement as soon as its immutable segment and
control-plane identity are durable. A bounded background projector then makes
that evidence visible to queries. The authenticated interface reports this
lag for the selected organization instead of pretending that accepted and
indexed mean the same thing.

The control database stores Web Foundations identities, organizations, scoped
access grants, source credential digests, sequence watermarks, segment
projection state, dashboards, alert rules, incident metadata, and optional
user-owned Web Push endpoints and their organization-scoped mappings. Every
organization's query projection is stored in a distinct SQLite database.
Authorization is applied before opening that projection.

Saved queries and dashboards live in the control database, but every key and
foreign-key relationship includes the organization identifier. Saved query
text is parsed into the same typed AST at write time; both representations are
stored and revalidated for exact semantic agreement when read. Updates use
optimistic revisions. Dashboard panels reference only saved queries from the
same organization. Source-control exports deliberately omit tenant IDs,
operator IDs, timestamps, and internal revisions.

The web interface is an ordinary `net/http` application rendered through
compiler-generated Sandwich Hime components. The application buffers complete
HTML before committing status and headers. Hime-san remains a development and
CI tool; the service links only the pinned Sando runtime. Content-hashed CSS
and JavaScript are embedded in the binary and served under immutable URLs.
JavaScript opens an authenticated SSE connection only to learn that newer data
exists. The stream carries no telemetry or resource labels, and dropping it
does not remove any navigation, query result, table, or authentication
function.

The text language and visual builder both produce the same versioned typed AST.
Planning receives an already-authorized organization/resource scope separately
from that AST; query text cannot select a tenant. Explain output names the
scoped projected source, reviewed descriptors and indexes, estimated scan,
cache eligibility, budgets, and required permissions. Unknown fields remain
raw-query candidates but default to sensitive, high-cardinality, and unindexed.
Execution opens only the already-authorized organization's projection in
query-only mode. Server-owned project, environment, and service constraints
are added independently of the AST; the executor applies typed comparisons,
bounded RE2 regular expressions, time windows, grouping buckets, aggregates,
sorting, row limits, and separate time, decoded-byte, and memory ceilings.
Only default safe columns and fields explicitly referenced by the query enter
the result table. `window 24h` is a lookback; `window(5m)` is a distinct
aggregation bucket in the versioned AST.

Alert rules reference a saved query in the same organization. A single
evaluator claims each due rule by advancing its next-evaluation time before it
opens the organization's query projection, preventing concurrent duplicate
evaluation. The ordinary query budget remains authoritative. A configured row
threshold determines whether an evaluation matches; consecutive matches move
an incident from pending to firing. Query failure records only the bounded
code `query_unavailable` and leaves an existing incident unchanged. Incident
state and its append-only event sequence live in the control database, contain
no query result or telemetry value, and remain organization-keyed on every
relationship.

Web Push remains downstream of durable incident state. Only a committed
transition into `firing` enters a bounded, deduplicated in-memory queue. The
dispatcher reauthorizes `incidents.read`, encrypts one fixed generic sentence,
and uses a redirect-free HTTPS client that rejects non-public DNS results.
Vendor delivery cannot block rule evaluation, and delivery failure cannot
change incident state. The service worker ignores payload content and opens
the authenticated application rather than carrying a tenant or incident
identifier through the push relay.

Unknown attribute keys produce descriptor proposals only after their raw
segment is committed. Proposal evidence is aggregated once per segment using
the segment digest, organization, and field as the idempotency identity. The
control database stores counts, estimated bytes, inferred type, first/last
observation times, and a generic example query—not observed values. Built-in
reviewed fields are excluded. Proposals remain sensitive, high-cardinality,
and unindexed; proposal persistence does not activate a descriptor.

Descriptor activation is an explicit organization-authorized operation. A
reviewed descriptor is loaded from a bounded private JSON file; unknown
properties and weak or symlinked files are rejected. Observatory copies the
currently active descriptors into a new per-organization projection version,
builds a typed custom-field index by scanning the disposable observation
projection, and changes the active version in the same SQLite transaction.
Invalid historical values are omitted rather than coerced. Existing and newly
ingested observations use the active registry after commit, while prior index
tables remain available for recovery. The control-database proposal status is
held under a write claim during the build and acknowledged only after the
projection commit; retry repairs an interrupted acknowledgement idempotently.

## Ingestion transaction

1. Authenticate the source credential and load its server-owned scope.
2. For native v2, validate the bounded transport envelope. If it exactly
   matches the current acknowledged stream watermark, hash and discard the
   complete body, recheck the watermark under the source lock, and return the
   retained acknowledgement without decoding or writing it again.
3. For a new batch, validate decompressed size, record count, field bounds,
   timestamps, signal type, sequence, and every envelope/body field.
4. Commit a content-addressed zstd raw segment with `fsync` and atomic rename.
5. Serialize organization quota admission and reject the exact segment before
   cataloguing it when the approved quota is exhausted.
6. In one control-database transaction, catalogue the committed segment and
   advance the `(source, stream)` watermark with its bounded envelope metadata.
7. Acknowledge the exact sequence,
   raw-segment digest, and canonical logical-batch digest.
8. Outside the acknowledgement path, group a bounded number of one
   organization's pending segments into one projection transaction. Project
   at most four distinct organizations concurrently, while keeping each
   tenant's base projection, active custom index, metric rollups, and replay
   ledgers in its own transaction.
9. Aggregate unknown-field proposal evidence without retaining observed
   values, then mark each projected segment complete in the control database.

The dogfood server bounds an authenticated request at 32 MiB and admits at
most eight ingestion bodies concurrently. File agents read no more than 4 MiB
of source text into a cycle. These independent bounds preserve batching
headroom while preventing source credentials from creating unbounded request
memory pressure.

A retry of the same sequence and digest is idempotently acknowledged even
while projection is pending. Reusing a sequence with different bytes or
submitting an older sequence is rejected. If projection fails, the durable
segment remains pending and the projector retries it without holding the
source or listener hostage. Work is bounded and selected fairly across
organizations so one tenant's corrupt segment cannot prevent other tenants
from advancing.

Server startup first reconciles raw objects and control metadata without
decoding already catalogued objects, then opens the listener and drains
pending projections in the background. The one-shot `check` and `migrate`
commands retain a blocking recovery path for offline verification.

Every projected metric sample also updates a five-minute aggregate in the same
organization projection transaction. Rollups retain exact count, sum, minimum,
and maximum plus a deterministic bounded histogram for explicitly approximate
percentiles. Only reviewed, non-sensitive, bounded-cardinality dimensions with
the `metric` retention class enter that longer-lived projection. Unknown and
sensitive attributes remain raw-only. Summary queries that can be represented
faithfully select the rollup explicitly in their explain plan; unsupported
query shapes continue to use raw samples.

The server applies retention after recovery and once per hour. Projected rows
expire at their signal's hot cutoff. Once every record in a segment is outside
that hot window, the control database first records an exact cold destination,
then the unchanged zstd object is atomically renamed into the private cold
tree, and finally its catalog path and tier advance. Recovery completes either
side of that rename idempotently. Cold segments remain checksum-verifiable and
queryable through a slower scan path with the ordinary authorization and
resource budgets. Cold raw evidence is preserved indefinitely by default.
Only a policy with `delete_cold_raw` explicitly enabled marks segments beyond
its final cold cutoff as retiring and removes them through a separate
crash-recoverable lifecycle. Resolved incidents and security audit evidence
use the configured evidence window. Organization overrides may shorten
defaults. Extending a finite server policy to indefinite preservation requires
an exact organization approval and an enforceable storage quota.

The agent has a separate durability boundary. It commits a private,
checksummed zstd envelope before attempting HTTPS delivery and removes it only
after an acknowledgement binds the exact logical batch. Its envelope digest
continues to protect the checkpoint and compressed local bytes. Collection
adapters use fixed whitelists so known credentials and high-risk fields are
absent before the spool write. Server configuration cannot alter the agent's
selected local sources.

OTLP/HTTP accepts the standard protobuf wire shape for logs, metrics, and
traces without enabling gRPC, a collector listener, or remote configuration.
The server authenticates the enrolled source before decoding, applies limits
to both compressed and decompressed bytes, removes known credential-bearing
attribute keys, and injects the source's stored resource scope. OTLP payloads
cannot select an organization, project, environment, or service. Automatic
stream sequences are assigned under a per-source lock; native batches retain
their explicit replay-safe sequence and digest acknowledgement contract.

Linux host metrics are collected in the same unprivileged agent cycle and
enter the same durable spool. The collector reads a fixed set of bounded
`/proc` and cgroup v2 files, named filesystem statistics, and only process IDs
resolved through explicitly configured PID files. Files are required to be
regular and non-symlinked; cgroup traversal is confined component-by-component
beneath the configured root. Local paths, raw PIDs, command lines, and
environment values are not projected.

## Tenant boundary

Payloads contain no organization, project, environment, or service selector.
Those values come from the enrolled source record after credential
verification. Published Web Foundations Preview 3 supplies user identities,
personal and shared organizations, resources, teams, invitations, and scoped
query grants, plus the forced initial-password rotation contract. Platform
operator status is a separate policy and does not authorize telemetry access.
A query request names a desired resource, but the server independently
authorizes that scope and computes sensitive-field access before it constructs
the planner input.
