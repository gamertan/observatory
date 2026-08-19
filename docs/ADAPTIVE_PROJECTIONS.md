<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Adaptive time-partitioned projections

Status: design candidate; not an implemented capability or release claim.

## Purpose

Observatory should preserve forensic evidence by default without requiring
every accepted observation to become a fully indexed row immediately. The raw
segment and control catalogue already contain the durable identity, tenant,
signal, source, sequence, byte size, and observed-time range needed to defer
most read-model work.

The proposed model is an event lake with adaptive materializations:

1. acknowledge immutable raw evidence and its small catalogue entry;
2. keep a bounded recent window available for live authorized views;
3. incrementally maintain only projections required by currently observed
   views, explicitly warmed workloads, or reviewed central correlations;
4. build ad-hoc historical materializations on demand from the relevant raw
   time partitions; and
5. evict any derived projection that no longer justifies its storage cost.

Raw evidence remains authoritative. Every memory view, SQLite partition,
index, rollup, and query cache remains disposable and reconstructable.

## Batch identity, not per-record deduplication

An enrolled agent is trusted to classify and serialize the records it was
configured to collect. Observatory does not need to maintain a global
per-record deduplication index in the ingestion path. The durable unit is one
bounded authenticated batch identified by its enrolled source, stream, and
monotonic sequence. Its retained segment catalogue records the first and last
observed timestamps, record and byte counts, and the exact segment and
canonical logical-batch digests. Agent epochs separately namespace locally
generated alert-transition sequences across process-state replacement.

The server derives organization, project, environment, and service scope from
the enrollment. It commits the immutable batch once, advances the stream
watermark atomically, and acknowledges its exact identity. Retrying the same
sequence and digest is an idempotent no-op. Reusing a sequence with different
bytes is quarantined as corruption. A sequence gap is retained as an explicit
continuity event rather than hidden. Timestamp ranges select storage and query
partitions but are not deduplication keys because legitimate batches may
overlap and host clocks may drift.

### Implemented native v2 early-replay envelope

The agent sends new native batches to `/api/v2/ingest/native`. A small
authenticated header envelope is available before the JSON record body, so an
exact replay takes a cheaper path. The envelope contains only:

- protocol version, stream ID, signal, and monotonic sequence;
- the SHA-256 of the exact encoded body and the canonical logical-batch digest;
- record count and encoded byte count; and
- first and last observed timestamps.

Source and tenant scope remain server-derived from the enrolled credential.
For a sequence already acknowledged with both digests, the server hashes and
discards the bounded body, returns the retained raw-segment identity, and avoids
JSON decoding, compression, catalogue writes, or projection wakeups. It must
still read the complete bounded body and verify its encoded digest before
acknowledging; trusting an enrolled agent does not make a buggy reused sequence
safe to accept without checking the bytes.

For a new sequence, the existing validation and raw-first commit remain
mandatory. The server checks the declared count, byte size, signal, and time
bounds against the decoded batch before it commits or acknowledges it. An
envelope mismatch is a rejected batch, not a reason to rewrite telemetry.
Overlapping time ranges, late data, and repeated values remain valid. This is
an ingestion-cost optimization and audit index, not content-based record
deduplication.

The legacy `/api/v1/ingest/native` endpoint remains available during the
preview compatibility window. A stream last accepted through v1 has blank
envelope columns. Its first matching v2 retry follows the full validation path
once, verifies the retained segment identity, and backfills the v2 metadata;
later exact retries use the early path.

## Partition shape

Partition first by organization, signal, and UTC time—not by arbitrary field
names or user-supplied identifiers. A starting comparison should use one
SQLite database per organization, signal, and UTC day. This keeps a normal
30-day hot window near 90 files per organization, permits logs, metrics, and
traces to project concurrently, narrows index working sets, and makes expiry a
bounded file operation.

Hourly partitions may be evaluated for unusually high-volume days only after
the daily prototype is measured. Five-minute, hourly, and daily *rollups* are
aggregation resolutions; they should not be confused with the physical file
boundary. The partition catalogue must tell the planner which exact files and
rollup resolutions cover a requested window.

Each materialized partition records:

- organization, signal, UTC start and end;
- projection schema and generation;
- the exact raw segment digests or a durable high-watermark plus delta ledger;
- row, byte, and rollup counts;
- creation, last-query, and expiry times;
- build state and failure state; and
- the reviewed query evidence that justified eager or cached materialization.

Late observations update only their observed-time partition. The new
generation is built beside the active one and atomically activated. Queries
must either use one complete generation or merge its explicit delta; they may
never silently omit late evidence.

## Materialization classes

### Live tail

A bounded per-organization memory ring receives records only after their raw
segment has been durably acknowledged. It is keyed by segment digest and record
index, capped by both age and bytes, and safe to lose. It serves the recent log
tail, current metric samples, and trace arrivals while the disk projector is
behind. Authorization is checked before the ring is opened, and disk results
are deduplicated when a query overlaps the ring.

SSE is the default UI transport for these server-to-client updates. It works
through ordinary HTTPS, has browser reconnection semantics, and is directly
testable. WebSockets remain a future option for a feature that needs genuine
bidirectional streaming; form mutations continue to use server-side POST,
redirect, and flash-message flows.

### Agent-owned alert evaluation

Single-source alert rules should normally execute at the enrolled agent that
already sees the stream. Rules are bounded, declarative, locally configured,
and versioned. The server cannot remotely add a source path, collector, shell
command, or executable rule. An agent evaluates its hot in-memory batch state
without requiring the server to project that stream and emits only bounded
rule-evaluation results: matched, clear, or an explicit evaluation error. The
server remains the authority that applies consecutive-match policy and turns
those evaluations into pending, firing, acknowledged, silenced, and resolved
incident states.

Each transition is authenticated by its enrolled source and binds:

- rule identifier and version;
- source, stream, and agent epoch;
- evaluation window and state;
- exact raw batch sequence range and segment digest evidence; and
- a monotonic transition sequence and observed timestamp.

It contains no telemetry values by default. The server deduplicates the
transition and binds it to the exact retained raw segment before accepting it.
One agent cannot assert another source's scope. Reusing a sequence with
different bytes is corruption, while replaying the same sequence and digest
is an idempotent no-op. During the compatibility phase the server records this
source evidence without mutating incident state; the existing central
evaluator remains the oracle until differential comparisons prove equivalent
results and failure behavior.

This model deliberately trusts an authenticated agent to classify and
evaluate its own data. It still protects ordinary retries, crashes, replay,
configuration drift, and a buggy agent. It cannot prove that a compromised or
offline agent reported honestly. The server therefore retains source
heartbeat, sequence-gap, and enrollment-revocation checks: a dead agent cannot
report its own absence. Cross-source or cross-service correlation remains an
explicit, bounded central workload rather than the default alert path.

The first implementation slice evaluates filter-only log rules over one exact
durable batch. It deliberately excludes historical windows and cross-batch
state while the source and central results are compared. A raw batch remains
in the agent spool until both the raw admission and its source evaluation have
matching acknowledgements. This gives the transition durable retry behavior
without introducing a second telemetry store at the edge.

Incident evidence labels distinguish `source_reported`,
`server_observed_absence`, and `centrally_correlated` conclusions. The current
server-side saved-query evaluator remains the compatibility oracle until edge
evaluation passes differential tests, disconnect/replay testing, and a
production soak. Merely pinning or saving a dashboard never enables eager
evaluation.

### Warm

Frequently used saved queries retain their materializations for a configured
period. Query evidence may propose warming or eviction, but an administrator
approves durable storage-policy changes.

### Observed leases

An authorized live Explore or dashboard session may create a bounded
materialization lease for its exact organization, query, and time window.
Every observer of the same materialization key shares one build/cache entry;
50 or 1,000 viewers increase notification fan-out, not projection work. The
SSE connection carries invalidation notices and renews demand; it does not
carry telemetry and is not itself storage authority. Equivalent future
WebSocket transport would obey the same lease contract.

The key includes the canonical typed query AST, authorized scope, bounded time
window, descriptor generation, and materialization schema. A leased
materialization may contain a query-specific temporary index, but Observatory
does not create a permanent organization-wide index for every dashboard.
Repeated measured benefit may produce a reviewed warm-index proposal with its
estimated build, storage, and write-amplification cost. Approval and quota—not
viewer count alone—promote it to durable policy.

Leases are deduplicated, expire after a disconnect grace period, and are
limited per user and organization. Connection churn cannot create a new
unbounded job, extend retention, or bypass query cost and sensitive-field
permissions. A completed materialization may cool into the ordinary warm cache
or be evicted. Agent-owned rules and server heartbeat checks remain
independent of browser observers; a central cross-source rule acquires its own
explicit, bounded lease.

### Lazy

An ad-hoc historical query first uses the segment catalogue to identify exact
time and scope candidates. A small query may scan them directly under the
ordinary time, byte, row, and memory budgets. A larger query creates a bounded
materialization job. The UI reports its state and progress, then refreshes the
result through SSE; the no-JavaScript path remains a normal status page with a
manual refresh.

The first query is allowed to be slower. It is not allowed to become an
unbounded request, hold an HTTP connection indefinitely, or bypass query
budgets. A materialization that exceeds its approved budget stops with a
specific, resumable status rather than the generic “temporarily unavailable”
response.

## Read and write separation

The ingestion plane is append-oriented: validate, compress, checksum, sync,
catalogue, acknowledge. It does not wait for query indexing.

The read plane is projection-oriented: select only authorized organization,
signal, and time partitions; use exact rollups where semantically valid; merge
partition-local partial results; then apply the final sort and limit. Query
planning limits partition fan-out and reports the raw bytes, materializations,
indexes, permissions, and expected cold work in `explain`.

This preserves SQLite's operational simplicity while allowing concurrent
writers across independent partition files. It also creates a fair test of
SQLite itself: if partition-local insertion remains the measured bottleneck
after index review, the same raw segments and partition contract can be used
to compare another embedded representation.

## What this does not solve automatically

- A memory tail improves visibility, not durable projector throughput.
- Lazy materialization trades continuous background cost for first-query cost.
- Too many tiny partitions increase file, migration, and planning overhead.
- Cross-partition summaries need deterministic mergeable aggregate state.
- Agent rules still consume bounded local CPU and memory, and central
  heartbeat checks still run when no user is online.
- Cross-source rules require reviewed central work and cannot be reduced to
  one agent's local stream.
- Agent compromise or suppression remains a trust boundary; authentication
  proves which enrolled source reported an event, not that the host itself was
  honest.
- Historical regular-expression or high-cardinality queries still require
  strict scan and memory budgets.
- Application-supplied sensitive data remains governed by descriptor,
  authorization, retention, and export policy regardless of storage tier.

## Staged proof

1. Add aggregate cost-centre instrumentation without changing behavior.
2. Generalize the existing budgeted cold-segment reader to prove authorized
   bounded queries over selected hot raw segments; compare every result with
   the current SQLite projection.
3. Add a strict partition catalogue and build one signal/day materialization
   beside the current projection. Differentially test queries, late data,
   duplicates, corruption, cancellation, and restart.
4. Add the bounded recent-memory view and prove overlap deduplication.
5. Move one single-source rule to agent evaluation and one observed dashboard
   to a shared lease. Differentially compare the rule with the current server
   evaluator and prove that many dashboard viewers do not duplicate work.
6. Prove agent restart, offline spool, sequence gaps, duplicate transitions,
   changed rule versions, unavailable-node detection, and lazy evidence
   verification. Keep one reviewed cross-source rule central.
7. Run same-host 100,000- and one-million-observation comparisons, then the
   four-CPU/eight-GiB release campaign.
8. Stop universal row projection only after the adaptive path reproduces the
   current query, incident, retention, rebuild, and authorization behavior.

The first slice of step 2 is implemented as a logs-only, non-public candidate
that reads both hot and cold retained batches under the ordinary typed-query
budgets. Differential tests cover filters, sorting, summaries, regular
expressions, resource scope, an absent projection, and incomplete retention
transitions. The production projection remains the oracle. This candidate
holds the organization lock during its scan and therefore is not yet the
catalogue-snapshot or shared-lease implementation described above.

The published capacity gate is not weakened to make this design pass. If the
product intentionally changes first-query behavior, that contract and its
separate warm-query boundary must be reviewed explicitly before the fixture is
changed.
