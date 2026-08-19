<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Query execution

Observatory's text editor and assisted visual builder produce the same
versioned typed AST. The builder serializes its bounded controls to reviewable
query text and submits that text to the ordinary parser; it does not create a
parallel query language or bypass validation. Query text never selects or
overrides an organization: the HTTP server and local CLI authorize the
requested resource scope separately before planning or opening its projection.

```text
logs
| where service == "eql"
| where status >= 500
```

Use one `where` stage per comparison in the current preview:

```text
logs
| where service == "eql"
| where status >= 500
| window 24h
| summarize count(), p95(duration) by route, window(5m)
| sort count desc
| limit 50
```

`window 24h` limits the lookback range. `window(5m)` creates five-minute
summary buckets; these are separate AST fields. Filters are typed from reviewed
field descriptors. Regular expressions use Go's bounded RE2 implementation,
not a backtracking engine. Arbitrary SQL is never accepted.

The first assisted builder covers one optional comparison, one lookback, one
optional aggregate, one optional grouping field, one optional time bucket, and
a fixed row limit. Values are quoted before serialization and a literal
pipeline character is escaped before parsing, so form values cannot introduce
new stages. Multi-filter and multi-aggregate work remains in the text editor
until a richer builder can preserve the same explicit AST contract.

Reviewed custom fields use the active per-organization descriptor registry.
An exact or range filter on an activated indexed field is correlated through
that version's typed index instead of casting arbitrary raw JSON. Values that
did not satisfy the reviewed type during the index build remain in raw truth
but do not silently become zero or another valid indexed value.

Unknown fields remain raw-queryable only to principals with the separate
sensitive-telemetry permission. Results contain fixed safe identity columns
plus fields explicitly referenced by the query; sensitive bodies are never a
default result column.

Every execution has independent duration, row, projected-byte, and memory
limits. `explain` reports the authorized projection, descriptors, index policy,
conservative scan estimate, cache eligibility, permissions, and budgets before
execution.

## Storage scale is not query cost

Observatory deliberately separates admission of evidence from execution of a
query. A large organization store, historical import, or forensic archive is
not itself a reason to reject new data or a small recent query. Ingestion and
import use their own explicit storage quotas, bounded batches, backpressure,
durable progress, and capacity checks. Query limits never act as an implicit
organization-size quota.

Planning considers the authorized signal, resource scope, time window,
available indexes or rollups, and result limit. A projection file's total size
alone must not make an indexed, bounded recent-record query unavailable. The
executor still enforces actual duration, rows, logical bytes read, and memory;
summaries, alternate sorts, regular-expression filters, and cold forensic
reads retain conservative preflight because they may need to examine more of
the selected evidence. `explain` should make that distinction visible rather
than promising that a cheap result follows from a small output alone.

A log summary with one canonical `status >= N` threshold, `count()`, a route
group, and either no bucket or a multiple-of-five-minute bucket uses an exact
five-minute projection. Its explain source ends in
`/rollup:http-status-route:5m`. The server still injects the organization and
optional project, environment, and service scope; the same duration, scan,
memory, and result limits apply. Missing routes remain distinct from explicitly
empty routes, and malformed stored statuses are excluded rather than cast to
zero. A lower time boundary inside a bucket reads only that raw partial bucket
and merges it with the complete projected buckets. Queries outside that exact
shape remain on the general executor instead of receiving a different
interpretation merely to reach a faster plan.

Metric summaries with no per-sample value filter and a bucket of at least five
minutes can use the retained aggregate projection. Its explain source ends in
`/rollup:5m`. Counts, sums, minima, maxima, and averages remain exact;
percentiles use the bounded rollup histogram and set
`statistics.approximate=true`. Unknown, sensitive, high-cardinality, and
raw-only fields make the query use raw samples instead of silently reading an
incomplete rollup.

Hot projection expiry does not make older evidence disappear. A query whose
lookback overlaps cold segments includes their catalogued uncompressed size in
the explain estimate, verifies and decompresses each exact zstd object, and
applies the same organization scope, sensitive-field permission, typed
filters, and execution budgets. This path deliberately accepts more latency
for forensic detail. If matching cold metric segments exist, Observatory uses
the exact raw path rather than combining them with an incomplete rollup.
The explain source adds `/cold:raw` when that tier participates.

## Local authorized query

The local command reads query text from standard input so values do not need to
appear in process arguments. Local operating-system access does not grant
telemetry access: `--actor-user-id` must still hold the scoped query grant.

```sh
printf '%s\n' 'logs | where status >= 500 | window 1h | limit 50' |
  observatory query \
    --actor-user-id USER_ID \
    --organization-id ORGANIZATION_ID
```

Use the optional project, environment, and service flags to narrow the
authorized scope. Output is a stable versioned JSON table: column descriptors
are ordered once and each row contains positional nullable string values in the
column's declared type and unit.

## HTTP endpoints

- `POST /api/v1/query/parse` validates text or builder AST input.
- `POST /api/v1/query/explain` requires a scoped query grant.
- `POST /api/v1/query` executes the same authorized plan.

Session-backed endpoints require the canonical same origin. Error responses do
not echo query values or telemetry.
