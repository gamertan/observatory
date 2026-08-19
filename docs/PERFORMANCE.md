<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Performance engineering ledger

This document preserves measured optimization work, including changes that
were deliberately rejected. It prevents an attractive idea from being
reimplemented and rerun without a materially different premise.

The capacity fixture is a synthetic engineering instrument. Its local results
are useful for comparing two exact implementations on the same host; they are
not production sizing claims and do not replace the constrained release
campaign in [CAPACITY.md](CAPACITY.md).

## Current data path

Observatory deliberately separates four jobs:

1. the agent batches typed observations;
2. the server validates and durably acknowledges an immutable, checksummed,
   zstd-compressed raw segment;
3. a background projector builds disposable per-organization SQLite read
   models, typed indexes, and rollups; and
4. queries read authorized projections or budgeted cold evidence.

Raw segments are the forensic truth. SQLite is currently a replaceable query
accelerator, not the only copy of an observation. A bounded in-memory layer may
accelerate the recent live window, but it must populate only after raw
acknowledgement and must remain safe to lose and rebuild.

## Experiment ledger

All August 18 local comparisons used the same Linux/WSL2 checkout based on
private commit `7c4f834aee8afcb2e9c3ae534b1b37b03259c9a3`, Go 1.26.6, the same synthetic
mixed workload, and an unconstrained 16-logical-CPU host. They are comparative
diagnostics, not release evidence.

| Experiment | Corpus | Sustain / burst | Visibility p95 | Fill or query notes | Result |
| --- | ---: | ---: | ---: | --- | --- |
| Existing prepared single-row projection writes | 100,000 | 2,630.64/s / 13,084.50/s | 84.7 ms / 228.1 ms | about 198 MB peak RSS; about 176.9 MB dataset | Baseline retained. |
| 256-row multi-value SQLite inserts | 100,000 | 2,631.28/s / 13,015.34/s | 200.7 ms / 382.3 ms | about 197 MB peak RSS; about 205.6 MB dataset | Rejected and removed: no throughput gain, worse visibility and storage. |
| `synchronous=NORMAL` projection plus transaction receipts and recovery reconciliation | 100,000 | 2,630.13/s / 12,991.85/s | 175.35 ms / 230.76 ms | 199,081,984-byte peak RSS; 177,218,281-byte dataset | Rejected and removed: added recovery machinery without a measurable throughput gain. |
| Existing prepared single-row projection writes | 1,000,000 | 3,815.33/s / 18,901.41/s | 121.83 ms / 257.26 ms | fill 6.604 s; queries 6.226/1.839/1.557 ms; 1,090,726,860-byte dataset | Larger baseline retained. |
| `synchronous=NORMAL` projection plus receipts | 1,000,000 | 3,823.49/s / 18,766.63/s | 173.67 ms / 219.41 ms | fill 6.789 s; queries 6.637/1.721/1.586 ms; 1,092,327,298-byte dataset | Rejected and removed: within noise on throughput, slower fill, larger dataset. |

Do not repeat either rejected experiment unless the transaction shape, schema,
SQLite version, storage medium, or workload has materially changed. Record the
new premise and a same-host baseline before doing so.

## Native v2 exact-replay envelope

The native v2 endpoint places bounded batch identity metadata in authenticated
request headers before the JSON record body. A retry of the current
acknowledged `(source, stream, sequence)` can therefore hash and discard the
complete bounded body, recheck the watermark under the source lock, and return
the retained acknowledgement without JSON decoding, zstd compression,
catalogue writes, or projection notification. New batches still follow the
complete validation and raw-first transaction.

An August 18, 2026 Linux/amd64 Go 1.26.6 HTTP-handler microbenchmark used an
exact 500-record, approximately 60.6-KB JSON retry on an Intel i7-10700K. Five
independent benchmark samples recorded:

| Path | Median time | Bytes allocated/op | Allocations/op |
| --- | ---: | ---: | ---: |
| Legacy native v1 exact retry | 4.105 ms | about 22.4 MB | about 14,760 |
| Framed native v2 exact retry | 0.275 ms | about 49.9 KB | 301 |

For this one retry workload, v2 used about 14.9 times less wall time, 449 times
fewer allocated bytes, and 49 times fewer allocations. Reproduce with:

```sh
go test -buildvcs=false ./internal/httpserver \
  -run '^$' -bench '^BenchmarkNativeExactReplay$' -benchmem -count=5
```

This is not new-batch throughput, whole-agent delivery latency, or a production
capacity result. It proves only that the early exact-replay path removes the
intended duplicate work. The server still reads and hashes every replay byte;
transport integrity and the immutable retained segment remain authoritative.

## First cost-centre diagnostic

The capacity report now records projection backlog/drain time, raw/control/
projection file bytes, and SQLite page use by schema object. The fields contain
only aggregate counts and checked-in schema names; they contain no telemetry
values, tenant identifiers, or local paths.

An unconstrained local 100,000-primary/109,000-total observation diagnostic on
the same August 18 baseline recorded:

- 19 pending segments and 14,936,883 decoded bytes at the start of drain;
- 4.580 seconds to drain that backlog;
- 446,217 bytes of compressed raw segments;
- 158,247,552 bytes across all organization projection SQLite files and
  sidecars;
- 1,705,496 bytes of control SQLite files and sidecars; and
- 97,124,352 allocated SQLite page bytes in the primary projection, comprising
  28,409,856 table bytes, 68,702,208 index bytes, and 12,288 internal bytes.

The synthetic observations compress unusually well, so the roughly 355:1
projection-to-compressed-raw ratio must not be extrapolated to real telemetry.
The within-SQLite result is still actionable: indexes consumed about 2.42
times the table bytes and about 70.7 percent of allocated primary-projection
pages. Index write amplification is therefore the first implementation case
study. This one short diagnostic is not a release capacity result.

## Presence-only base-index candidate

The first index case study replaced four full projection indexes with partial
indexes that contain only observations where the indexed value is present:
metric value, HTTP route, HTTP status, and request duration. Severity remains
a full index because its current storage representation uses an empty string
for absence. The migration is independently versioned and changes the old and
new index sets in one SQLite transaction; an interrupted migration therefore
retains the complete prior set and safely retries.

Same-host comparisons against the cost-centre baseline recorded:

| Corpus | Baseline index bytes | Candidate index bytes | All projection SQLite | Projection drain | Query p95 notes |
| ---: | ---: | ---: | ---: | ---: | --- |
| 100,000 primary observations | 68,702,208 | 57,135,104 (-16.8%) | 158,247,552 to 143,429,744 (-9.4%) | 4.580 s to 4.704 s | Same millisecond range; drain difference is within short-run noise. |
| 1,000,000 primary observations | 693,755,904 | 572,768,256 (-17.4%) | 1,087,731,688 to 954,606,472 (-12.2%) | 58.267 s to 54.535 s (-6.4%) | Baseline 6.157/1.908/1.659 ms; candidate 6.156/5.444/1.680 ms. The isolated recent-items increase remains only milliseconds and needs repetition before interpretation. |

The million-observation candidate retained the identical 283,639,808 table
bytes and reduced the primary projection from 977,408,000 to 856,420,352
allocated bytes. Synthetic compressed raw sizes were 4,011,063 and 4,031,350
bytes respectively; that small corpus variance is not attributed to the index
change.

This is a promising bounded schema improvement, not proof that continuous
universal projection is the final architecture. Migration and selective-query
tests must pass from legacy preview databases, followed by the full verifier
and trusted CI, before adoption. The adaptive raw-first design remains the
larger direction.

## What the evidence says

SQLite is not yet proven to be the limiting technology. The failed
ten-million-observation campaign proves that the current *projection shape*
cannot drain the synthetic fill inside the published window. It does not
separate SQLite's engine cost from Observatory's choices around row shape,
index count, JSON expression indexes, typed descriptor indexing, rollups, WAL
checkpoints, or single-organization serialization.

The two rejected experiments also show that transaction syntax and one
durability pragma are not the dominant cost. The next work must measure cost
centres instead of swapping databases or adding cache infrastructure by
intuition.

## Required cost-centre evidence

Add aggregate, value-free timing and byte counters to the synthetic fixture
for:

- native batch validation, JSON encoding, zstd compression, file write,
  file `fsync`, directory `fsync`, and control-catalog commit;
- raw-segment open, checksum, decompression, and decode;
- base observation insertion, built-in index maintenance, reviewed custom
  index maintenance, metric rollups, log rollups, WAL commit, and checkpoint;
- projector queue depth, oldest lag, rows and bytes per transaction, active
  writer time, and time waiting for an organization lock; and
- query planning, rows/bytes scanned, SQLite execution, cold decode, and result
  encoding.

These counters belong only in the capacity fixture or bounded internal
instrumentation. They must not include telemetry values, local paths,
credentials, host names, or tenant identifiers.

Projection backlog/drain and file/page accounting above are implemented. The
per-operation CPU/wall-time breakdown remains open.

## Ordered technical case studies

The larger lazy/eager partition design is specified in
[ADAPTIVE_PROJECTIONS.md](ADAPTIVE_PROJECTIONS.md). The ordered experiments
below are its evidence path, not independent promises to ship every idea.

### 1. Index write amplification

The base observation table currently maintains its primary key plus general
scope/time/name indexes and signal-specific severity, value, correlation, HTTP
JSON-expression, trace, and span access paths. Measure per-index bytes and
projection time. Compare only reviewed alternatives such as partial
signal-specific indexes or replacing a generic expression index with an exact
rollup already used by the supported query shape. Every candidate must rerun
the existing query and cold-evidence gates.

### 2. Time and signal partitioning

One organization currently has one SQLite writer. A partition per bounded time
window and/or signal could let logs, metrics, and traces project concurrently,
limit index working sets, and make retention a file-level operation. The cost
is a more complex planner, bounded multi-database queries, atomic partition
catalogue changes, and additional recovery cases. Prototype this only after
the index-cost campaign identifies single-database write amplification.

### 3. Bounded recent-memory view

A per-organization ring keyed by segment digest can make the latest live tail
visible immediately after durable raw acknowledgement while disk projection
continues. Queries would merge the bounded memory window with disk results and
deduplicate by segment/record identity. This improves live experience and
absorbs short projection bursts; it does not increase durable projector
throughput and must never become acknowledgement truth.

### 4. Durable admission group commit

Each accepted native batch currently creates and synchronizes its own raw file
and directory, then commits the control catalogue. A bounded group-commit
coordinator could acknowledge several independent streams after one directory
sync and one control transaction. It must preserve per-stream ordering,
organization quota checks, exact digest acknowledgements, cancellation, and a
small maximum wait. This is relevant only if cost-centre evidence places the
limit on durable admission rather than projection.

### 5. Projection representation

If row/index tuning and partitioning remain insufficient, compare a compact
typed projection representation against SQLite on identical raw segments.
Candidates must retain authorization-before-open, bounded queries, atomic
replacement, offline rebuild, corruption handling, and small-server operation.
An external database is not an optimization if it merely moves the same write
amplification into more infrastructure.

## Database decision boundary

Keep SQLite while it satisfies the measured small-server boundary with simpler
operations. Consider another embedded or external engine only after an exact
candidate demonstrates that the required workload remains blocked by SQLite
itself after index, partition, and batching work. Any replacement must beat the
same fixture while preserving tenant isolation, raw replay, deterministic
recovery, query budgets, deployment simplicity, and idle resource use.
