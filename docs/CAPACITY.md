<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Capacity campaign

Observatory's release capacity gate is executable and intentionally narrow. It
measures this implementation on one 4-vCPU/8-GiB Linux boundary; it is not a
claim of generic superiority or unlimited scale.

The campaign:

- sustains 2,000 mixed observations per second for one hour across four
  equally weighted organizations so concurrent isolation and all four
  constrained CPUs are exercised;
- absorbs 10,000 mixed observations per second for 60 seconds;
- requires p95 ingestion-to-query visibility below two seconds;
- expands the primary organization to at least ten million observations and
  runs indexed log and metric-rollup views over its last 24 hours, requiring
  every p95 below three seconds;
- places 72 ordered batches at the edge of the 72-hour outage budget, replays
  them, recognizes a duplicate, and removes local evidence only after an exact
  logical-batch acknowledgement;
- archives expired raw objects unchanged, queries cold evidence, and removes
  only material beyond the final cold cutoff; and
- records bounded RSS and disk growth without emitting a path, host, user,
  credential, source value, or telemetry value.

The aggregate release gate is not a claim that one organization can ingest
10,000 observations per second through its deliberately serialized SQLite
projection. The same fixture accepts `-primary-phase-weight 7` for a separate
70-percent hot-tenant diagnostic and records that weight in its JSON report.
The ten-million-observation query corpus is still built in the primary
organization after the timed phases.

The workload producer and visibility observer run independently. The observer
queries each primary log batch while traffic continues and records when that
timestamp reaches the read model; it never makes the producer wait for its own
query. The achieved ingest rate therefore measures scheduled durable
acceptance, while the separate visibility distribution still captures
background projection lag under the same load.

Run a short development proof with:

```sh
./scripts/capacity-campaign.sh
```

The ordinary public-preview gate runs that development proof after the
complete deterministic verifier and five-second smoke passes for each fuzz
target:

```sh
./scripts/preview-gate.sh
```

This is the default dogfood gate. The hour, ten-million-observation, extended
fuzz, fleet, and 24-hour campaigns are milestone tools. They are not required
for every interface iteration and must not be implied by a preview that did
not run them.

The release campaign must run inside an externally enforced four-CPU,
8-GiB cgroup and requires an explicit mode:

```sh
OBSERVATORY_CAPACITY_MODE=release ./scripts/capacity-campaign.sh
```

The resulting JSON is aggregate evidence. A passing development run does not
replace a run against the exact packaged release commit, its immutable digest,
or the later medium-fleet soak. A campaign that completes every stage but
misses a terminal rate, visibility, query, or memory gate still emits the same
aggregate report with `pass: false` before returning a failure. Earlier stage
failures remain fail-closed and may produce only the bounded stage marker and
error. Individual visibility samples may be observed for up to 30 seconds so
one outlier does not erase the phase evidence; the release boundary remains
the aggregate p95 below two seconds.

Report schema version 2 adds the backlog present immediately after synthetic
fill, projection-drain duration, storage bytes by raw/control/projection class,
and primary-projection SQLite page bytes by checked-in schema object. These are
aggregate performance counters, not telemetry export.

## August 17 constrained-run observations

The first full-duration campaign found a concurrent first-write directory
creation race after completing its one-hour sustain phase. The directory
validator was corrected to tolerate `EEXIST` only long enough to re-inspect the
exact private, non-symlink directory chain, and a 64-writer regression now
protects that boundary.

The corrected implementation was then exercised in a disposable Debian 12
container with four CPUs, 8 GiB of memory, a 1,024-process ceiling, a read-only
root filesystem, no network, all Linux capabilities dropped,
`no-new-privileges`, and a non-root user. The container used the pinned image
digest:

```text
debian@sha256:936abff852736f951dab72d91a1b6337cf04217b2a77a5eaadc7c0f2f1ec1758
```

That run completed 7,200,000 mixed observations in 3,600.38 seconds: about
1,999.79 observations per second, within the one-percent sustain tolerance.
It did not pass the burst gate. The 600,000-observation burst required
227.73 seconds, about 2,634.66 observations per second rather than the required
10,000. The container never reached its memory boundary or an OOM condition;
its observed memory remained below 2 GiB. Aggregate block-I/O counters reached
approximately 57.1 GB while retained test data was approximately 8.1 GB,
identifying synchronous durable-write amplification as the next measured
engineering boundary rather than CPU or memory exhaustion.

Once the burst miss was conclusive, the disposable run was stopped during its
ten-million-observation fill. Its dataset was removed by the fixture's normal
signal cleanup; timestamped stage logs and container exit evidence were
retained. Queries, outage replay, retention, and the final aggregate report
from that run are therefore not release evidence. Observatory will not lower
or relabel the published gate: durable-write grouping and projection work must
be measured, reviewed, and followed by a complete exact-candidate rerun.

## August 18 query-boundary observation

A later constrained candidate reached the complete ten-million-observation
primary corpus but stopped at the first required query. The indexed
`status >= 500` path still scanned and grouped the matching raw log rows, and
the ten-second execution budget expired before it produced the route/window
summary. No aggregate report was emitted, so that run is failure evidence—not
a capacity pass.

The response is an additive, exact five-minute status/route projection. It is
updated in the same SQLite transaction as the primary projection, uses a
per-segment ledger for replay idempotence, backfills older projections once,
and expires with the hot-log projection. A non-aligned lower window boundary
still scans its exact raw fragment, bounded to less than five minutes. Queries
that need cold evidence or do not match the narrow typed shape stay on the raw
path.

Before another full release campaign, the implementation completed the entire
development fixture and a separate one-million-observation diagnostic inside
the release cgroup boundary. The diagnostic used four CPUs and 8 GiB of memory;
the error summary completed five times with a 12.94 ms maximum sample, the
ordinary indexed item view with a 4.59 ms maximum, and the metric rollup with a
3.73 ms maximum. Maximum RSS was 205,545,472 bytes and the dataset was
1,005,353,808 bytes. Those measurements are a scale diagnostic only. They do
not replace the required one-hour, ten-million-observation exact-candidate
campaign or its three-second p95 gate.

## August 18 asynchronous-projection diagnostic

After durable acknowledgement was separated from grouped background
projection, a short local Linux/WSL2 development run exercised the same mixed
fixture with a two-second sustain, two-second burst, 100,000-observation query
corpus, four organizations, and a 500-millisecond visibility target. It was not
run inside the release cgroup and is not release evidence.

The sustain reached about 2,530 observations per second with 31.92 ms p95
ingest time and 201 ms p95 visibility. The burst reached about 10,787
observations per second with 29.83 ms p95 ingest time and 404 ms p95
visibility. The three required query shapes completed with p95 samples of
2.264 ms, 1.992 ms, and 1.512 ms. Maximum RSS was approximately 208 MB and the
dataset approximately 164 MB.

This diagnostic is evidence that acknowledgement-path projection writes were
the measured burst bottleneck and that the revised shape is worth the full
campaign. It does not close the four-CPU/eight-GiB gate, the one-hour sustain,
the 60-second burst, the ten-million-observation corpus, outage replay, or the
exact packaged-candidate requirement.

## August 18 exact-candidate boundary

The exact asynchronous-projection candidate was then run in the release
four-CPU/eight-GiB container. It completed the one-hour sustain, burst, and
ten-million-observation fill without an out-of-memory condition. After a
ten-minute projection drain, 1,118 committed raw segments (922,788,512 bytes)
remained pending and the oldest projection lag was 12 minutes 22 seconds. The
campaign therefore failed closed before the query, outage-replay, retention,
and terminal aggregate stages.

This is useful negative evidence: durable acceptance and bounded memory held,
but projection throughput at that synthetic scale is not yet a supported
claim. The result does not block lower-volume public dogfooding. It does block
calling the release-scale capacity gate complete, and it is the reason that
extended capacity remains a milestone campaign rather than the default
preview loop.

The retained baseline comparisons, rejected multi-row and durability
experiments, and ordered lower-level case studies are recorded in
[PERFORMANCE.md](PERFORMANCE.md). Rejected experiments must not be repeated
without a materially changed premise and a new same-host baseline.
