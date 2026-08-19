<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Retention and metric rollups

Observatory enforces the server policy in `server.json` after startup recovery
and once per hour:

- hot log projections: 30 days;
- hot trace projections: 30 days;
- hot raw metric projections: 14 days;
- immutable cold raw segments: preserved indefinitely by default;
- five-minute metric rollups: 400 days; and
- deployment events, resolved incidents, and security audit evidence: 400 days.

All values are explicit configuration. The list above is the shipped example,
not a hidden fallback. `cold_raw_days` becomes a final raw-evidence cutoff only
when `delete_cold_raw` is explicitly enabled. It is not an additional window
after the hot cutoff.

## Hot and cold evidence

Raw batches are already independently Zstandard-compressed and addressed by
their SHA-256 digest. Observatory does not wrap them in a gzip tarball: that
would make selective verification and opening slower while usually saving
little space over already-compressed input. When the newest observation in a
segment leaves its hot window, Observatory atomically moves the exact object
from `raw/` to `cold/` and advances its catalog tier. No telemetry is decoded,
rewritten, or recompressed during that move.

Cold queries are intentionally allowed to take longer. Their explain estimate
includes each selected segment's catalogued uncompressed size. Execution
validates the catalog path and time range, verifies the compressed checksum,
decodes a bounded segment, and applies the same tenant scope, sensitive-field
authorization, typed filters, scan limit, memory limit, row limit, and timeout
as a hot query. Matching cold metric segments force an exact raw query instead
of mixing incomplete history with aggregate rollups.
The explain plan adds `/cold:raw` whenever this tier participates.

The default therefore preserves forensic raw detail without an automatic
destruction date. Projections and rollups still expire on schedule, so ordinary
queries stay compact while a deliberate cold query can recover exact older
evidence at an accepted additional cost. Full-disk encryption, protected
backups, quota planning, and filesystem capacity remain operator
responsibilities in the first preview.

Forensic retention applies only **after** Observatory's collection boundary.
It does not mean collect everything: request and response bodies remain off by
default, known credential and header deny rules run before spooling, source
adapters use allowlists, and unknown fields remain sensitive and unindexed.
An operator must still choose lawful inputs and retention appropriate to the
people and systems represented by the evidence.

Observatory does not currently combine cold objects into `tar.gz` archives.
Each raw batch is already zstd-compressed and content-addressed, so another
compression layer would usually save little while making selective reads and
independent checksum verification harder. A future high-inode-volume backend
may pack many unchanged zstd objects into an immutable checksummed container
with a separate bounded index. Such a pack must be completely written,
verified, and catalogued before its source objects can be retired; packing must
never change their logical digests or tenant boundaries.

## What a rollup retains

Every metric ingest updates its five-minute aggregate in the same SQLite
transaction as the raw projection. Each aggregate retains exact count, sum,
minimum, maximum, and the last sample value/timestamp plus a bounded deterministic
histogram. `p50`, `p95`, and `p99` over rollups are approximations and the
query result sets `statistics.approximate` to `true`. Count, sum, minimum,
maximum, and average remain exact for the retained samples.

Longer retention never silently widens the data boundary. A dimension enters
a rollup only when its descriptor is:

- reviewed or an Observatory built-in;
- marked with the `metric` retention class;
- public or internal, never sensitive; and
- low or medium cardinality.

Unknown, sensitive, and high-cardinality attributes remain raw-only. The
explain plan names `/rollup:5m` whenever the aggregate projection is selected.
Queries that filter individual values, request sub-five-minute buckets, or
need fields unavailable in the aggregate continue to use raw samples.

Metric values are bounded to an absolute value of `1e25`. This is far beyond
ordinary duration, byte, counter, and host measurements while keeping sums
and the fixed histogram domain finite under hostile input.

## Organization policy

An organization owner can shorten a policy:

```sh
sudo observatory admin retention set \
  --config /etc/gamertan-observatory/server.json \
  --actor-user-id USER_ID \
  --organization-id ORGANIZATION_ID \
  --raw-logs-days 14 \
  --raw-traces-days 14 \
  --raw-metrics-days 7 \
  --cold-raw-days 180 \
  --delete-cold-raw \
  --metric-rollups-days 180 \
  --evidence-days 180
```

`cold_raw_days` cannot be shorter than any hot raw/evidence window. Omit
`--delete-cold-raw` to preserve cold evidence indefinitely. Enabling deletion
is an explicit shortening policy. Extending any server default—including
turning off deletion when the server default enables it—additionally requires
the exact organization ID and a positive byte quota larger than the
organization's current stored data:

```sh
  --approve-extension ORGANIZATION_ID \
  --quota-bytes 10737418240
```

The policy change and actor are recorded without telemetry values. A quota is
checked before accepting another raw segment, using current raw/projection
storage plus a conservative allowance for the new projection. Secret values
never enter the policy, audit summary, command output, or process arguments.

## Deletion and recovery boundary

Projected observations expire at their individual hot timestamps. Raw
segments are immutable, so a segment becomes cold only when its newest
observation crosses that signal's hot cutoff. A batch spanning multiple
timestamps can therefore keep its older members hot until the newest member
expires; agents should keep batches time-local. The pending archive path is
recorded first, the exact segment is verified and atomically moved, both
directory entries are synchronized, and the tier is advanced. Startup recovery
safely completes an interruption before or after the rename.

Only when `delete_cold_raw` is true does the final cold cutoff separately mark
the segment retiring. Its
remaining projection and per-segment rollup ledger rows are removed, its
checksum/path are revalidated, its file and directory entry are synchronized,
and finally its control record is deleted. A missing file is accepted only for
the recorded interrupted-retirement state; changed bytes or another path stop
recovery.

Metric rollups are disposable projections. Their expiration and SQLite
compaction do not alter hot or cold raw evidence. Projection rebuilds use only
hot segments so they do not turn the fast database back into an archive; the
query engine opens cold evidence directly when requested. Once the final cold
window expires under that explicit policy, rebuilding intentionally cannot
recreate those deleted samples. Backups must follow the same published
retention and deletion policy.
