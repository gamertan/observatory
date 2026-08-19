<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Recovery and projection rebuild

Observatory treats immutable, checksummed raw segments as the replayable
telemetry truth. Per-organization SQLite projections, custom indexes, query
caches, and rollups are disposable products of that truth.

## Ordinary startup recovery

All three commands reconcile raw segments that reached durable storage before
their control record. `observatory server` then opens its listener and drains
catalogued but unprojected segments through the bounded background projector.
`observatory check` and `observatory migrate` wait for that projection work as
part of their offline verification. This closes both crash windows without
making source acknowledgement or server readiness depend on disposable query
state. Already projected segments are not rewritten.

Discovery walks only private raw-object metadata: organization, source,
stream, sequence, path, encoded size, and the content digest carried in the
immutable filename. Observatory compares already catalogued objects with the
control database without reading their telemetry. Only an object missing from
the catalog is checksum-verified, decompressed, decoded, validated, and
admitted. Pending projections are replayed in bounded, organization-local
groups. This keeps recovery memory proportional to one fixed directory batch,
one bounded segment group, and one small projection page rather than to the
entire retained archive.

That bounded startup path is not a substitute for forensic verification.
Checksums are still verified when an orphan is admitted, a segment is queried,
moved to cold storage, deleted, exported, or used for an explicit projection
rebuild. Operators should schedule those evidence checks and backups rather
than forcing every accepted raw object through memory before the listener can
open.

When an explicit policy enables cold deletion, startup recovery also completes
a segment retirement that was interrupted
after its durable control-state transition. It removes any remaining raw
projection rows, verifies and removes the exact checksummed segment, and only
then clears its control record. A missing retired file is an idempotent state;
a changed file or path is a hard failure.

Cold archival has an earlier independent recovery boundary. Observatory first
records the exact cold path, then atomically renames the verified zstd object,
then advances its catalog tier. Startup safely completes either a pending move
or a move that reached disk before the catalog update. It will not follow a
symlink, accept another path, or rebuild altered bytes.

The shipped policy never starts the retirement transition. Cold raw evidence
therefore remains available until an organization or server operator has
deliberately enabled `delete_cold_raw`; projection expiry and compaction do not
silently imply evidence deletion.

To run retention and SQLite compaction explicitly while the server is stopped:

```sh
observatory migrate \
  --config /etc/gamertan-observatory/server.json \
  --apply-retention
```

The long-running server and ordinary local commands hold a shared lock on the
data directory. Offline migration and projection replacement require an
exclusive lock, so they fail closed while any participating Observatory
process is using that directory.

## Rebuild one organization

Stop the Observatory server, retain a filesystem-level backup, and run:

```sh
observatory migrate \
  --config /etc/gamertan-observatory/server.json \
  --rebuild-organization organization-id \
  --approve-rebuild-organization organization-id
```

The two organization values must match exactly. The command:

1. acquires exclusive ownership of the data directory;
2. refuses unknown organizations, symlinked projections, and unsafe SQLite
   sidecars;
3. reads every registered **hot** raw segment for the organization through the
   checksum-verifying segment store; cold evidence remains outside the fast
   projection and available through the budgeted cold query path;
4. rebuilds the base projection and the organization's activated descriptor
   version beside the live projection;
5. finalizes the replacement as a private standalone SQLite file; and
6. atomically replaces only that organization's projection and synchronizes
   its directory.

Validation or reconstruction failures before activation remove the temporary
files and preserve the existing projection. Other organizations are not
opened or rewritten. The JSON report contains the organization, raw segment
and observation counts, active projection version, and indexed-row count; it
contains no telemetry values.

## Evidence boundary

The rebuild proves that the currently registered checksummed hot segments can
recreate the fast disposable projection. Cold segments remain independently
checksummed forensic truth and are not silently promoted back into hot SQLite.
Neither mechanism replaces backups of the control database, raw/cold segments,
server configuration, identity state, or encryption keys. A missing or corrupt
segment is a hard failure, not a reason to silently accept partial history.

No public Observatory preview exists yet, so there is not yet a supported
cross-preview migration promise. Every future public schema must add an
explicit migration fixture and rebuild campaign before its release can be
called compatible.
