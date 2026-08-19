<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Descriptive field schema

Every reviewed Observatory field descriptor records its signal, type, unit,
meaning, sensitivity, cardinality budget, index policy, retention class, and
projection version. Built-in fields such as normalized HTTP route and status
already have explicit descriptors.

Unknown attribute keys remain queryable only with the sensitive-telemetry
permission. They default to:

- sensitive;
- high cardinality;
- no index;
- raw retention.

This includes client addresses, raw queries, referrers, user agents, and
anonymous session identifiers selected through an agent source's explicit
`sensitive_fields` policy. Collection and classification are separate review
steps: opting a value into durable raw evidence does not make it public,
low-cardinality, or indexed.

The reviewed sensitivity classes are deliberately small:

- `public`: eligible for an explicitly approved public-safe aggregate;
- `internal`: ordinary authenticated organization telemetry; and
- `sensitive`: separately authorized evidence such as client addresses,
  queries, referrers, user agents, session correlations, or unreviewed fields.

`public` is an eligibility label, not an automatic publication instruction.
A future unauthenticated status view must compile a separate allowlisted
aggregate projection with coarse buckets, minimum group sizes, a publication
delay, and explicit organization approval. It must never expose the
authenticated dashboard, raw records, identifiers, small groups, or query
text. This public-safe projection is roadmap work rather than a capability of
the current private preview.

`raw`, `metric`, and `evidence` are distinct lifecycle classes. `raw` survives
the hot projection cutoff in the checksummed cold archive indefinitely by
default. An organization can opt into an explicit final raw deletion window.
Only reviewed,
non-sensitive, bounded-cardinality metric dimensions marked `metric` enter the
five-minute rollup projection. Selecting `metric` is therefore a retention
decision as well as a query optimization; see
[`RETENTION.md`](RETENTION.md).

After a raw segment is committed, Observatory records one aggregate proposal
summary per unknown field in that segment. The segment digest, organization,
and field form an idempotency key, so ingestion recovery cannot double count
proposal evidence. The proposal contains occurrence count, estimated encoded
bytes, an inferred type, first/last seen times, and a generic query using the
field name. It never stores an observed value or telemetry body.
The batch validator rejects more than 1,024 distinct attribute keys before raw
segment commit so source-controlled field names cannot create unbounded schema
work.

Organization owners can inspect pending proposals locally:

```sh
observatory admin descriptors list \
  --actor-user-id USER_ID \
  --organization-id ORGANIZATION_ID
```

Operating the host or holding the platform-operator role does not grant this
permission. Descriptor review uses the organization-scoped `schema.manage`
grant.

## Review and activation

The list output supplies the inferred descriptor, occurrence count, estimated
encoded bytes, first/last observation time, and generic example query. Review
those values and create a complete descriptor JSON file. The file is an
administrative input, so production requires an absolute, root-owned,
mode-`0600`, regular non-symlink file; JSON is capped at 64 KiB and unknown
properties fail closed.

```json
{
  "version": 1,
  "signal": "metrics",
  "field": "workshop.queue_depth",
  "type": "integer",
  "unit": "items",
  "meaning": "Number of work items waiting in the selected service queue.",
  "sensitivity": "internal",
  "cardinality": "low",
  "index": "range",
  "retention": "raw",
  "projection_version": 1
}
```

The input projection version is a placeholder; Observatory assigns the next
organization-local version during activation.

```sh
observatory admin descriptors activate \
  --actor-user-id USER_ID \
  --organization-id ORGANIZATION_ID \
  --descriptor-file /root/reviews/workshop.queue_depth.json
```

Activation copies every currently active descriptor into a new immutable
version, builds the complete typed custom-field index beside the current one,
and changes the active version inside the same organization-database
transaction. Invalid historical values stay in raw evidence but are not
coerced into the index. New ingestion writes to the active version. Old index
tables remain available for recovery, and retry repairs an interrupted
control-database acknowledgement without rebuilding an already active,
identical descriptor.

A proposal that should not become part of the reviewed schema can be rejected
idempotently:

```sh
observatory admin descriptors reject \
  --actor-user-id USER_ID \
  --organization-id ORGANIZATION_ID \
  --signal metrics \
  --field workshop.queue_depth
```

An active descriptor cannot be rejected. Revision of an already active
descriptor requires a future explicit review-proposal workflow; the current
command will not silently reinterpret an active field.
