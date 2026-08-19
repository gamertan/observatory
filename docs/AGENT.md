<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Agent boundary

The Observatory agent is an unprivileged outbound collector. Its local JSON
configuration is authoritative: the server cannot add a path, collector,
command, socket, or environment value remotely.

Configuration and the enrolled credential remain separate root-owned
mode-`0600` regular files under `/etc`. The example systemd unit uses
`LoadCredential=` to expose private, read-only runtime copies to the dedicated
service account. `observatory agent --systemd-credentials` confines both paths
to direct children of systemd's `CREDENTIALS_DIRECTORY`; the agent itself does
not run as root. Its service account receives read access only to the explicitly
selected Caddy, application, and Tend streams. It does not need a Docker socket,
an inbound port, a shell plugin, or write access to the source logs.

The producer and its operator remain authoritative for what a source log is
allowed to contain. Observatory is not a universal DLP system and cannot infer
an organization's private vocabulary or prove that a renamed field is safe.
The initial adapters therefore use a documented fixed field set before durable
spooling, plus a small source-specific `sensitive_fields` list. This is a
defence-in-depth boundary and a useful safe default—not permission to log a
secret upstream. An absent list means the privacy-minimized fields below, and
Observatory never widens it remotely.

- Caddy: method, query-free path, status, response bytes, duration, and a
  syntactically bounded request ID. The shipped Caddy example appends that ID
  from the completed response as a dedicated top-level field, then removes
  the complete request-header and response-header maps, client addresses,
  user identity, and the URI query before the edge record reaches disk;
- Web Foundations requestlog: method, normalized route, status, response bytes,
  duration, authorization outcome, and request ID;
- Tend: the strict version-1 bounded activation and rollback event fields;
  unknown, malformed, unsafe, oversized, or trailing data is rejected.

The optional `linux_metrics` source reads aggregate CPU ticks, load, uptime,
memory, network counters, named filesystem capacity, selected cgroup v2
counters, and processes named by explicit PID files. It never enumerates all
processes, reads command lines or environments, invokes a shell, or opens a
collector port. Configuration assigns stable public labels so local paths and
PIDs are not stored as telemetry attributes. A disappearing selected process
or cgroup emits an `up=0` metric while other host evidence remains durable.

Cookies, authorization headers, request and response bodies, arbitrary
headers, and unknown JSON fields never enter the native batch. By default,
raw query strings, client addresses, referrers, user agents, and anonymous
session identifiers do not enter it either. An application whose documented
privacy policy and operating need permit richer evidence may opt in per source:

```json
{
  "kind": "caddy_json",
  "path": "/var/log/caddy/example-access.jsonl",
  "stream_id": "caddy-access",
  "sensitive_fields": ["client_ip", "query", "referrer", "user_agent"]
}
```

`caddy_json` accepts `client_ip`, `query`, `referrer`, and `user_agent`.
`requestlog_jsonl` accepts those fields plus `session_id`. Unsupported and
duplicate names fail configuration validation. Values remain bounded, and IP
addresses must parse as IPv4 or IPv6. Selected values enter Observatory as
unknown sensitive, high-cardinality, unindexed raw fields until an authorized
schema review explicitly classifies them. Query and referrer values can carry
credentials or personal data even when collection is disclosed; filter known
secret-bearing parameters at the producer, restrict access, and choose a
retention window appropriate to the application's policy. The copyable
`Caddyfile.sensitive-access-log` demonstrates the intended producer boundary.

Source scope is not read from any log; it comes from the server-side enrollment
record after credential verification.

## Batching and delivery cadence

`flush_interval` is the maximum delay between collection cycles while the
agent is healthy. `batch_records` caps the number of observations read into
one durable batch for one stream during that cycle; it is not a reason to wait
for a quiet stream to fill. Each batch is committed to the local spool before
its source cursor advances, and delivery removes it only after an exact server
acknowledgement.

Larger batches amortize filesystem, compression, HTTPS, and server admission
costs. A shorter interval reduces live-view latency. The checked-in profile
uses up to 5,000 records once per second. Operators can select any validated
combination from 1 to 5,000 records and 100 milliseconds to one minute based
on source volume and desired freshness. The tailer also caps bytes read during
one cycle, so an existing multi-gigabyte file is caught up over bounded cycles
rather than loaded into memory at once.

The file tailer reads at most 4 MiB of source data per cycle while the checked-
in server accepts at most 32 MiB per authenticated request. That headroom
accounts for native-batch JSON framing without making request memory
unbounded. The server also admits at most eight concurrent authenticated
ingestion bodies. A future byte-aware batcher should make the source/request
relationship explicit for custom profiles that choose different ceilings.

The spool fails closed at its configured byte or age budget. A server
acknowledgement must match the exact source, stream, sequence, and canonical
logical-batch digest before the agent removes its local batch. The local spool
envelope retains a separate digest because it also contains the cursor
checkpoint; private storage encodings are not treated as protocol identities.
Each pending envelope carries
a bounded cursor checkpoint. Startup applies those checkpoints before it reads
new bytes, so a crash between the spool commit and state-file replacement
cannot duplicate a different payload under the same sequence. Collected records
advance only after that envelope is durable; deliberately discarded complete
records advance only after their bounded counters and cursor are durably saved.

Delivery uses the versioned native v2 endpoint. The agent supplies bounded
stream, sequence, signal, exact encoded-body digest, canonical logical-batch
digest, record/byte counts, and first/last observation times as request
metadata. Source and organization scope still come only from the enrolled
credential. On an exact retry the server reads and hashes the complete bounded
body but does not decode, recompress, recatalogue, or reproject it. Time ranges
help select storage and query partitions; overlapping ranges and repeated
values remain valid and are never treated as record-level duplicates.

## Local alert rules

An agent may evaluate an optional, locally configured rule against one exact
log batch after that batch is durable. The first supported rule shape is
deliberately narrow: one `caddy_json` or `requestlog_jsonl` stream, one or more
typed `where` filters, no sort, summary, or historical window, and a bounded
minimum match count. It uses the same typed filter implementation as the
central query evaluator.

```json
{
  "alert_rules": [
    {
      "version": 1,
      "id": "http-failures",
      "revision": 1,
      "stream_id": "application-request",
      "query": "logs | where status >= 500 | limit 10",
      "minimum_matches": 1
    }
  ]
}
```

The identifier and revision must name an enabled, source-scoped server rule
whose saved query has the same intended semantics. Configuration remains
local; the server cannot install or edit this rule. After the raw batch is
acknowledged, the agent reports only `matched`, `clear`, or `error`, its local
rule identity, the exact raw segment identity, the batch time range, and a
monotonic sequence. It sends no telemetry values in that transition.

The raw spool entry is removed only after both acknowledgements match. If the
transition request fails, retrying first replays the same raw batch as an
idempotent no-op and then replays the same transition. During this
compatibility phase the server stores the authenticated source result but does
not mutate incident state from it. The existing central evaluator remains the
oracle until differential tests and a production soak demonstrate equivalent
results and failures. Multi-batch windows, cross-source rules, and server-owned
incident confirmation remain central work in this preview.

The tailer preserves incomplete lines, discards oversized or malformed
complete records without retaining their contents, caps read work per cycle,
detects copy-truncation, and follows an unread inode through a rename in the
configured file's directory. If the old inode has already disappeared, the
agent records a discontinuity and begins the new file; it does not claim that
unrecoverable bytes were observed.

An organization-authorized local administrator writes a short-lived
enrollment token directly to a new mode-`0600` file. `observatory agent enroll`
exchanges it once over HTTPS and creates the configured credential file without
overwriting any existing secret. If the credential cannot be written, the
client asks the server to revoke the newly enrolled source.

Create the source's resource hierarchy through the supported offline
administration commands before issuing an enrollment. Each command acquires
the same shared process lock as the live server, validates its exact parent
scope, requires the actor's `organization.manage` grant, and returns only
generated public identifiers. Normal hierarchy and enrollment administration
can run while the server is live. Exclusive migrations still require the
server to stop. Never edit the control database directly.

```sh
sudo observatory admin project create \
  --config /etc/gamertan-observatory/server.json \
  --actor-user-id USER_ID \
  --organization-id ORGANIZATION_ID \
  --slug gamertan \
  --name 'Gamertan'

sudo observatory admin environment create \
  --config /etc/gamertan-observatory/server.json \
  --actor-user-id USER_ID \
  --organization-id ORGANIZATION_ID \
  --project-id PROJECT_ID \
  --slug production \
  --name 'Production'

sudo observatory admin service create \
  --config /etc/gamertan-observatory/server.json \
  --actor-user-id USER_ID \
  --organization-id ORGANIZATION_ID \
  --project-id PROJECT_ID \
  --environment-id ENVIRONMENT_ID \
  --slug web \
  --name 'Web application'
```

Creating the hierarchy is intentionally incremental: a successfully created
project remains a valid resource if a later environment or service command is
rejected. Slugs are unique within their parent, and failed authorization or
parent validation creates nothing.

```sh
sudo observatory admin enrollment create \
  --config /etc/gamertan-observatory/server.json \
  --actor-user-id USER_ID \
  --source-id HOST_SOURCE_ID \
  --organization-id ORGANIZATION_ID \
  --project-id PROJECT_ID \
  --environment-id ENVIRONMENT_ID \
  --service-id SERVICE_ID \
  --lifetime 15m \
  --output-file /etc/gamertan-observatory/new-agent-enrollment.json

sudo observatory agent enroll \
  --config /etc/gamertan-observatory/agent.json \
  --enrollment-file /etc/gamertan-observatory/new-agent-enrollment.json

sudo systemctl enable --now observatory-agent.service
```

The token and credential never appear in command arguments: only their file
paths do. Remove the enrollment-token file after a successful exchange. The
copyable unit in `examples/observatory-agent.service` documents the supported
unprivileged runtime boundary.

## Production dogfood profile

The checked-in `release/agent.json` and `release/observatory-agent.service`
describe the first production profile. One host-scoped source credential is
bound to the public application node. Locally authoritative collectors keep
EQL's edge and application evidence in distinct streams and collect aggregate
Linux and selected service-cgroup metrics. This scope does not imply that all
telemetry belongs to the Observatory application merely because Observatory
receives it.

The profile intentionally omits `sensitive_fields`. Client addresses, query
strings, referrers, user agents, and session identifiers therefore remain out
of the agent spool and server. They may be enabled later, per stream, only
after the producer filter, privacy policy, access grants, and retention window
have been reviewed. The capability remains supported; privacy minimization is
the production default rather than an architectural prohibition.

The Observatory origin's own Caddy access log is not collected by this first
profile. Ingesting the agent's requests from that log would create a perpetual
self-observation loop. The profile does collect the bounded Tend event files
for Gamertan, Sandwich Hime, and Observatory as three independent streams.
Their application release state remains authoritative; ingestion is evidence,
not a deployment dependency.

The service account has supplementary read-only membership in the `caddy` and
`eqlwiki` groups, write access only to its private state directory, no inbound
listener, no Docker socket, and no shell. `PartOf=gamertan-observatory.service`
restarts the agent when a Tend activation moves the shared `current` binary,
so server and agent do not drift across releases.
