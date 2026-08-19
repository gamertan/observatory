<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Tend deployment boundary

Observatory pins Tend `v0.2.0-preview.2` as a checksum-verified Go tool and uses
its schema-2 singleton-candidate strategy on Linux. The
release configuration is [`release/tend.json`](../release/tend.json). It pins
the public origin, live and candidate loopback addresses, health paths,
application marker, release root, state path, shared host lock, and exact build
package. It contains no secret values.

## Two deliberately different processes

The installed service explicitly runs:

```text
observatory server --config %d/server.json --systemd-credential-config
```

Systemd copies the root-owned mode-`0600` configuration and Web Push private
key into the service's private credential directory. Systemd 255 presents each
runtime copy as a root-owned mode-`0440` credential confined to the unit;
Observatory accepts that mode only when explicit systemd-credential validation
also proves the credential-directory boundary and owner. The static
`gamertan-observatory` service user can read those copies and write only its
state directory. The originals stay root-owned mode `0600` under
`/etc/gamertan-observatory/`.

Local operator commands that read the server configuration use the same
explicit `--systemd-credential-config` flag and confined credential-directory
policy. This applies to bootstrap, resource and enrollment management,
retention and schema review, local queries, dashboard import/export, and
migrations; no operator workflow needs a less restrictive duplicate config.

Tend executes a candidate binary without arguments and supplies only
`OBSERVATORY_TEND_CANDIDATE_LISTEN=127.0.0.1:18093`. That narrowly named mode:

- accepts only a numeric loopback address and nonzero port;
- exposes only `/`, `/healthz`, and `/readyz` over plain loopback HTTP;
- returns a fixed marker and security headers;
- does not read configuration, open storage, acquire a process lock, run a
  migration, evaluate alerts, send Web Push, access the network, or write a
  file.

The candidate proves that the exact binary starts and answers its bounded
contract. It does not pretend to prove a live data migration. After the
candidate passes, Tend stops it, atomically selects the immutable release,
restarts the installed service, probes the real loopback application, and
probes the routed HTTPS origin. A failure restores the previous release.

The candidate listen variable must never appear in the shared Tend environment
file. Tend's server policy rejects that mistake. The live address remains in
the root-owned Observatory configuration.

## Installed files

The reviewed deployment inputs are:

- `release/observatory.service`: hardened non-root service;
- `release/server.json`: non-secret dogfood server configuration;
- `release/observatory.env.example`: intentionally empty shared environment;
- `release/Caddyfile.observatory`: initial origin handler;
- `release/tend.json`: application-owned packaging and activation contract.

The Caddy handler also defines a bounded, rotated JSON edge log. It strips the
entire query, request and response header maps, client addresses, and Caddy
user identity before writing. A late `log_append` copies only the bounded
application response request ID into a dedicated top-level field, allowing the
agent to correlate accepted edge and application records without retaining
cookies, credentials, referrers, user agents, or query values. The log file is
not an application authorization record and remains separate evidence.

That installed handler is the privacy-minimized deployment policy, not a
platform prohibition. Applications that disclose and require richer traffic
evidence can use per-source `sensitive_fields` with a separately reviewed Caddy
filter, such as `examples/Caddyfile.sensitive-access-log`. The richer policy
still removes both header maps and never retains cookies or authorization
headers. Its query-key deny list is only a starting point: the application must
add every secret-bearing parameter it accepts before enabling query collection.

On the host, their controlled destinations are:

```text
/etc/gamertan-observatory/server.json       root:root 0600
/etc/gamertan-observatory/web-push.json     root:root 0600
/etc/tend/environment/observatory.env       root:root 0600
/etc/tend/services/observatory.json         root:root 0644
/etc/systemd/system/gamertan-observatory.service
/opt/gamertan-observatory/
/var/lib/gamertan-observatory/
```

The initial Caddy stanza is an explicit infrastructure change performed before
the first Tend activation. Tend validates and uses the existing routed origin;
it does not silently edit the host's top-level Caddyfile for a new service.

## First installation and the first Tend maintenance release

Tend intentionally bootstraps singleton state from an existing, validated
`current` release pointer. It does not invent a service account, Caddy origin,
root-owned configuration, or first live release. Observatory's one-time
installation therefore uses a twice-built, checksum-approved Tend package from
an exact clean pushed commit, exercises that binary in the stateless candidate
mode, installs its immutable release, creates the first `current` pointer, and
starts the reviewed service and Caddy origin under direct operator control.

The next exact pushed commit became the real Tend maintenance campaign:
candidate health and application smoke, pointer activation, service restart,
routed public-origin smoke, state recording, rollback, and identical-artifact
redeployment. The observation below separates the one-time bootstrap from that
completed dogfood exercise.

## Initial dogfood bootstrap observation

On August 17, 2026, the initial live Observatory bootstrap used a Tend package
built twice from one clean pushed development source. Both package runs
produced the same SHA-256 digest:

```text
42c21deba0519955ea7cbb140ea37321403cb26622d54d69c68bcfd19fe2764e
```

The installed `v0.0.1-preview.3` development binary reports Go 1.26.6. Tend
validated and safely extracted the immutable archive, and the stateless
candidate contract passed before the directly controlled first activation.
The resulting non-root systemd service remained ready with zero restarts while
the canonical HTTPS origin and the pre-existing EQL Helper, Gamertan, and
Sandwich Hime origins were rechecked.

The bootstrap found two real integration defects before activation was
accepted:

- systemd 255 presents a copied `LoadCredential` file as root-owned mode
  `0440`, although the original remains root-owned mode `0600`; Observatory
  originally rejected the runtime copy. The validator now permits `0440` only
  when explicit systemd-credential mode also proves that the file is inside
  the unit's credential directory and owned by root;
- an omitted Web Push notifier was stored as a typed nil pointer in a non-nil
  interface, so the first incident evaluation panicked. Optional push
  construction now returns a genuinely nil interface when no notifier is
  configured, and its regression test exercises an incident with Web Push
  disabled.

Neither failure altered an existing application origin. Failed Observatory
artifacts were retained as diagnostic evidence, and the service was accepted
only after the corrected package passed its checks. Tend state remained
intentionally uninitialized until the first maintenance activation.

## First Tend maintenance and rollback observation

Trusted CI run 220 passed the exact pushed maintenance source. Tend built it
twice with Go 1.26.6 and module downloads disabled; both archives were
byte-identical at:

```text
3afed7dcc719d98d9bc9a4e13790ce0a71036c339f1a354fa4e0d67abab3ccdb
```

On August 17, 2026, `tend push` sent that approved digest through the dedicated
forced-command deployment account. The host policy accepted only the
`observatory` service and validated the archive before Tend exercised the
stateless candidate, activated `v0.0.1-preview.4`, restarted the installed
unit, checked loopback health and readiness, probed the routed HTTPS origin,
and initialized deployment state with `v0.0.1-preview.3` as the previous
release.

The recorded Tend rollback then restored the exact preview.3 release and
swapped preview.4 into the previous position. Loopback health, the public
Observatory origin, and EQL Helper continuity passed before the same approved
preview.4 archive was sent through the restricted transport again. Tend
revalidated and reactivated its existing content-addressed release. Final
state records preview.4 active and preview.3 previous.

The candidate port and shared host lock were free after the exercise. The
service reported zero restarts and no warning-or-higher journal entries, and
the Observatory, EQL Helper, Gamertan, and Sandwich Hime origins all returned
success. This closes Observatory's initial Tend maintenance-and-rollback
dogfood claim; it does not close the separate medium-fleet, capacity, or public
preview release gates.

## Startup-readiness dogfood finding

On August 18, 2026, Tend correctly refused Observatory
`v0.0.1-preview.13` after the activated process did not bind its loopback
socket inside the 30-second post-activation window. Tend restored the exact
preview.12 release, preserved the earlier rollback release, recorded the failed
digest, and returned the service to active state with zero restarts.

The package and stateless candidate had passed. The full server then performed
raw retention and identity-evidence pruning synchronously before opening its
listener. Those maintenance passes are bounded and valid, but their elapsed
time depends on accumulated data and cold filesystem state; they are not a safe
availability prerequisite. Observatory now completes mandatory raw recovery,
opens the configured listener, and only then runs retention and evidence
pruning through the same background path used for hourly maintenance. A
maintenance failure remains visible in bounded logs but does not prevent the
otherwise healthy server from answering readiness probes.

This also records a Tend integration limitation: a stateless candidate proves
the packaged binary and candidate process boundary, not a stateful
application's complete startup path. Tend should continue to restore on a
missed activation window, but a future release should report this distinction
more explicitly and reject linked-worktree packaging before the build rather
than after Go omits `vcs.revision`. The trusted Gitea release workflow produced
and verified identical preview.13 bytes, but the Gitea Actions artifact API did
not list the successfully uploaded artifact; the independently reproduced
local digest and CI log therefore remained the review evidence for this
attempt.

Preview.14 exposed a second, independent startup boundary on the accumulated
production archive. Mandatory recovery enumerated every hot raw segment by
checksum-verifying, decompressing, and retaining every decoded batch before it
compared the archive with the control catalog. With 20,550 small segments this
exceeded the service's 768 MiB memory limit before the listener opened. Tend
restored the recorded release, but the same archive-bound algorithm also
prevented that older binary from becoming ready; Tend therefore correctly
left its bounded stateless candidate routed for operator recovery instead of
claiming a successful rollback.

Recovery now walks only private filesystem metadata and compares each object
with a prepared catalog lookup. It decodes one segment only when the catalog
is missing that committed object, and it replays unprojected catalog rows in
pages of 128. This fixes the availability defect rather than hiding it behind
a larger memory allocation. Full checksum verification remains part of
orphan admission, reads, cold archival, deletion, export, and explicit
projection rebuild. A deployment with production-scale retained evidence must
exercise the stateful startup path under its configured memory limit before
activation; the stateless package candidate remains a separate gate.

## Preview.19 native-batch and stateful-Compose observation

Trusted Gitea release-candidate run 380 passed exact source commit
`2b00be0984188b0c59d6a843921e03c9b182b881` with Go 1.26.6. Two independent
Tend package runs and the retained CI artifact produced the same archive:

```text
6ce16931412f618fa4a3d0130fc0f69e7f96f994b1f12e6be3a66a0e49a9af95
```

The public-preview capacity gate passed at 221 observations/second sustained,
1,315/second burst, approximately 60 ms visibility p95, approximately 2.1 ms
query p95, and approximately 173 MiB maximum RSS. These are bounded synthetic
gate results, not a medium-fleet or generic production-capacity claim.

Before activation, the exact candidate was exercised against a copy of the
accumulated production control database, organization projection, and
immutable raw archive. The first migration failed closed while building the
new presence-only projection index: SQLite reported `database or disk is full`
with the service's 64 MiB `/tmp` tmpfs. The same image, data, limits, and
migration passed with a 512 MiB tmpfs, drained 986 pending raw segments to
zero, and finished with 27,788 retained segments. The database was not corrupt;
the index sort needed a larger bounded temporary working area. The reviewed
Compose definition now records that scratch budget explicitly.

Observatory's production topology is a Docker Compose singleton, which Tend
does not yet model. The maintainer therefore paused the durable agent, verified
mode-`0600` SQLite backups and their SHA-256 digests, migrated the live data
offline, and started the exact candidate under the staged Compose definition.
Direct health and readiness passed approximately 3.25 seconds after the final
start; the routed public origin settled approximately one second later.

The first activation script probed the public origin only once. That eager
probe observed a transient `503` and invoked its rollback path even though the
candidate had passed direct readiness. The rollback then demonstrated an
important second boundary: Preview.18 correctly rejected the newly migrated
control schema 11 and entered a fail-closed restart loop. The verified backups
remained intact, but restoring them would have discarded valid forward
migration work. The operator instead stopped the old agent, started the
schema-compatible Preview.19 candidate, waited through bounded direct and
public-origin readiness loops, and then started the matching Preview.19 agent.
An independent observer recorded a bounded `502`/`503` interruption during
the failed rollback and recovery. No continuous-delivery claim is made.

At the immediate post-activation check on August 19, 2026:

- the server and agent both reported the exact Preview.19 image, zero restarts,
  no OOM event, and no warning-or-higher log entry;
- `/`, `/healthz`, and `/readyz` returned success through the public origin,
  while `/app/` returned its expected authenticated redirect;
- `observatory check` returned `ok` against the live configuration and data;
- all 27,998 retained segments were projected with zero pending work; and
- the first stream advanced by the new agent had non-empty native-v2 batch and
  encoded-body digests, proving the authenticated batch-identity path in the
  live control catalogue.

This is staging dogfood evidence for an unreleased development build. It does
not create a public tag, close the medium-fleet soak, or make the current
Compose handoff a supported Tend strategy. It does prove that authenticated
`(source, stream, sequence)` batch identity, exact digest replay protection,
raw-first durability, and overlapping-time-window semantics work together on
the live data plane without a global per-record deduplication index.

## Secrets and administration

No secret belongs in `tend.json`, the release manifest, process arguments, or
the shared environment file. Web Push keys and later credentials use systemd
credentials. Local operator bootstrap creates a one-time password in a new
private file and is performed while the application is stopped or through a
separately reviewed administrative procedure; it is not part of deployment
activation. The first browser or API session can reach only rotation, logout,
health, and immutable shell assets until the password is replaced.

The first dogfood deployment is an unreleased development build. A public tag
requires the capacity campaign, rollback exercise, medium-fleet soak, reviewed
public snapshot, checksums, SBOM, signatures, and release gates in the roadmap.
