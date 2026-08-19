<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Tend deployment evidence

Observatory consumes Tend's bounded version-1 deployment-event JSONL as an
unprivileged, read-only file source. Tend does not call Observatory and never
waits for an Observatory acknowledgement. Identity, entropy, event-file, agent,
network, and server failures therefore cannot decide whether Tend activates or
rolls back an application.

Each accepted record has exactly these fields:

- a cryptographically random operation ID;
- service, approved artifact SHA-256, source commit, and release version;
- phase, optional slot, elapsed milliseconds, outcome, and UTC observation
  time.

The adapter rejects unknown fields, trailing JSON, negative durations,
malformed identifiers, unsafe values, invalid timestamps, and records larger
than Tend's 4-KiB producer limit. It discards the source line after converting
only this fixed field set into a deployment observation. No environment value,
secret path, HTTP body, command output, or arbitrary process output belongs to
the contract.

## Agent configuration

Grant the dedicated Observatory agent account read access only to the selected
service's event file, then configure an explicit local source:

```json
{
  "kind": "tend_events_jsonl",
  "path": "/opt/example/deployment-events.jsonl",
  "stream_id": "tend-deployments"
}
```

The source's organization, project, environment, and service scope comes from
its server-side enrollment. Neither the file nor a deployment event may choose
tenant scope. The normal durable cursor and spool rules apply during rotation,
agent restarts, or an Observatory outage.

## Querying

Activation and rollback attempts share the `tend.deployment` observation name
and correlate through `deployment.operation_id`:

```text
deployments
| where service.name == "example-site"
| sort deployment.duration_ms desc
| limit 50
```

Keep candidate, activation, and rollback phases together when reconstructing a
release operation. A missing event means evidence was unavailable; it must not
be interpreted as proof that a deployment did not occur. Tend's own state and
the application's active release remain authoritative for deployment control.

The producer contract is maintained by [Gamertan Tend](https://gitea.speelman.ca/gamertan/tend).

## Production dogfood observation

On August 18, 2026, one checksum-approved Tend candidate exercised candidate
validation, activation, explicit rollback, and reactivation for Gamertan,
Sandwich Hime, and Observatory. The production agent then projected all three
bounded event files through separate streams: ten Gamertan events and six for
each of the two singleton services. Gamertan's stream intentionally includes
two failed pre-activation candidates that never received public traffic; those
records helped identify a hardened-umask extraction defect before the corrected
candidate completed all three service cycles.

This observation demonstrates the producer-to-agent-to-projection path and its
failure evidence. It is not a substitute for Tend state, active-release
inspection, public health checks, or the remaining Observatory fleet and
capacity release gates.
