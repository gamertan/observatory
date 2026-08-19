<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Incidents and alert rules

Observatory alert rules reuse a stored, versioned query. They do not introduce
a second expression language, arbitrary SQL, shell execution, or a remote
plugin surface.

Each rule defines:

- one organization-owned saved query;
- a bounded minimum result-row count;
- one to ten required consecutive matching evaluations;
- a severity and a 15-second to 24-hour evaluation interval; and
- an enabled state.

The evaluator claims at most 64 due rules per pass. Every query retains the
server's ordinary time, row, decoded-byte, and memory budgets. Rules execute
without sensitive-field permission; a query that requires sensitive or
unknown fields fails closed as `query_unavailable`. Query failure never clears
an existing incident.

The durable lifecycle is:

1. The first matching evaluation opens a `pending` incident.
2. The configured consecutive-match count promotes it to `firing`.
3. An authorized responder may `acknowledge`, `silence`, or `resolve` it.
4. A non-matching successful evaluation resolves the open incident.
5. An expired silence returns to `firing` if the rule still matches.

Every transition appends a sequenced organization-scoped event. Events record
only the transition, actor identifier, and time. They do not copy query text,
query results, resource labels, or telemetry values into the control database.
The SSE channel carries only a generic refresh hint.

PWA installation, explicit offline inbox access, application badge state, and
generic Web Push are progressive layers over this durable lifecycle. Web Push
is optional and best effort; it cannot create, update, resolve, or otherwise
replace an incident record. Its exact privacy boundary is documented in
[`PWA.md`](PWA.md).
