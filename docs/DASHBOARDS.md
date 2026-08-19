<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Saved queries and dashboards

Observatory persists query definitions before building the web interface on
top of them. A saved query contains bounded human metadata, one organization,
an optional project/environment/service scope, the reviewed query text, and
the exact versioned typed AST produced from that text. Reads reparse the text,
hydrate its duration fields, validate the stored AST, and require the two
representations to match.

Dashboards are versioned ordered collections of at most 16 panels. Each panel
selects one saved query and one deliberately small visualization contract:
`table`, `stat`, or `timeseries`. Composite foreign keys prevent a panel from
referencing another organization's query. Updates to saved queries and
dashboards require their current revision so concurrent edits fail instead of
silently overwriting one another.

Identifiers are generated from cryptographic randomness; randomness failure
fails the write and never falls back to time or a predictable counter.

## Source-control export

`ExportDashboard` produces strict version-1 JSON containing the dashboard
definition and each referenced query once. It keeps the stable definition IDs
needed by panels, but omits organization IDs, operator user IDs, timestamps,
internal revisions, and redundant stored AST bytes.

`observatory export` performs the same organization-authorized read from the
local server data directory. `observatory import` accepts exactly one strict,
bounded JSON bundle on standard input and requires the destination
organization twice: once as `--organization-id` and again as the exact
`--approve-organization` value. Import reparses every query, validates each
resource scope against the destination organization, replaces all portable
identifiers with cryptographically generated local identities, and commits
the queries, dashboard, and panels in one SQLite transaction. A bundle cannot
select its tenant or actor.

Example:

```sh
observatory export --organization-id organization-id \
  --actor-user-id user-id --dashboard operations >operations.json

observatory import --organization-id organization-id \
  --approve-organization organization-id --actor-user-id user-id \
  <operations.json
```

The Sandwich Hime interface creates saved queries and one-panel dashboards
through organization-authorized, CSRF-protected forms. A first assisted builder
serializes fixed, bounded controls into ordinary text and then uses the same
parser and stored AST contract as the text editor. It never sends a caller-
constructed AST around query validation.

An authorized dashboard page exposes ordinary server-rendered forms for its
metadata and panels. Metadata changes, panel additions, panel edits, and panel
removals submit the dashboard's opaque identity and current revision. The
server reloads the organization-owned dashboard, preserves every untouched
panel, validates saved-query ownership and presentation compatibility, and
uses the storage transaction's optimistic revision check. A concurrent edit
returns `409 Conflict` and requires a reload; it never silently overwrites the
newer definition. These controls remain fully usable without JavaScript.

Dashboard pages execute every saved panel through the same bounded query
engine and retain the full table for every presentation. Time-series panels
may add a native `meter` summary for at most 48 finite, nonnegative numeric
points; unsupported values fail closed to the table alone. Strict JSON export
exposes only the source-control definition. The first preview intentionally
keeps assisted editing to bounded controls and leaves richer expressions to
the complete typed query editor; a second browser-side query language is not a
release requirement.
