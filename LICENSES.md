<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Licence map

| Path | Licence |
| --- | --- |
| Go application and internal packages | AGPL-3.0-only |
| `scripts/`, `.gitea/`, documentation, and release machinery | AGPL-3.0-only |
| `examples/` | 0BSD |
| Browser campaign source and tooling | AGPL-3.0-only |

The browser campaign pins Apache-2.0-licensed Playwright as a development-only
dependency. Its optional macOS watcher is MIT-licensed. Neither is linked into
or packaged with the Observatory binary.

Every text source file carries an SPDX identifier or, where strict JSON cannot
accept comments, a matching `.license` sidecar or machine-readable licence
field. Generated Sandwich Hime outputs inherit the licence of their adjacent
`.sando` source and retain exact generator provenance. The complete AGPL and
0BSD licence texts are included in `LICENSE` and `examples/LICENSE`.
