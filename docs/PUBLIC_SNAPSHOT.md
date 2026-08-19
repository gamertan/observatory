<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Public snapshot boundary

Observatory uses a private development repository and a separate canonical
public source repository. Public history is not a mirror of private history.
Each publication is a reviewed root snapshot of one exact, clean, pushed
private `main` commit.

`scripts/public-snapshot.allow` is the complete public file boundary. The
exporter refuses workflow directories, absolute or parent-traversing paths,
missing tracked files, dirty worktrees, and a private HEAD that differs from
`origin/main`. It archives only the allowlisted paths from the committed Git
tree, byte-compares them with the worktree, scans the result for known private
material, and records the source commit, tree, date, and file count in
`PUBLIC-SNAPSHOT.json` with a SHA-256 sidecar.

The generated snapshot has no `.git` directory. Publication tooling creates a
new reviewed public commit; it must never push private refs, tags, workflows,
reflogs, or historical objects. The canonical public Gitea commit and GitHub
discovery commit may have different Git identities, but their exported file
trees and snapshot manifest must be byte-identical.

Before the first preview, the public snapshot, release archive, SBOM,
checksums, signature, canonical tag, and installed module must all be traced
back to the same reviewed private source commit. A public snapshot does not by
itself make an unreleased development build supported.

