#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
destination=$work/public
"$root/scripts/export-public.sh" --destination "$destination" >/dev/null
test -f "$destination/PUBLIC-SNAPSHOT.json"
test -f "$destination/PUBLIC-SNAPSHOT.sha256"
(cd "$destination" && sha256sum -c PUBLIC-SNAPSHOT.sha256)
test ! -e "$destination/.git"
test ! -e "$destination/.gitea"
test ! -e "$destination/.github"
while IFS= read -r file; do
	cmp "$root/$file" "$destination/$file"
done <"$root/scripts/public-snapshot.allow"
(cd "$destination" && GOWORK=off go test -buildvcs=false ./...)
(cd "$destination" && GOWORK=off go vet -buildvcs=false ./...)
echo "public snapshot isolation verified"
