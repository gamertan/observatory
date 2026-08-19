#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
./scripts/check-licenses.sh
test "$(go env GOVERSION)" = go1.26.6
test "$(himesan version --json)" = '{"compiler":"v1.0.0-beta.2","runtime_abi":"sando.v1","go":"go1.26.6","features":["lsp-stdio"]}'
test "$(go list -m -f '{{.Version}}' gamertan.com/tend)" = v0.2.0-preview.2
go tool tend version | grep -Fq '"version": "v0.2.0-preview.2"'
go tool tend check --config "$root/release/tend.json" >/dev/null
himesan check -json . >/dev/null

verify_dir=$(mktemp -d)
trap 'rm -rf "$verify_dir"' EXIT
find internal -type f -name '*.sando.go' -print | LC_ALL=C sort >"$verify_dir/generated"
test -s "$verify_dir/generated"
while IFS= read -r file; do sha256sum "$file"; stat -c '%y %n' "$file"; done <"$verify_dir/generated" >"$verify_dir/before"
himesan generate -json . >/dev/null
himesan generate -json . >/dev/null
while IFS= read -r file; do sha256sum "$file"; stat -c '%y %n' "$file"; done <"$verify_dir/generated" >"$verify_dir/after"
cmp "$verify_dir/before" "$verify_dir/after"

test -z "$(gofmt -l .)"
go test -buildvcs=false ./...
go test -buildvcs=false -tags observatory_browser_fixture ./internal/browsertest
go test -buildvcs=false -tags observatory_capacity_fixture ./internal/capacitytest
go test -buildvcs=false -race ./...
go vet -buildvcs=false ./...
go build -buildvcs=false -trimpath -o "$verify_dir/observatory" ./cmd/observatory
test "$(go list -buildvcs=false -deps ./cmd/observatory | grep '^gamertan.com/sandwich-hime' || true)" = 'gamertan.com/sandwich-hime/sando'
git diff --check
