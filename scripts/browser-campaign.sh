#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

test "$(node -p 'require("./test/browser/node_modules/@playwright/test/package.json").version')" = 1.62.1

campaign_dir=$(mktemp -d)
fixture_pid=
cleanup() {
  if test -n "$fixture_pid"; then
    kill -TERM "$fixture_pid" 2>/dev/null || true
    wait "$fixture_pid" 2>/dev/null || true
  fi
  rm -rf "$campaign_dir"
}
trap cleanup EXIT

fixture=${OBSERVATORY_BROWSER_FIXTURE:-}
if test -z "$fixture"; then
  test "$(go env GOVERSION)" = go1.26.6
  go build -buildvcs=false -trimpath -tags observatory_browser_fixture -o "$campaign_dir/fixture" ./internal/browsertest
  fixture="$campaign_dir/fixture"
else
  case "$fixture" in /*) ;; *) exit 1;; esac
  test -x "$fixture"
fi
"$fixture" >"$campaign_dir/origin" 2>"$campaign_dir/fixture.log" &
fixture_pid=$!
for _ in $(seq 1 100); do
  if test "$(wc -l <"$campaign_dir/origin")" -ge 2; then break; fi
  if ! kill -0 "$fixture_pid" 2>/dev/null; then
    cat "$campaign_dir/fixture.log" >&2
    exit 1
  fi
  sleep 0.1
done
origin=$(head -n 1 "$campaign_dir/origin")
spki=$(sed -n '2p' "$campaign_dir/origin")
case "$origin" in https://localhost:*) ;; *) cat "$campaign_dir/fixture.log" >&2; exit 1;; esac
case "$spki" in *[!A-Za-z0-9+/=]*|'') exit 1;; esac

OBSERVATORY_BROWSER_ORIGIN="$origin" OBSERVATORY_BROWSER_SPKI="$spki" node test/browser/campaign.mjs
if test -d .git; then
  test -z "$(git status --porcelain=v1 --untracked-files=all -- . ':!test/browser/node_modules')"
fi
