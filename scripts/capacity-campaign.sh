#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
test "$(uname -s)" = Linux

campaign_dir=$(mktemp -d)
cleanup() { rm -rf "$campaign_dir"; }
trap cleanup EXIT
fixture=${OBSERVATORY_CAPACITY_FIXTURE:-}
if test -z "$fixture"; then
  test "$(go env GOVERSION)" = go1.26.6
  CGO_ENABLED=0 go build -buildvcs=false -trimpath -tags observatory_capacity_fixture -o "$campaign_dir/observatory-capacity" ./internal/capacitytest
  fixture="$campaign_dir/observatory-capacity"
else
  case "$fixture" in /*) ;; *) exit 2;; esac
  test -x "$fixture"
fi

case "${OBSERVATORY_CAPACITY_MODE:-development}" in
  development)
    "$fixture" \
      -sustain-rate 200 -sustain-duration 5s \
      -burst-rate 1000 -burst-duration 2s \
      -minimum-primary-observations 20000 -query-iterations 3
    ;;
  release)
    "$fixture" \
      -require-cgroup -expected-cpus 4 -expected-memory-bytes 8589934592
    ;;
  *) exit 2;;
esac

test -z "$(git status --porcelain=v1 --untracked-files=all)"
