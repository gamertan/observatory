#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

test "$(go env GOVERSION)" = go1.26.6
fuzz_time=${OBSERVATORY_FUZZ_TIME:-30s}

go test -buildvcs=false ./internal/query -run '^$' -fuzz '^FuzzParse$' -fuzztime "$fuzz_time"
go test -buildvcs=false ./internal/otlp -run '^$' -fuzz '^FuzzDecode$' -fuzztime "$fuzz_time"
go test -buildvcs=false ./internal/collector -run '^$' -fuzz '^FuzzTendCollector$' -fuzztime "$fuzz_time"

go test -buildvcs=false -race -count=1 \
  ./cmd/observatory \
  ./internal/config \
  ./internal/httpserver \
  ./internal/identity \
  ./internal/model \
  ./internal/query \
  ./internal/segment \
  ./internal/spool \
  ./internal/storage \
  ./internal/tailer \
  ./internal/webpush

git diff --check
