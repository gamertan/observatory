#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

# Complete but bounded dogfood evidence. Release-scale capacity and extended
# assurance remain explicit milestone campaigns.
./scripts/verify.sh

fuzz_time=${OBSERVATORY_PREVIEW_FUZZ_TIME:-5s}
go test -buildvcs=false ./internal/query -run '^$' -fuzz '^FuzzParse$' -fuzztime "$fuzz_time"
go test -buildvcs=false ./internal/nativeprotocol -run '^$' -fuzz '^FuzzParseEnvelopeHeaders$' -fuzztime "$fuzz_time"
go test -buildvcs=false ./internal/otlp -run '^$' -fuzz '^FuzzDecode$' -fuzztime "$fuzz_time"
go test -buildvcs=false ./internal/collector -run '^$' -fuzz '^FuzzTendCollector$' -fuzztime "$fuzz_time"

OBSERVATORY_CAPACITY_MODE=development ./scripts/capacity-campaign.sh
test -z "$(git status --porcelain=v1 --untracked-files=all)"
