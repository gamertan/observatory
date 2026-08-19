// SPDX-License-Identifier: AGPL-3.0-only

module gamertan.com/observatory

go 1.26

require (
	gamertan.com/sandwich-hime/sando v1.0.0-beta.1
	gamertan.com/web v0.1.0-preview.4
	github.com/klauspost/compress v1.18.7
	go.opentelemetry.io/proto/otlp v1.11.0
	google.golang.org/protobuf v1.36.11
	modernc.org/sqlite v1.56.0
)

require (
	gamertan.com/tend v0.2.0-preview.2 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

tool gamertan.com/tend/cmd/tend
