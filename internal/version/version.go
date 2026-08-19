// SPDX-License-Identifier: AGPL-3.0-only

package version

import "runtime"

var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

type Info struct {
	Version  string   `json:"version"`
	Commit   string   `json:"commit"`
	Date     string   `json:"date"`
	Go       string   `json:"go"`
	Features []string `json:"features"`
}

func Current() Info {
	return Info{Version: Version, Commit: Commit, Date: Date, Go: runtime.Version(), Features: []string{"native-ingest-v1", "native-ingest-v2", "raw-zstd-segments", "sqlite-projections", "typed-query-v1", "organization-access-v1", "agent-tail-v1", "agent-enrollment-v1", "retention-v1", "cold-archive-v1", "metric-rollup-5m-v1", "tend-candidate-v1"}}
}
