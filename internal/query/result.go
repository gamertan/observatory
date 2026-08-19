// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"errors"

	"gamertan.com/observatory/internal/schema"
)

const ResultVersion = 1

var (
	ErrBudgetExceeded = errors.New("query execution budget exceeded")
	ErrTypeMismatch   = errors.New("query value does not match its field type")
)

type Column struct {
	Field string      `json:"field"`
	Type  schema.Type `json:"type"`
	Unit  string      `json:"unit,omitempty"`
}

// Row values align positionally with Result.Columns. Nil is a missing value;
// non-nil values use the canonical string form described by the column type.
type Row struct {
	Values []*string `json:"values"`
}

type Statistics struct {
	ScannedRows  int   `json:"scanned_rows"`
	MatchedRows  int   `json:"matched_rows"`
	ScannedBytes int64 `json:"scanned_bytes"`
	DurationNS   int64 `json:"duration_ns"`
	Truncated    bool  `json:"truncated"`
	Approximate  bool  `json:"approximate,omitempty"`
}

type Result struct {
	Version int        `json:"version"`
	Explain Explain    `json:"explain"`
	Columns []Column   `json:"columns"`
	Rows    []Row      `json:"rows"`
	Stats   Statistics `json:"statistics"`
}
