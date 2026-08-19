// SPDX-License-Identifier: AGPL-3.0-only

package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"
)

const AlertTransitionVersion = 1

// AlertTransition is a bounded source-reported rule evaluation. Resource
// scope, rule metadata, and incident authority remain server-owned. The
// transition carries no telemetry values.
type AlertTransition struct {
	Version       int       `json:"version"`
	RuleID        string    `json:"rule_id"`
	RuleRevision  int       `json:"rule_revision"`
	AgentEpoch    string    `json:"agent_epoch"`
	Sequence      uint64    `json:"sequence"`
	StreamID      string    `json:"stream_id"`
	BatchSequence uint64    `json:"batch_sequence"`
	SegmentDigest string    `json:"segment_digest"`
	WindowStart   time.Time `json:"window_start"`
	WindowEnd     time.Time `json:"window_end"`
	State         string    `json:"state"`
	ObservedAt    time.Time `json:"observed_at"`
}

func (value AlertTransition) Validate(now time.Time) error {
	if value.Version != AlertTransitionVersion || validateID("rule_id", value.RuleID) != nil || value.RuleRevision < 1 || value.RuleRevision > 1_000_000 || !validLowerHex(value.AgentEpoch, 32) || value.Sequence == 0 || value.Sequence > math.MaxInt64 || ValidateStreamID(value.StreamID) != nil || value.BatchSequence == 0 || value.BatchSequence > math.MaxInt64 || !validLowerHex(value.SegmentDigest, 64) {
		return errors.New("alert transition identity is invalid")
	}
	if value.State != "matched" && value.State != "clear" && value.State != "error" {
		return errors.New("alert transition state is invalid")
	}
	if now.IsZero() || value.WindowStart.IsZero() || value.WindowEnd.Before(value.WindowStart) || value.WindowEnd.Sub(value.WindowStart) > 24*time.Hour || value.ObservedAt.Before(value.WindowEnd) || value.ObservedAt.Before(now.Add(-7*24*time.Hour)) || value.ObservedAt.After(now.Add(10*time.Minute)) {
		return errors.New("alert transition time range is invalid")
	}
	return nil
}

func (value AlertTransition) Digest() (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", errors.New("encode alert transition digest")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
