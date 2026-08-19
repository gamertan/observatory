// SPDX-License-Identifier: AGPL-3.0-only

package edgealert

import (
	"errors"
	"time"

	"gamertan.com/observatory/internal/config"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

type Evaluation struct {
	State       string
	Matches     int
	WindowStart time.Time
	WindowEnd   time.Time
	ObservedAt  time.Time
}

// Evaluate applies one locally configured, filter-only log rule to one exact
// durable batch. It does not perform I/O, mutate incident state, or retain
// telemetry beyond the caller-owned batch.
func Evaluate(rule config.AgentAlertRule, batch model.Batch) (Evaluation, error) {
	if rule.AST.Signal != model.SignalLogs || batch.Signal != model.SignalLogs || rule.StreamID != batch.StreamID || len(batch.Records) == 0 {
		return Evaluation{}, errors.New("edge alert rule and batch are incompatible")
	}
	first, last := batch.Records[0].Timestamp.UTC(), batch.Records[0].Timestamp.UTC()
	matches := 0
	state := "clear"
	for _, observation := range batch.Records {
		timestamp := observation.Timestamp.UTC()
		if timestamp.Before(first) {
			first = timestamp
		}
		if timestamp.After(last) {
			last = timestamp
		}
		matched, err := query.MatchObservation(observation, rule.AST, nil)
		if err != nil {
			return Evaluation{State: "error", Matches: matches, WindowStart: first, WindowEnd: last, ObservedAt: maxTime(batch.ObservedAt.UTC(), last)}, nil
		}
		if matched {
			matches++
			if matches >= rule.MinimumMatches {
				state = "matched"
			}
		}
	}
	return Evaluation{State: state, Matches: matches, WindowStart: first, WindowEnd: last, ObservedAt: maxTime(batch.ObservedAt.UTC(), last)}, nil
}

func maxTime(left, right time.Time) time.Time {
	if left.After(right) {
		return left
	}
	return right
}
