// SPDX-License-Identifier: AGPL-3.0-only

package model

import (
	"strings"
	"testing"
	"time"
)

func TestAlertTransitionValidationAndDigest(t *testing.T) {
	now := time.Date(2026, 8, 18, 22, 30, 0, 0, time.UTC)
	value := AlertTransition{Version: AlertTransitionVersion, RuleID: "rule-a", RuleRevision: 1, AgentEpoch: strings.Repeat("a", 32), Sequence: 1, StreamID: "requests", BatchSequence: 2, SegmentDigest: strings.Repeat("b", 64), WindowStart: now.Add(-time.Minute), WindowEnd: now, State: "matched", ObservedAt: now}
	if err := value.Validate(now); err != nil {
		t.Fatal(err)
	}
	first, err := value.Digest()
	if err != nil || len(first) != 64 {
		t.Fatalf("digest=%q err=%v", first, err)
	}
	second, err := value.Digest()
	if err != nil || first != second {
		t.Fatalf("digest changed: %q %q err=%v", first, second, err)
	}
	invalid := []AlertTransition{
		{},
		func() AlertTransition { copy := value; copy.AgentEpoch = "not-hex"; return copy }(),
		func() AlertTransition { copy := value; copy.Sequence = 0; return copy }(),
		func() AlertTransition { copy := value; copy.Sequence = ^uint64(0); return copy }(),
		func() AlertTransition { copy := value; copy.BatchSequence = ^uint64(0); return copy }(),
		func() AlertTransition { copy := value; copy.State = "firing"; return copy }(),
		func() AlertTransition { copy := value; copy.WindowStart = now.Add(-25 * time.Hour); return copy }(),
		func() AlertTransition { copy := value; copy.ObservedAt = now.Add(-time.Second); return copy }(),
	}
	for index, candidate := range invalid {
		if err := candidate.Validate(now); err == nil {
			t.Fatalf("invalid transition %d accepted", index)
		}
	}
}
