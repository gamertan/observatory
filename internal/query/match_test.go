// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
)

func TestMatchObservationUsesCanonicalTypedFilters(t *testing.T) {
	now := time.Date(2026, 8, 18, 23, 55, 0, 0, time.UTC)
	observation := model.Observation{Timestamp: now, Name: "http.request", Severity: "error", Attributes: map[string]string{"http.status_code": "503", "http.route": "/failed"}}
	ast, err := Parse(`logs | where status >= 500 | where route == "/failed" | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	matched, err := MatchObservation(observation, ast, nil)
	if err != nil || !matched {
		t.Fatalf("matched=%t err=%v", matched, err)
	}
	observation.Attributes["http.status_code"] = "200"
	matched, err = MatchObservation(observation, ast, nil)
	if err != nil || matched {
		t.Fatalf("matched=%t err=%v", matched, err)
	}
	delete(observation.Attributes, "http.status_code")
	matched, err = MatchObservation(observation, ast, nil)
	if err != nil || matched {
		t.Fatalf("missing field matched=%t err=%v", matched, err)
	}
}

func TestMatchObservationRejectsInvalidTypedFilterValue(t *testing.T) {
	ast, err := Parse(`logs | where status >= nope | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	observation := model.Observation{Timestamp: time.Now().UTC(), Name: "http.request", Attributes: map[string]string{"http.status_code": "503"}}
	if _, err = MatchObservation(observation, ast, nil); err != ErrTypeMismatch {
		t.Fatalf("err=%v", err)
	}
}
