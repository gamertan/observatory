// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

func TestRawQueryCandidateMatchesProjectionOracle(t *testing.T) {
	ctx := t.Context()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 18, 22, 0, 0, 0, time.UTC)
	for _, source := range []struct {
		id      string
		service string
		batches []model.Batch
	}{
		{id: "source-a", service: "service-a", batches: []model.Batch{
			{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: now.Add(-2 * time.Minute), Signal: model.SignalLogs, Records: []model.Observation{
				requestObservation(now.Add(-3*time.Minute), "/items", 503, 300),
				requestObservation(now.Add(-4*time.Minute), "/items", 200, 80),
			}},
			{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 2, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{
				requestObservation(now.Add(-time.Minute), "/checkout", 500, 900),
				{Timestamp: now.Add(-30 * time.Second), Name: "application.note", Body: "safe", Severity: "information"},
			}},
		}},
		{id: "source-b", service: "service-b", batches: []model.Batch{
			{Version: model.BatchVersion, SourceID: "source-b", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{
				requestObservation(now.Add(-90*time.Second), "/items", 502, 450),
			}},
		}},
	} {
		token, err := store.CreateSource(ctx, source.id, model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: source.service})
		if err != nil {
			t.Fatal(err)
		}
		for _, batch := range source.batches {
			if _, err = store.Ingest(ctx, token, batch, batch.ObservedAt); err != nil {
				t.Fatal(err)
			}
		}
	}
	projectAll(t, store)

	queries := []struct {
		text  string
		scope query.Scope
	}{
		{`logs | where status >= 500 | window 1h | sort duration desc | limit 2`, query.Scope{OrganizationID: "organization-a"}},
		{`logs | where status >= 500 | summarize count(), p95(duration) by route | sort count desc | limit 10`, query.Scope{OrganizationID: "organization-a"}},
		{`logs | where route =~ "^/item" | window 1h | limit 10`, query.Scope{OrganizationID: "organization-a", ServiceID: "service-a"}},
	}
	for _, candidate := range queries {
		ast, err := query.Parse(candidate.text, 100)
		if err != nil {
			t.Fatalf("parse %q: %v", candidate.text, err)
		}
		projected, err := store.Query(ctx, ast, candidate.scope, testQueryBudget(), now)
		if err != nil {
			t.Fatalf("projected %q: %v", candidate.text, err)
		}
		raw, err := store.queryRawCandidate(ctx, ast, candidate.scope, testQueryBudget(), now)
		if err != nil {
			t.Fatalf("raw %q: %v", candidate.text, err)
		}
		if !reflect.DeepEqual(projected.Columns, raw.Columns) || !reflect.DeepEqual(projected.Rows, raw.Rows) || projected.Stats.Truncated != raw.Stats.Truncated || projected.Stats.MatchedRows != raw.Stats.MatchedRows {
			t.Fatalf("query %q diverged\nprojected=%+v\nraw=%+v", candidate.text, projected, raw)
		}
	}
}

func TestRawQueryCandidateReadsDurableUnprojectedBatchesWithoutWriting(t *testing.T) {
	ctx := t.Context()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 18, 22, 15, 0, 0, time.UTC)
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{requestObservation(now, "/ready", 200, 25)}}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	projectionPath := filepath.Join(store.root, "organizations", "organization-a", "projection.sqlite")
	if _, err = os.Lstat(projectionPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("projection unexpectedly exists: %v", err)
	}
	ast, err := query.Parse(`logs | where route == "/ready" | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.queryRawCandidate(ctx, ast, query.Scope{OrganizationID: "organization-a"}, testQueryBudget(), now)
	if err != nil || len(result.Rows) != 1 || columnValue(t, result, 0, "http.route") != "/ready" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err = os.Lstat(projectionPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("raw query created a projection: %v", err)
	}
	var projected int
	if err = store.control.QueryRow(`SELECT COUNT(projected_at) FROM segments`).Scan(&projected); err != nil || projected != 0 {
		t.Fatalf("projected=%d err=%v", projected, err)
	}
	budget := testQueryBudget()
	budget.MaxScannedBytes = 1
	if _, err = store.queryRawCandidate(ctx, ast, query.Scope{OrganizationID: "organization-a"}, budget, now); err == nil {
		t.Fatal("raw query ignored the scan budget")
	}
	if _, err = store.control.Exec(`UPDATE segments SET archiving_at=?,archive_path=path WHERE source_id='source-a'`, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.queryRawCandidate(ctx, ast, query.Scope{OrganizationID: "organization-a"}, testQueryBudget(), now); err == nil || err.Error() != "raw query segment transition is incomplete" {
		t.Fatalf("transition error=%v", err)
	}
}

func TestRawQueryCandidateRejectsNonLogSignals(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	ast, err := query.Parse(`metrics | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.queryRawCandidate(t.Context(), ast, query.Scope{OrganizationID: "organization-a"}, testQueryBudget(), time.Now().UTC()); err == nil {
		t.Fatal("non-log raw query candidate was accepted")
	}
}
