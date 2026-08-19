// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

func TestMetricSummaryQueriesUseFiveMinuteRollups(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	ctx := t.Context()
	scope := model.Scope{OrganizationID: "org-query-rollup", ProjectID: "project", EnvironmentID: "production", ServiceID: "web"}
	token, err := store.CreateSource(ctx, "source-query-rollup", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 4, 9, 0, 0, time.UTC)
	sequence := uint64(1)
	for _, sample := range []struct {
		at    time.Time
		value float64
	}{{now.Add(-8 * time.Minute), 1}, {now.Add(-7 * time.Minute), 2}, {now.Add(-2 * time.Minute), 100}} {
		value := sample.value
		batch := model.Batch{Version: model.BatchVersion, SourceID: "source-query-rollup", StreamID: "metrics", Sequence: sequence, ObservedAt: now, Signal: model.SignalMetrics, Records: []model.Observation{{Timestamp: sample.at, Name: "request.duration", Value: &value, Attributes: map[string]string{"http.route": "/items", "private.dimension": "secret"}}}}
		if _, err = store.Ingest(ctx, token, batch, now); err != nil {
			t.Fatal(err)
		}
		sequence++
	}
	projectAll(t, store)
	ast, err := query.Parse(`metrics | where route == "/items" | window 1h | summarize count(), avg(value), p95(value) by name, window(10m) | limit 20`, 100)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Query(ctx, ast, query.Scope{OrganizationID: scope.OrganizationID, ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID, ServiceID: scope.ServiceID, Sensitive: true}, query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 1 << 20, MaxMemoryBytes: 1 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Explain.ProjectedSources) != 1 || !strings.HasSuffix(result.Explain.ProjectedSources[0], "/rollup:5m") {
		t.Fatalf("sources=%v", result.Explain.ProjectedSources)
	}
	if !result.Stats.Approximate || result.Stats.ScannedRows != 2 || result.Stats.MatchedRows != 2 || len(result.Rows) != 1 {
		t.Fatalf("stats=%+v rows=%+v", result.Stats, result.Rows)
	}
	row := result.Rows[0]
	if len(row.Values) != 5 || row.Values[2] == nil || *row.Values[2] != "3" || row.Values[3] == nil || row.Values[4] == nil {
		t.Fatalf("row=%+v", row)
	}
	average, err := strconv.ParseFloat(*row.Values[3], 64)
	if err != nil || average < 34.3 || average > 34.4 {
		t.Fatalf("average=%g err=%v", average, err)
	}
	p95, err := strconv.ParseFloat(*row.Values[4], 64)
	if err != nil || p95 < 98 || p95 > 102 {
		t.Fatalf("p95=%g err=%v", p95, err)
	}

	rawAST, err := query.Parse(`metrics | where value >= 2 | window 1h | summarize count() | limit 20`, 100)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := store.Query(ctx, rawAST, query.Scope{OrganizationID: scope.OrganizationID, Sensitive: true}, query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 1 << 20, MaxMemoryBytes: 1 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(raw.Explain.ProjectedSources[0], "/rollup:5m") || len(raw.Rows) != 1 || raw.Rows[0].Values[0] == nil || *raw.Rows[0].Values[0] != "2" {
		t.Fatalf("raw=%+v", raw)
	}
	unknownAST, err := query.Parse(`metrics | where private.dimension == "secret" | window 1h | summarize count() | limit 20`, 100)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := store.Query(ctx, unknownAST, query.Scope{OrganizationID: scope.OrganizationID, Sensitive: true}, query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 1 << 20, MaxMemoryBytes: 1 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(unknown.Explain.ProjectedSources[0], "/rollup:5m") || len(unknown.Rows) != 1 || unknown.Rows[0].Values[0] == nil || *unknown.Rows[0].Values[0] != "3" {
		t.Fatalf("unknown=%+v", unknown)
	}
}
