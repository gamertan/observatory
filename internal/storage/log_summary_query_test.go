// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

func TestIndexedLogCountSummaryPreservesScopeBucketsAndStatistics(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 18, 12, 4, 0, 0, time.UTC)
	primaryScope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "web"}
	primaryToken, err := store.CreateSource(ctx, "source-a", primaryScope)
	if err != nil {
		t.Fatal(err)
	}
	primary := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{
		requestObservation(now.Add(-time.Minute), "/items", 503, 300),
		requestObservation(now.Add(-2*time.Minute), "/items", 500, 200),
		requestObservation(now.Add(-3*time.Minute), "/ignored", 200, 100),
		requestObservation(now.Add(-10*time.Minute), "/about", 503, 400),
		{Timestamp: now.Add(-time.Minute), Name: "application.http.request", Attributes: map[string]string{"http.route": "/invalid", "http.status_code": "500suffix", "duration_ns": "100"}},
	}}
	if _, err = store.Ingest(ctx, primaryToken, primary, now); err != nil {
		t.Fatal(err)
	}
	secondaryScope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-b", EnvironmentID: "production", ServiceID: "worker"}
	secondaryToken, err := store.CreateSource(ctx, "source-b", secondaryScope)
	if err != nil {
		t.Fatal(err)
	}
	secondary := model.Batch{Version: model.BatchVersion, SourceID: "source-b", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{
		requestObservation(now.Add(-time.Minute), "/other", 500, 500),
	}}
	if _, err = store.Ingest(ctx, secondaryToken, secondary, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)

	ast, err := query.Parse(`logs | where status >= 500 | window 1h | summarize count() by route, window(5m) | sort count desc | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a"}, testQueryBudget(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Explain.ProjectedSources) != 1 || !strings.HasSuffix(result.Explain.ProjectedSources[0], "/rollup:http-status-route:5m") {
		t.Fatalf("sources=%v", result.Explain.ProjectedSources)
	}
	if len(result.Rows) != 3 || columnValue(t, result, 0, "http.route") != "/items" || columnValue(t, result, 0, "count") != "2" {
		t.Fatalf("result=%+v", result)
	}
	if result.Stats.ScannedRows != 4 || result.Stats.MatchedRows != 4 || result.Stats.ScannedBytes < 1 || result.Stats.Truncated {
		t.Fatalf("statistics=%+v", result.Stats)
	}
	if result.Explain.EstimatedScanBytes < 1 || result.Explain.EstimatedScanBytes >= result.Stats.ScannedBytes {
		t.Fatalf("estimate=%d logical_scan=%d", result.Explain.EstimatedScanBytes, result.Stats.ScannedBytes)
	}
	if bucket := columnValue(t, result, 0, "window_start"); bucket != now.Add(-time.Minute).Truncate(5*time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("bucket=%q", bucket)
	}

	scoped, err := store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a", ProjectID: "project-a"}, testQueryBudget(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped.Rows) != 2 || scoped.Stats.ScannedRows != 3 || scoped.Stats.MatchedRows != 3 {
		t.Fatalf("scoped=%+v", scoped)
	}
}

func TestIndexedLogCountSummaryUsesRawOnlyForPartialLowerBucket(t *testing.T) {
	ctx := t.Context()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 18, 12, 7, 30, 0, time.UTC)
	scope := model.Scope{OrganizationID: "organization-partial", ProjectID: "project", EnvironmentID: "production", ServiceID: "web"}
	token, err := store.CreateSource(ctx, "source-partial", scope)
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-partial", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{
		requestObservation(time.Date(2026, 8, 18, 12, 1, 0, 0, time.UTC), "/before", 500, 1),
		requestObservation(time.Date(2026, 8, 18, 12, 2, 0, 0, time.UTC), "/partial", 500, 2),
		requestObservation(time.Date(2026, 8, 18, 12, 4, 59, 0, time.UTC), "/partial", 503, 3),
		requestObservation(time.Date(2026, 8, 18, 12, 5, 0, 0, time.UTC), "/full", 500, 4),
		requestObservation(time.Date(2026, 8, 18, 12, 6, 0, 0, time.UTC), "/ignored", 200, 5),
		{Timestamp: time.Date(2026, 8, 18, 12, 5, 1, 0, time.UTC), Name: "application.http.request", Attributes: map[string]string{"http.status_code": "500"}},
		{Timestamp: time.Date(2026, 8, 18, 12, 5, 2, 0, time.UTC), Name: "application.http.request", Attributes: map[string]string{"http.route": "", "http.status_code": "500"}},
	}}
	ack, err := store.Ingest(ctx, token, batch, now)
	if err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	// Replaying the already projected segment must not increment the additive
	// rollup. The segment ledger makes projection recovery idempotent.
	if err = projectAt(ctx, store.organizationProjectionPath(scope.OrganizationID), scope, batch, ack.Digest); err != nil {
		t.Fatal(err)
	}

	ast, err := query.Parse(`logs | where status >= 500 | window 6m | summarize count() by route, window(5m) | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Query(ctx, ast, query.Scope{OrganizationID: scope.OrganizationID}, testQueryBudget(), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.ScannedRows != 5 || result.Stats.MatchedRows != 5 || len(result.Rows) != 4 {
		t.Fatalf("result=%+v", result)
	}
	if bucket := columnValue(t, result, 0, "window_start"); bucket != "2026-08-18T12:00:00Z" {
		t.Fatalf("partial bucket=%q", bucket)
	}
	if route := columnValue(t, result, 0, "http.route"); route != "/partial" || columnValue(t, result, 0, "count") != "2" {
		t.Fatalf("partial row=%+v", result.Rows[0])
	}
	// Missing and explicitly empty routes remain distinct typed values.
	if result.Rows[1].Values[1] != nil || result.Rows[2].Values[1] == nil || *result.Rows[2].Values[1] != "" {
		t.Fatalf("route presence was collapsed: %+v", result.Rows)
	}
	if columnValue(t, result, 3, "http.route") != "/full" || columnValue(t, result, 3, "count") != "1" {
		t.Fatalf("full row=%+v", result.Rows[3])
	}
}

func TestLogRollupMigrationBackfillsExistingProjection(t *testing.T) {
	ctx := t.Context()
	root := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(filepath.Join(root, "organizations", "legacy"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "organizations", "legacy", "projection.sqlite")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(`CREATE TABLE observations (
		organization_id TEXT NOT NULL, project_id TEXT NOT NULL, environment_id TEXT NOT NULL, service_id TEXT NOT NULL,
		source_id TEXT NOT NULL, stream_id TEXT NOT NULL, sequence INTEGER NOT NULL, record_index INTEGER NOT NULL,
		signal TEXT NOT NULL, timestamp TEXT NOT NULL, name TEXT NOT NULL, severity TEXT, body TEXT, value REAL,
		trace_id TEXT, span_id TEXT, correlation_id TEXT, attributes_json TEXT NOT NULL, segment_digest TEXT NOT NULL,
		PRIMARY KEY(source_id,stream_id,sequence,record_index));
		INSERT INTO observations VALUES
		('legacy','project','prod','web','source','logs',1,0,'logs','2026-08-18T12:01:00Z','request',NULL,NULL,NULL,NULL,NULL,NULL,'{"http.route":"/one","http.status_code":"503"}','digest'),
		('legacy','project','prod','web','source','logs',1,1,'logs','2026-08-18T12:02:00Z','request',NULL,NULL,NULL,NULL,NULL,NULL,'{"http.route":"/one","http.status_code":"503"}','digest'),
		('legacy','project','prod','web','source','logs',1,2,'logs','2026-08-18T12:02:01Z','request',NULL,NULL,NULL,NULL,NULL,NULL,'{"http.route":"/invalid","http.status_code":"503suffix"}','digest')`); err != nil {
		t.Fatal(err)
	}
	if err = legacy.Close(); err != nil {
		t.Fatal(err)
	}
	projection, err := openProjection(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer projection.Close()
	var count, segments, version int
	if err = projection.QueryRow(`SELECT observation_count FROM log_status_route_rollups_5m`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if err = projection.QueryRow(`SELECT COUNT(*) FROM log_rollup_segments`).Scan(&segments); err != nil || segments != 1 {
		t.Fatalf("segments=%d err=%v", segments, err)
	}
	if err = projection.QueryRow(`SELECT version FROM log_rollup_state WHERE id=1`).Scan(&version); err != nil || version != logRollupVersion {
		t.Fatalf("version=%d err=%v", version, err)
	}
}

func TestIndexedLogCountSummaryEligibilityIsNarrow(t *testing.T) {
	tests := []struct {
		text string
		want bool
	}{
		{`logs | where status >= 500 | summarize count() by route, window(5m) | limit 10`, true},
		{`logs | where status >= 400 | summarize count() by route | limit 10`, true},
		{`logs | where status == 500 | summarize count() by route | limit 10`, false},
		{`logs | where status =~ "5.." | summarize count() by route, window(5m) | limit 10`, false},
		{`logs | where route == "/items" | summarize count() by route, window(5m) | limit 10`, false},
		{`logs | where status >= 500 | summarize count() by status, window(5m) | limit 10`, false},
		{`logs | where status >= 500 | summarize p95(duration) by route, window(5m) | limit 10`, false},
		{`logs | where status >= 500 | summarize count() by route, window(1500ms) | limit 10`, false},
		{`traces | where status >= 500 | summarize count() by route, window(5m) | limit 10`, false},
	}
	for _, test := range tests {
		ast, err := query.Parse(test.text, 100)
		if err != nil {
			t.Fatalf("parse %q: %v", test.text, err)
		}
		if got := indexedLogCountSummaryEligible(ast); got != test.want {
			t.Fatalf("eligible(%q)=%t want %t", test.text, got, test.want)
		}
	}
}
