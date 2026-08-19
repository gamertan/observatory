// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

func TestBaseIndexMigrationReplacesLegacyFullIndexes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	dir := filepath.Join(root, "organizations", "legacy")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "projection.sqlite")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE observations (organization_id TEXT NOT NULL,project_id TEXT NOT NULL,environment_id TEXT NOT NULL,service_id TEXT NOT NULL,source_id TEXT NOT NULL,stream_id TEXT NOT NULL,sequence INTEGER NOT NULL,record_index INTEGER NOT NULL,signal TEXT NOT NULL,timestamp TEXT NOT NULL,name TEXT NOT NULL,severity TEXT,body TEXT,value REAL,trace_id TEXT,span_id TEXT,correlation_id TEXT,attributes_json TEXT NOT NULL,segment_digest TEXT NOT NULL,PRIMARY KEY(source_id,stream_id,sequence,record_index))`,
		`CREATE TABLE storage_projection_state (id INTEGER PRIMARY KEY CHECK(id=1),metric_rollup_version INTEGER NOT NULL CHECK(metric_rollup_version BETWEEN 0 AND 1))`,
		`INSERT INTO storage_projection_state(id,metric_rollup_version) VALUES(1,1)`,
		`CREATE INDEX observations_value ON observations(signal,value,timestamp)`,
		`CREATE INDEX observations_http_route ON observations(signal,json_extract(attributes_json,'$."http.route"'),timestamp)`,
		`CREATE INDEX observations_http_status ON observations(signal,CAST(json_extract(attributes_json,'$."http.status_code"') AS INTEGER),timestamp)`,
		`CREATE INDEX observations_duration ON observations(signal,CAST(json_extract(attributes_json,'$."duration_ns"') AS REAL),timestamp)`,
	}
	for _, statement := range statements {
		if _, err = legacy.Exec(statement); err != nil {
			legacy.Close()
			t.Fatal(err)
		}
	}
	if err = legacy.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := openProjection(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err = db.QueryRow(`SELECT base_index_version FROM storage_projection_state WHERE id=1`).Scan(&version); err != nil || version != baseIndexVersion {
		t.Fatalf("base index version=%d err=%v", version, err)
	}
	for _, name := range []string{"observations_value", "observations_http_route", "observations_http_status", "observations_duration"} {
		var definition string
		if err = db.QueryRow(`SELECT sql FROM sqlite_schema WHERE type='index' AND name=?`, name).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.ToUpper(definition), " WHERE ") || !strings.Contains(strings.ToUpper(definition), " IS NOT NULL") {
			t.Fatalf("index %s was not migrated: %s", name, definition)
		}
	}
}

func TestPresenceIndexesSupportSelectiveQueries(t *testing.T) {
	ctx := t.Context()
	store := testStore(t)
	defer store.Close()
	now := time.Now().UTC()
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	logToken, err := store.CreateSource(ctx, "source-logs", scope)
	if err != nil {
		t.Fatal(err)
	}
	logs := model.Batch{Version: model.BatchVersion, SourceID: "source-logs", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{
		{Timestamp: now, Name: "http.server.request", Severity: "error", Attributes: map[string]string{"http.route": "/items", "http.status_code": "503", "duration_ns": "500"}},
		{Timestamp: now.Add(-time.Second), Name: "application.event", Severity: "information", Attributes: map[string]string{}},
	}}
	if _, err = store.Ingest(ctx, logToken, logs, now); err != nil {
		t.Fatal(err)
	}
	metricToken, err := store.CreateSource(ctx, "source-metrics", scope)
	if err != nil {
		t.Fatal(err)
	}
	value := 42.0
	metrics := model.Batch{Version: model.BatchVersion, SourceID: "source-metrics", StreamID: "metrics", Sequence: 1, ObservedAt: now, Signal: model.SignalMetrics, Records: []model.Observation{{Timestamp: now, Name: "system.cpu.utilization", Value: &value}}}
	if _, err = store.Ingest(ctx, metricToken, metrics, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	queries := []string{
		`logs | where route == "/items" | summarize count() by status | limit 10`,
		`logs | where status >= 500 | summarize p95(duration) by route | limit 10`,
		`logs | where duration >= 100 | summarize count() by route | limit 10`,
		`metrics | where value >= 1 | summarize count() by name | limit 10`,
	}
	for _, text := range queries {
		ast, parseErr := query.Parse(text, 10)
		if parseErr != nil {
			t.Fatalf("parse %q: %v", text, parseErr)
		}
		result, queryErr := store.Query(ctx, ast, query.Scope{OrganizationID: scope.OrganizationID}, testQueryBudget(), now)
		if queryErr != nil || len(result.Rows) == 0 {
			t.Fatalf("query %q rows=%d err=%v", text, len(result.Rows), queryErr)
		}
	}
}
