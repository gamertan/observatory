// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

func TestQueryExecutesScopedTypedFiltersAndSorting(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 7, 0, 0, 0, time.UTC)
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	records := []model.Observation{
		requestObservation(now.Add(-time.Minute), "/ok", 200, 50),
		requestObservation(now.Add(-2*time.Minute), "/broken", 503, 300),
		requestObservation(now.Add(-3*time.Minute), "/slow", 500, 200),
		{Timestamp: now.Add(-4 * time.Minute), Name: "application.http.request", Attributes: map[string]string{"http.route": "/invalid", "http.status_code": "not-a-number", "duration_ns": "invalid"}},
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: records}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	otherToken, err := store.CreateSource(ctx, "source-b", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-b"})
	if err != nil {
		t.Fatal(err)
	}
	other := model.Batch{Version: model.BatchVersion, SourceID: "source-b", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{requestObservation(now, "/other", 599, 999)}}
	if _, err = store.Ingest(ctx, otherToken, other, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	projectionPath := filepath.Join(store.root, "organizations", "organization-a", "projection.sqlite")
	projectionBefore, err := os.ReadFile(projectionPath)
	if err != nil {
		t.Fatal(err)
	}
	infoBefore, err := os.Stat(projectionPath)
	if err != nil {
		t.Fatal(err)
	}

	ast, err := query.Parse(`logs | where status >= 500 | window 1h | sort duration desc | limit 1`, 100)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}, testQueryBudget(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || result.Stats.MatchedRows != 2 || !result.Stats.Truncated {
		t.Fatalf("result=%+v", result)
	}
	duration := columnValue(t, result, 0, "duration_ns")
	service := columnValue(t, result, 0, "service.id")
	if duration != "300" || service != "service-a" {
		t.Fatalf("duration=%q service=%q result=%+v", duration, service, result)
	}
	ast, err = query.Parse(`logs | sort duration desc | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	result, err = store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a", ServiceID: "service-a"}, testQueryBudget(), now)
	if err != nil {
		t.Fatal(err)
	}
	for index, column := range result.Columns {
		if column.Field == "duration_ns" && (len(result.Rows) != 4 || result.Rows[3].Values[index] != nil) {
			t.Fatalf("invalid numeric value was not sorted last: %+v", result)
		}
	}
	projectionAfter, err := os.ReadFile(projectionPath)
	if err != nil {
		t.Fatal(err)
	}
	infoAfter, err := os.Stat(projectionPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(projectionBefore, projectionAfter) || !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("query execution modified the organization projection")
	}
}

func TestQuerySummarizesThroughSharedBucketAST(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 7, 2, 0, 0, time.UTC)
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{
		requestObservation(now.Add(-time.Minute), "/items", 200, 100),
		requestObservation(now.Add(-2*time.Minute), "/items", 500, 300),
		requestObservation(now.Add(-time.Minute), "/about", 200, 20),
	}}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	ast, err := query.Parse(`logs | summarize count(), p95(duration) by route, window(5m) | sort count desc | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	if ast.Window != 0 || ast.Bucket != 5*time.Minute {
		t.Fatalf("window=%s bucket=%s", ast.Window, ast.Bucket)
	}
	result, err := store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a"}, testQueryBudget(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 2 || columnValue(t, result, 0, "http.route") != "/items" || columnValue(t, result, 0, "count") != "2" || columnValue(t, result, 0, "p95_duration") != "300" {
		t.Fatalf("result=%+v", result)
	}
	filtered, err := query.Parse(`logs | where status >= 500 | summarize count() by route, window(5m) | sort count desc | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	result, err = store.Query(ctx, filtered, query.Scope{OrganizationID: "organization-a"}, testQueryBudget(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || columnValue(t, result, 0, "http.route") != "/items" || columnValue(t, result, 0, "count") != "1" {
		t.Fatalf("filtered result=%+v", result)
	}
}

func TestSummaryProjectionUsesSelectiveIndexWithoutRecordOrder(t *testing.T) {
	now := time.Date(2026, 8, 17, 7, 2, 0, 0, time.UTC)
	ast, err := query.Parse(`logs | where status >= 500 | window 24h | summarize count() by route, window(5m) | sort count desc | limit 50`, 100)
	if err != nil {
		t.Fatal(err)
	}
	statement, _, err := projectionSelection(ast, query.Scope{OrganizationID: "organization-a"}, nil, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statement, "FROM observations o INDEXED BY observations_http_status") {
		t.Fatalf("summary did not pin the selective status index: %s", statement)
	}
	if strings.Contains(statement, " ORDER BY o.timestamp") {
		t.Fatalf("summary retained unnecessary record ordering: %s", statement)
	}

	ordinary, err := query.Parse(`logs | where status >= 500 | window 24h | limit 50`, 100)
	if err != nil {
		t.Fatal(err)
	}
	statement, arguments, err := projectionSelection(ordinary, query.Scope{OrganizationID: "organization-a"}, nil, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(statement, " INDEXED BY ") || !strings.Contains(statement, " ORDER BY o.timestamp") || !strings.HasSuffix(statement, " LIMIT ?") || arguments[len(arguments)-1] != 51 {
		t.Fatalf("ordinary record query changed its ordered plan: %s", statement)
	}

	regularExpression, err := query.Parse(`logs | where route =~ "^/items" | window 24h | limit 50`, 100)
	if err != nil {
		t.Fatal(err)
	}
	statement, _, err = projectionSelection(regularExpression, query.Scope{OrganizationID: "organization-a"}, nil, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(statement, " LIMIT ?") {
		t.Fatalf("regular-expression query limited rows before Go evaluation: %s", statement)
	}
}

func TestQueryPlansBoundedRecordLimitIndependentlyOfProjectionSize(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{
		requestObservation(now.Add(-time.Minute), "/one", 200, 10),
		requestObservation(now.Add(-2*time.Minute), "/two", 200, 20),
		requestObservation(now.Add(-3*time.Minute), "/three", 200, 30),
	}}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	projectionBytes, err := store.EstimateOrganizationBytes("organization-a")
	if err != nil || projectionBytes < 4 {
		t.Fatalf("projection bytes=%d err=%v", projectionBytes, err)
	}
	budget := testQueryBudget()
	budget.MaxScannedBytes = projectionBytes - 1
	budget.MaxMemoryBytes = min(projectionBytes/2, 1<<20)
	ast, err := query.Parse(`logs | window 1h | limit 1`, 100)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a"}, budget, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || result.Stats.ScannedRows != 2 || !result.Stats.Truncated || result.Explain.EstimatedScanBytes != budget.MaxMemoryBytes {
		t.Fatalf("result=%+v", result)
	}

	regex, err := query.Parse(`logs | where route =~ "^/" | window 1h | limit 1`, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Query(ctx, regex, query.Scope{OrganizationID: "organization-a"}, budget, now); err == nil || !strings.Contains(err.Error(), "estimated query scan exceeds budget") {
		t.Fatalf("unbounded regex planning err=%v", err)
	}
}

func TestQueryEnforcesSensitiveAndExecutionBudgets(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 7, 0, 0, 0, time.UTC)
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "application.http.request", Body: "private evidence"}}}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	ast, _ := query.Parse(`logs | where body == "private evidence" | limit 10`, 100)
	if _, err = store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a"}, testQueryBudget(), now); !errors.Is(err, query.ErrSensitivePermissionRequired) {
		t.Fatalf("sensitive err=%v", err)
	}
	ast, _ = query.Parse(`logs | limit 10`, 100)
	budget := testQueryBudget()
	budget.MaxMemoryBytes = 1
	if _, err = store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a", Sensitive: true}, budget, now); !errors.Is(err, query.ErrBudgetExceeded) {
		t.Fatalf("budget err=%v", err)
	}
}

func requestObservation(timestamp time.Time, route string, status int, duration int) model.Observation {
	return model.Observation{Timestamp: timestamp, Name: "application.http.request", Attributes: map[string]string{"http.route": route, "http.status_code": strconv.Itoa(status), "duration_ns": strconv.Itoa(duration)}}
}

func testQueryBudget() query.Budget {
	return query.Budget{MaxDuration: 5 * time.Second, MaxRows: 100, MaxScannedBytes: 100 << 20, MaxMemoryBytes: 10 << 20}
}

func columnValue(t *testing.T, result query.Result, row int, field string) string {
	t.Helper()
	for index, column := range result.Columns {
		if column.Field == field {
			if result.Rows[row].Values[index] == nil {
				t.Fatalf("field %s is nil", field)
			}
			return *result.Rows[row].Values[index]
		}
	}
	t.Fatalf("field %s is absent: %+v", field, result.Columns)
	return ""
}
