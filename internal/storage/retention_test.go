// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/segment"
)

var previewRetention = RetentionPolicy{RawLogsDays: 30, RawTracesDays: 30, RawMetricsDays: 14, ColdRawDays: 400, MetricRollupsDays: 400, EvidenceDays: 400}

func TestMetricRollupsAggregateAndBackfill(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	ctx := t.Context()
	scope := model.Scope{OrganizationID: "org-rollup", ProjectID: "project", EnvironmentID: "production", ServiceID: "web"}
	token, err := store.CreateSource(ctx, "source-rollup", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 4, 8, 0, 0, time.UTC)
	values := []float64{-2, 0, 3, 100}
	records := make([]model.Observation, 0, len(values))
	for index := range values {
		value := values[index]
		records = append(records, model.Observation{Timestamp: now.Add(time.Duration(index) * time.Second), Name: "http.duration", Value: &value, Attributes: map[string]string{"http.route": "/", "private.token_hint": "must-not-roll-up"}})
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-rollup", StreamID: "metrics", Sequence: 1, ObservedAt: now, Signal: model.SignalMetrics, Records: records}
	ack, err := store.Ingest(ctx, token, batch, now)
	if err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	if err = projectAt(ctx, store.organizationProjectionPath(scope.OrganizationID), scope, batch, ack.Digest); err != nil {
		t.Fatal(err)
	}
	db := openTestProjection(t, store.organizationProjectionPath(scope.OrganizationID))
	defer db.Close()
	var count int64
	var sum, minimum, maximum float64
	var histogram, dimensions string
	if err = db.QueryRow(`SELECT sample_count,value_sum,value_min,value_max,histogram_json,attributes_json FROM metric_rollups_5m`).Scan(&count, &sum, &minimum, &maximum, &histogram, &dimensions); err != nil {
		t.Fatal(err)
	}
	if count != 4 || sum != 101 || minimum != -2 || maximum != 100 {
		t.Fatalf("count=%d sum=%g min=%g max=%g", count, sum, minimum, maximum)
	}
	var ledger int
	if err = db.QueryRow(`SELECT COUNT(*) FROM metric_rollup_segments WHERE segment_digest=?`, ack.Digest).Scan(&ledger); err != nil || ledger != 1 {
		t.Fatalf("rollup ledger=%d err=%v", ledger, err)
	}
	if dimensions != `{"http.route":"/"}` {
		t.Fatalf("rollup dimensions=%s", dimensions)
	}
	bins, err := decodeHistogram(histogram)
	if err != nil {
		t.Fatal(err)
	}
	p95, ok := histogramPercentile(bins, .95)
	if !ok || math.Abs(p95-100) > 2 {
		t.Fatalf("p95=%g ok=%t", p95, ok)
	}

	// Simulate the projection shape from a prior private preview. The first
	// open performs one transactional backfill and records its version.
	legacyRoot := filepath.Join(t.TempDir(), "data")
	if err = os.MkdirAll(filepath.Join(legacyRoot, "organizations", "legacy"), 0o700); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(legacyRoot, "organizations", "legacy", "projection.sqlite")
	legacy, err := sql.Open("sqlite", legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(`CREATE TABLE observations (
		organization_id TEXT NOT NULL, project_id TEXT NOT NULL, environment_id TEXT NOT NULL, service_id TEXT NOT NULL,
		source_id TEXT NOT NULL, stream_id TEXT NOT NULL, sequence INTEGER NOT NULL, record_index INTEGER NOT NULL,
		signal TEXT NOT NULL, timestamp TEXT NOT NULL, name TEXT NOT NULL, severity TEXT, body TEXT, value REAL,
		trace_id TEXT, span_id TEXT, correlation_id TEXT, attributes_json TEXT NOT NULL, segment_digest TEXT NOT NULL,
		PRIMARY KEY(source_id,stream_id,sequence,record_index));
		INSERT INTO observations VALUES('legacy','project','prod','web','source','metrics',1,0,'metrics','2026-08-17T04:01:00Z','queue',NULL,NULL,5,NULL,NULL,NULL,'{}','digest')`); err != nil {
		t.Fatal(err)
	}
	if err = legacy.Close(); err != nil {
		t.Fatal(err)
	}
	legacy, err = openProjection(ctx, legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if err = legacy.QueryRow(`SELECT sample_count,value_sum FROM metric_rollups_5m`).Scan(&count, &sum); err != nil || count != 1 || sum != 5 {
		t.Fatalf("backfilled count=%d sum=%g err=%v", count, sum, err)
	}
}

func TestRetentionPreservesRollupsAndRetiresRawSegments(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	ctx := t.Context()
	scope := model.Scope{OrganizationID: "org-retain", ProjectID: "project", EnvironmentID: "production", ServiceID: "web"}
	token, err := store.CreateSource(ctx, "source-retain", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 5, 0, 0, 0, time.UTC)
	ingest := func(stream string, signal model.Signal, timestamp time.Time, value *float64) string {
		t.Helper()
		observation := model.Observation{Timestamp: timestamp, Name: "sample", Value: value}
		if signal == model.SignalLogs {
			observation = requestObservation(timestamp, "/retained", 503, 1)
		}
		batch := model.Batch{Version: model.BatchVersion, SourceID: "source-retain", StreamID: stream, Sequence: 1, ObservedAt: now, Signal: signal, Records: []model.Observation{observation}}
		ack, ingestErr := store.Ingest(ctx, token, batch, now)
		if ingestErr != nil {
			t.Fatal(ingestErr)
		}
		var path string
		if ingestErr = store.control.QueryRow(`SELECT path FROM segments WHERE digest=?`, ack.Digest).Scan(&path); ingestErr != nil {
			t.Fatal(ingestErr)
		}
		return path
	}
	metricValue := 42.0
	logPath := ingest("logs", model.SignalLogs, now.Add(-31*24*time.Hour), nil)
	metricPath := ingest("metrics", model.SignalMetrics, now.Add(-15*24*time.Hour), &metricValue)
	deploymentPath := ingest("deployments", model.SignalDeployments, now.Add(-399*24*time.Hour), nil)
	projectAll(t, store)
	report, err := store.ApplyRetention(ctx, previewRetention, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.RawSegmentsRemoved != 0 || report.RawSegmentsArchived != 2 || report.ProjectedObservationsRemoved != 2 || report.MetricRollupsRemoved != 0 || report.LogRollupsRemoved != 1 {
		t.Fatalf("report=%+v", report)
	}
	for _, hot := range []string{logPath, metricPath} {
		if _, err = os.Lstat(hot); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("hot path still exists: %s err=%v", hot, err)
		}
	}
	for _, signal := range []model.Signal{model.SignalLogs, model.SignalMetrics} {
		var path, tier string
		if err = store.control.QueryRow(`SELECT path,tier FROM segments WHERE organization_id=? AND signal=?`, scope.OrganizationID, signal).Scan(&path, &tier); err != nil {
			t.Fatal(err)
		}
		if tier != "cold" || !strings.Contains(filepath.ToSlash(path), "/cold/") {
			t.Fatalf("signal=%s tier=%s path=%s", signal, tier, path)
		}
		if _, err = os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = os.Lstat(deploymentPath); err != nil {
		t.Fatal(err)
	}
	metricAST, err := query.Parse(`metrics | window 720h | summarize count(), p95(value) | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	metricResult, err := store.Query(ctx, metricAST, query.Scope{OrganizationID: scope.OrganizationID, Sensitive: true}, query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 1 << 20, MaxMemoryBytes: 1 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	if metricResult.Stats.Approximate || len(metricResult.Rows) != 1 || metricResult.Rows[0].Values[0] == nil || *metricResult.Rows[0].Values[0] != "1" || metricResult.Rows[0].Values[1] == nil || *metricResult.Rows[0].Values[1] != "42" || len(metricResult.Explain.ProjectedSources) != 2 || !strings.HasSuffix(metricResult.Explain.ProjectedSources[1], "/cold:raw") {
		t.Fatalf("cold metric result=%+v", metricResult)
	}
	logAST, err := query.Parse(`logs | window 960h | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	logResult, err := store.Query(ctx, logAST, query.Scope{OrganizationID: scope.OrganizationID, Sensitive: true}, query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 1 << 20, MaxMemoryBytes: 1 << 20}, now)
	if err != nil || len(logResult.Rows) != 1 || len(logResult.Explain.ProjectedSources) != 2 || !strings.HasSuffix(logResult.Explain.ProjectedSources[1], "/cold:raw") {
		t.Fatalf("cold log result=%+v err=%v", logResult, err)
	}
	if _, err = store.Query(ctx, logAST, query.Scope{OrganizationID: scope.OrganizationID, Sensitive: true}, query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 1 << 20, MaxMemoryBytes: 1}, now); !errors.Is(err, query.ErrBudgetExceeded) {
		t.Fatalf("cold query memory budget err=%v", err)
	}
	db := openTestProjection(t, store.organizationProjectionPath(scope.OrganizationID))
	var observations, rollups, logRollups int
	if err = db.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM metric_rollups_5m`).Scan(&rollups); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM log_status_route_rollups_5m`).Scan(&logRollups); err != nil {
		t.Fatal(err)
	}
	if observations != 1 || rollups != 1 || logRollups != 0 {
		t.Fatalf("observations=%d metric_rollups=%d log_rollups=%d", observations, rollups, logRollups)
	}
	info, statErr := os.Stat(store.organizationProjectionPath(scope.OrganizationID))
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("projection mode=%v", info.Mode().Perm())
	}
	var rawSegments, ledger int
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM segments`).Scan(&rawSegments); err != nil || rawSegments != 3 {
		t.Fatalf("raw_segments=%d err=%v", rawSegments, err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM metric_rollup_segments`).Scan(&ledger); err != nil || ledger != 1 {
		t.Fatalf("rollup ledger=%d err=%v", ledger, err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM log_rollup_segments`).Scan(&ledger); err != nil || ledger != 1 {
		t.Fatalf("log rollup ledger=%d err=%v", ledger, err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	finalReport, err := store.ApplyRetention(ctx, previewRetention, now.Add(401*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if finalReport.RawSegmentsRemoved != 0 || finalReport.MetricRollupsRemoved != 1 {
		t.Fatalf("final report=%+v", finalReport)
	}
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM segments`).Scan(&rawSegments); err != nil || rawSegments != 3 {
		t.Fatalf("preserved raw_segments=%d err=%v", rawSegments, err)
	}
	deletingPolicy := previewRetention
	deletingPolicy.DeleteColdRaw = true
	deletionReport, err := store.ApplyRetention(ctx, deletingPolicy, now.Add(401*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if deletionReport.RawSegmentsRemoved != 3 {
		t.Fatalf("deletion report=%+v", deletionReport)
	}
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM segments`).Scan(&rawSegments); err != nil || rawSegments != 0 {
		t.Fatalf("final raw_segments=%d err=%v", rawSegments, err)
	}
	db = openTestProjection(t, store.organizationProjectionPath(scope.OrganizationID))
	defer db.Close()
	if err = db.QueryRow(`SELECT COUNT(*) FROM log_rollup_segments`).Scan(&ledger); err != nil || ledger != 0 {
		t.Fatalf("final log rollup ledger=%d err=%v", ledger, err)
	}
}

func TestRetainingColdRawBeyondDefaultRequiresApprovalOnlyWhenServerDeletes(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	defaults := previewRetention
	defaults.DeleteColdRaw = true
	policy := defaults
	policy.DeleteColdRaw = false
	input := SetRetentionInput{OrganizationID: "org-forensic", Policy: policy, Defaults: defaults, ActorUserID: "owner"}
	if _, err := store.SetOrganizationRetention(t.Context(), input, time.Now().UTC()); err == nil {
		t.Fatal("indefinite forensic retention without extension approval was accepted")
	}
	input.ApproveExtensionFor = input.OrganizationID
	input.QuotaBytes = 1
	retained, err := store.SetOrganizationRetention(t.Context(), input, time.Now().UTC())
	if err != nil || !retained.ExtensionApproved || retained.Policy.DeleteColdRaw {
		t.Fatalf("retained=%+v err=%v", retained, err)
	}
	var summary string
	if err = store.control.QueryRow(`SELECT summary FROM retention_policy_events WHERE organization_id=?`, input.OrganizationID).Scan(&summary); err != nil || !strings.Contains(summary, "delete_cold_raw=false") {
		t.Fatalf("summary=%q err=%v", summary, err)
	}
}

func TestColdCutoffDoesNotExtendAnIndefinitePolicy(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	policy := previewRetention
	policy.ColdRawDays++
	retained, err := store.SetOrganizationRetention(t.Context(), SetRetentionInput{
		OrganizationID: "org-indefinite", Policy: policy, Defaults: previewRetention, ActorUserID: "owner",
	}, time.Now().UTC())
	if err != nil || retained.ExtensionApproved {
		t.Fatalf("retained=%+v err=%v", retained, err)
	}
}

func TestMetricRollupRejectsOutOfRangeValueBeforeRawCommit(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	ctx := t.Context()
	scope := model.Scope{OrganizationID: "org-range", ProjectID: "project", EnvironmentID: "production", ServiceID: "web"}
	token, err := store.CreateSource(ctx, "source-range", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	value := maxMetricMagnitude * 2
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-range", StreamID: "metrics", Sequence: 1, ObservedAt: now, Signal: model.SignalMetrics, Records: []model.Observation{{Timestamp: now, Name: "sample", Value: &value}}}
	if _, err = store.Ingest(ctx, token, batch, now); err == nil {
		t.Fatal("out-of-range metric value was accepted")
	}
	entries, err := store.segments.List()
	if err != nil || len(entries) != 0 {
		t.Fatalf("raw entries=%d err=%v", len(entries), err)
	}
}

func TestColdQueryCombinesHotAndColdWithoutDuplication(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	ctx := t.Context()
	scope := model.Scope{OrganizationID: "org-hot-cold", ProjectID: "project", EnvironmentID: "production", ServiceID: "web"}
	token, err := store.CreateSource(ctx, "source-hot-cold", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 6, 0, 0, 0, time.UTC)
	for index, sample := range []struct {
		stream string
		at     time.Time
	}{{"old", now.Add(-31 * 24 * time.Hour)}, {"new", now.Add(-time.Hour)}} {
		batch := model.Batch{Version: model.BatchVersion, SourceID: "source-hot-cold", StreamID: sample.stream, Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: sample.at, Name: "sample", Body: string(rune('a' + index))}}}
		if _, err = store.Ingest(ctx, token, batch, now); err != nil {
			t.Fatal(err)
		}
	}
	projectAll(t, store)
	if _, err = store.ApplyRetention(ctx, previewRetention, now); err != nil {
		t.Fatal(err)
	}
	ast, err := query.Parse(`logs | window 960h | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Query(ctx, ast, query.Scope{OrganizationID: scope.OrganizationID, Sensitive: true}, query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 1 << 20, MaxMemoryBytes: 1 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 2 || result.Stats.MatchedRows != 2 || len(result.Explain.ProjectedSources) != 2 || !strings.HasSuffix(result.Explain.ProjectedSources[1], "/cold:raw") {
		t.Fatalf("combined result=%+v", result)
	}
}

func TestRetentionExtensionRequiresApprovalAndEnforcesQuota(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	ctx := t.Context()
	now := time.Date(2026, 8, 17, 5, 0, 0, 0, time.UTC)
	scope := model.Scope{OrganizationID: "org-quota", ProjectID: "project", EnvironmentID: "production", ServiceID: "web"}
	token, err := store.CreateSource(ctx, "source-quota", scope)
	if err != nil {
		t.Fatal(err)
	}
	extended := previewRetention
	extended.RawLogsDays++
	input := SetRetentionInput{OrganizationID: scope.OrganizationID, Policy: extended, Defaults: previewRetention, ActorUserID: "owner"}
	if _, err = store.SetOrganizationRetention(ctx, input, now); err == nil {
		t.Fatal("retention extension without approval was accepted")
	}
	used, err := store.organizationStorageBytes(scope.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	input.ApproveExtensionFor, input.QuotaBytes = scope.OrganizationID, used+1
	policy, err := store.SetOrganizationRetention(ctx, input, now)
	if err != nil || !policy.ExtensionApproved {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-quota", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "sample"}}}
	if _, err = store.Ingest(ctx, token, batch, now); err == nil || err.Error() != "organization storage quota exceeded" {
		t.Fatalf("quota ingest err=%v", err)
	}
	var segments int
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM segments`).Scan(&segments); err != nil || segments != 0 {
		t.Fatalf("segments=%d err=%v", segments, err)
	}
}

func TestQuotaAdmissionSerializesSourcesAndRecoveryCannotBypassQuota(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	ctx := t.Context()
	now := time.Date(2026, 8, 17, 5, 30, 0, 0, time.UTC)
	scope := model.Scope{OrganizationID: "org-quota-race", ProjectID: "project", EnvironmentID: "production", ServiceID: "web"}
	for _, sourceID := range []string{"source-race-a", "source-race-b"} {
		if _, err := store.CreateSource(ctx, sourceID, scope); err != nil {
			t.Fatal(err)
		}
	}
	batches := []model.Batch{
		{Version: model.BatchVersion, SourceID: "source-race-a", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "sample"}}},
		{Version: model.BatchVersion, SourceID: "source-race-b", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "sample"}}},
	}
	committed := make([]segment.Committed, len(batches))
	var err error
	for index := range batches {
		committed[index], err = store.segments.Commit(scope, batches[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	quota := committed[0].Compressed + committed[0].Uncompressed
	other := committed[1].Compressed + committed[1].Uncompressed
	if other > quota {
		quota = other
	}
	extended := previewRetention
	extended.RawLogsDays++
	if _, err = store.SetOrganizationRetention(ctx, SetRetentionInput{OrganizationID: scope.OrganizationID, Policy: extended, Defaults: previewRetention, ActorUserID: "owner", ApproveExtensionFor: scope.OrganizationID, QuotaBytes: quota}, now); err != nil {
		t.Fatal(err)
	}

	errorsBySource := make(chan error, len(batches))
	var group sync.WaitGroup
	for index := range batches {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			errorsBySource <- store.admitCommitted(ctx, scope, batches[index], committed[index], time.Now().UTC())
		}(index)
	}
	group.Wait()
	close(errorsBySource)
	accepted, rejected := 0, 0
	for admissionErr := range errorsBySource {
		switch {
		case admissionErr == nil:
			accepted++
		case errors.Is(admissionErr, ErrOrganizationStorageQuotaExceeded):
			rejected++
		default:
			t.Fatalf("admission error=%v", admissionErr)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("accepted=%d rejected=%d", accepted, rejected)
	}
	var recorded int
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM segments WHERE organization_id=?`, scope.OrganizationID).Scan(&recorded); err != nil || recorded != 1 {
		t.Fatalf("recorded=%d err=%v", recorded, err)
	}

	recoveryScope := model.Scope{OrganizationID: "org-quota-recovery", ProjectID: "project", EnvironmentID: "production", ServiceID: "web"}
	if _, err = store.CreateSource(ctx, "source-recovery", recoveryScope); err != nil {
		t.Fatal(err)
	}
	recoveryBatch := model.Batch{Version: model.BatchVersion, SourceID: "source-recovery", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "sample"}}}
	recoverySegment, err := store.segments.Commit(recoveryScope, recoveryBatch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.SetOrganizationRetention(ctx, SetRetentionInput{OrganizationID: recoveryScope.OrganizationID, Policy: extended, Defaults: previewRetention, ActorUserID: "owner", ApproveExtensionFor: recoveryScope.OrganizationID, QuotaBytes: 1}, now); err != nil {
		t.Fatal(err)
	}
	if err = store.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(recoverySegment.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("over-quota recovery segment still exists: %v", err)
	}
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM segments WHERE organization_id=?`, recoveryScope.OrganizationID).Scan(&recorded); err != nil || recorded != 0 {
		t.Fatalf("recovered records=%d err=%v", recorded, err)
	}
}

func TestRecoverFinishesInterruptedRetention(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	scope := model.Scope{OrganizationID: "org-recover", ProjectID: "project", EnvironmentID: "production", ServiceID: "web"}
	token, err := store.CreateSource(ctx, "source-recover", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-recover", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "sample"}}}
	ack, err := store.Ingest(ctx, token, batch, now)
	if err != nil {
		t.Fatal(err)
	}
	var path string
	if _, err = store.control.Exec(`UPDATE segments SET retiring_at=? WHERE digest=?`, now.Format(time.RFC3339Nano), ack.Digest); err != nil {
		t.Fatal(err)
	}
	if err = store.control.QueryRow(`SELECT path FROM segments WHERE digest=?`, ack.Digest).Scan(&path); err != nil {
		t.Fatal(err)
	}
	if err = store.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retiring segment exists after recovery: %v", err)
	}
	var segments int
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM segments`).Scan(&segments); err != nil || segments != 0 {
		t.Fatalf("segments=%d err=%v", segments, err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverFinishesInterruptedColdArchivesBeforeProjectionRecovery(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	ctx := t.Context()
	scope := model.Scope{OrganizationID: "org-archive-recover", ProjectID: "project", EnvironmentID: "production", ServiceID: "web"}
	token, err := store.CreateSource(ctx, "source-archive", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for sequence, stream := range []string{"before-move", "after-move"} {
		batch := model.Batch{Version: model.BatchVersion, SourceID: "source-archive", StreamID: stream, Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "sample"}}}
		ack, ingestErr := store.Ingest(ctx, token, batch, now)
		if ingestErr != nil {
			t.Fatal(ingestErr)
		}
		var candidate archivingSegment
		candidate.digest, candidate.sourceID, candidate.streamID, candidate.signal = ack.Digest, batch.SourceID, batch.StreamID, batch.Signal
		if ingestErr = store.control.QueryRow(`SELECT path,compressed_bytes FROM segments WHERE digest=?`, ack.Digest).Scan(&candidate.path, &candidate.bytes); ingestErr != nil {
			t.Fatal(ingestErr)
		}
		candidate.archivePath, ingestErr = store.coldArchivePath(scope.OrganizationID, candidate)
		if ingestErr != nil {
			t.Fatal(ingestErr)
		}
		if _, ingestErr = store.control.Exec(`UPDATE segments SET archiving_at=?,archive_path=? WHERE digest=?`, now.Format(time.RFC3339Nano), candidate.archivePath, ack.Digest); ingestErr != nil {
			t.Fatal(ingestErr)
		}
		if sequence == 1 {
			if ingestErr = store.segments.MoveToCold(candidate.path, candidate.archivePath, candidate.digest); ingestErr != nil {
				t.Fatal(ingestErr)
			}
		}
	}
	if err = store.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := store.control.Query(`SELECT path,tier,archiving_at,archive_path FROM segments WHERE organization_id=? ORDER BY stream_id`, scope.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var path, tier string
		var archivingAt, archivePath sql.NullString
		if err = rows.Scan(&path, &tier, &archivingAt, &archivePath); err != nil {
			t.Fatal(err)
		}
		if tier != "cold" || archivingAt.Valid || archivePath.Valid || !strings.Contains(filepath.ToSlash(path), "/cold/") {
			t.Fatalf("path=%s tier=%s archiving=%+v archive_path=%+v", path, tier, archivingAt, archivePath)
		}
		if _, err = os.Stat(path); err != nil {
			t.Fatal(err)
		}
		count++
	}
	if err = rows.Err(); err != nil || count != 2 {
		t.Fatalf("archives=%d err=%v", count, err)
	}
}
