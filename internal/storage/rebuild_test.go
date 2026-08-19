// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
)

func TestProjectionRebuildRestoresRawTruthAndActivatedDescriptorsAtomically(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "metrics", Sequence: 1, ObservedAt: now, Signal: model.SignalMetrics, Records: []model.Observation{
		{Timestamp: now.Add(-time.Minute), Name: "queue.depth", Value: floatPointer(1), Attributes: map[string]string{"workshop.queue_depth": "1"}},
		{Timestamp: now, Name: "queue.depth", Value: floatPointer(2), Attributes: map[string]string{"workshop.queue_depth": "2"}},
	}}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	logBatch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{
		requestObservation(now.Add(-time.Minute), "/broken", 503, 10),
		requestObservation(now, "/healthy", 200, 5),
	}}
	if _, err = store.Ingest(ctx, token, logBatch, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	reviewed := schema.Descriptor{Version: schema.DescriptorVersion, Signal: model.SignalMetrics, Field: "workshop.queue_depth", Type: schema.TypeInteger, Meaning: "Number of work items waiting in the selected service queue.", Sensitivity: schema.SensitivityInternal, Cardinality: schema.CardinalityLow, Index: schema.IndexRange, Retention: schema.RetentionRaw, ProjectionVersion: 1}
	if _, err = store.ActivateDescriptor(ctx, scope.OrganizationID, reviewed, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ast, err := query.Parse(`metrics | where workshop.queue_depth >= 1 | sort workshop.queue_depth desc | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Query(ctx, ast, query.Scope{OrganizationID: scope.OrganizationID}, testQueryBudget(), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	logAST, err := query.Parse(`logs | where status >= 500 | window 1h | summarize count() by route, window(5m) | limit 10`, 100)
	if err != nil {
		t.Fatal(err)
	}
	logBefore, err := store.Query(ctx, logAST, query.Scope{OrganizationID: scope.OrganizationID}, testQueryBudget(), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	otherScope := model.Scope{OrganizationID: "organization-b", ProjectID: "project-b", EnvironmentID: "production", ServiceID: "service-b"}
	otherToken, err := store.CreateSource(ctx, "source-b", otherScope)
	if err != nil {
		t.Fatal(err)
	}
	otherBatch := model.Batch{Version: model.BatchVersion, SourceID: "source-b", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "other.request"}}}
	if _, err = store.Ingest(ctx, otherToken, otherBatch, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	otherPath := filepath.Join(store.root, "organizations", otherScope.OrganizationID, "projection.sqlite")
	otherBefore, otherInfo := readFileAndInfo(t, otherPath)

	live := filepath.Join(store.root, "organizations", scope.OrganizationID, "projection.sqlite")
	if err = os.WriteFile(live, []byte("corrupt disposable projection"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := store.RebuildOrganization(ctx, scope.OrganizationID, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if report.Segments != 2 || report.Observations != 4 || report.ActiveVersion != 2 || report.IndexedRows != 2 {
		t.Fatalf("report=%+v", report)
	}
	after, err := store.Query(ctx, ast, query.Scope{OrganizationID: scope.OrganizationID}, testQueryBudget(), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.Columns, after.Columns) || !reflect.DeepEqual(before.Rows, after.Rows) || before.Stats.ScannedRows != after.Stats.ScannedRows || before.Stats.MatchedRows != after.Stats.MatchedRows {
		t.Fatalf("before=%+v after=%+v", before, after)
	}
	logAfter, err := store.Query(ctx, logAST, query.Scope{OrganizationID: scope.OrganizationID}, testQueryBudget(), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(logBefore.Columns, logAfter.Columns) || !reflect.DeepEqual(logBefore.Rows, logAfter.Rows) || logBefore.Stats.ScannedRows != logAfter.Stats.ScannedRows || logBefore.Stats.MatchedRows != logAfter.Stats.MatchedRows {
		t.Fatalf("log before=%+v after=%+v", logBefore, logAfter)
	}
	otherAfter, otherAfterInfo := readFileAndInfo(t, otherPath)
	if !bytes.Equal(otherBefore, otherAfter) || !otherInfo.ModTime().Equal(otherAfterInfo.ModTime()) {
		t.Fatal("rebuilding one organization modified another organization projection")
	}
	if _, err = os.Lstat(live + "-wal"); !os.IsNotExist(err) {
		t.Fatalf("rebuilt projection retained WAL: %v", err)
	}
	store.projectionMu.Lock()
	_, cached := store.projections[scope.OrganizationID]
	store.projectionMu.Unlock()
	if cached {
		t.Fatal("rebuilt projection retained its replaced database handle")
	}
	batch.Sequence = 2
	batch.ObservedAt = now.Add(time.Minute)
	batch.Records = []model.Observation{{Timestamp: now.Add(time.Minute), Name: "queue.depth", Value: floatPointer(3), Attributes: map[string]string{"workshop.queue_depth": "3"}}}
	if _, err = store.Ingest(ctx, token, batch, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	store.projectionMu.Lock()
	refreshed := store.projections[scope.OrganizationID]
	store.projectionMu.Unlock()
	if refreshed.db == nil {
		t.Fatal("rebuilt projection did not receive a fresh database handle")
	}
}

func TestProjectionRebuildFailurePreservesLiveProjection(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 12, 30, 0, 0, time.UTC)
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "application.request"}}}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	live := filepath.Join(store.root, "organizations", scope.OrganizationID, "projection.sqlite")
	liveBefore, liveInfo := readFileAndInfo(t, live)
	var rawPath string
	if err = store.control.QueryRow(`SELECT path FROM segments WHERE organization_id=?`, scope.OrganizationID).Scan(&rawPath); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(rawPath, []byte("corrupt raw truth"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RebuildOrganization(ctx, scope.OrganizationID, now.Add(time.Minute)); err == nil {
		t.Fatal("corrupt raw segment was accepted")
	}
	liveAfter, liveAfterInfo := readFileAndInfo(t, live)
	if !bytes.Equal(liveBefore, liveAfter) || !liveInfo.ModTime().Equal(liveAfterInfo.ModTime()) {
		t.Fatal("failed rebuild modified the live projection")
	}
	stages, err := filepath.Glob(filepath.Join(filepath.Dir(live), ".projection-rebuild-*"))
	if err != nil || len(stages) != 0 {
		t.Fatalf("stages=%v err=%v", stages, err)
	}
}

func TestProjectionRebuildRejectsUnknownOrganization(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	if _, err := store.RebuildOrganization(context.Background(), "unknown-organization", time.Now().UTC()); err == nil {
		t.Fatal("unknown organization projection was created")
	}
	path := filepath.Join(store.root, "organizations", "unknown-organization", "projection.sqlite")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("unknown organization projection exists: %v", err)
	}
}

func TestProjectionRebuildRefusesSymlinkProjectionOrSidecar(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	ctx := context.Background()
	now := time.Date(2026, 8, 17, 13, 0, 0, 0, time.UTC)
	dir := filepath.Join(store.root, "organizations", "organization-a")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, "projection.sqlite")
	if err := os.WriteFile(live, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.sqlite")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, live+"-wal"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RebuildOrganization(ctx, "organization-a", now); err == nil {
		t.Fatal("symlink projection sidecar was accepted")
	}
	if err := os.Remove(live + "-wal"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(live); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, live); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RebuildOrganization(ctx, "organization-a", now); err == nil {
		t.Fatal("symlink projection was accepted")
	}
}

func readFileAndInfo(t *testing.T, path string) ([]byte, os.FileInfo) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return body, info
}
