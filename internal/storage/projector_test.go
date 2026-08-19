// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"os"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

func TestDurableAcknowledgementPrecedesProjection(t *testing.T) {
	ctx := t.Context()
	store := testStore(t)
	defer store.Close()
	now := time.Now().UTC()
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "application.request"}}}
	ack, err := store.Ingest(ctx, token, batch, now)
	if err != nil || ack.Duplicate {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}
	duplicate, err := store.Ingest(ctx, token, batch, now)
	if err != nil || !duplicate.Duplicate || duplicate.Digest != ack.Digest {
		t.Fatalf("duplicate=%+v err=%v", duplicate, err)
	}
	status, err := store.ProjectionStatus(ctx, now.Add(time.Second))
	if err != nil || status.PendingSegments != 1 || status.PendingBytes < 1 || status.OldestPendingLag < time.Second {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	var projected int
	if err = store.control.QueryRowContext(ctx, `SELECT COUNT(projected_at) FROM segments`).Scan(&projected); err != nil || projected != 0 {
		t.Fatalf("projected=%d err=%v", projected, err)
	}
	report, err := store.ProjectPending(ctx)
	if err != nil || report.ProjectedSegments != 1 || report.ProjectedRecords != 1 || report.ProjectedBytes < 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	status, err = store.ProjectionStatus(ctx, now.Add(2*time.Second))
	if err != nil || status.PendingSegments != 0 || status.PendingBytes != 0 || !status.OldestCommitted.IsZero() || status.OldestPendingLag != 0 {
		t.Fatalf("projected status=%+v err=%v", status, err)
	}
}

func TestProjectorGroupsBoundedSegmentsAndResumesAfterReopen(t *testing.T) {
	ctx := t.Context()
	store := testStore(t)
	root := store.root
	now := time.Now().UTC()
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	const total = projectionGroupMaxSegments + 3
	for sequence := uint64(1); sequence <= total; sequence++ {
		batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "logs", Sequence: sequence, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "application.request"}}}
		if _, err = store.Ingest(ctx, token, batch, now); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.ProjectPending(ctx)
	if err != nil || first.ProjectedSegments != projectionGroupMaxSegments {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.RecoverRaw(ctx); err != nil {
		t.Fatal(err)
	}
	status, err := store.ProjectionStatus(ctx, now.Add(time.Second))
	if err != nil || status.PendingSegments != total-projectionGroupMaxSegments {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	second, err := store.ProjectPending(ctx)
	if err != nil || second.ProjectedSegments != total-projectionGroupMaxSegments {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	ast, err := query.Parse(`logs | limit 100`, 100)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Query(ctx, ast, query.Scope{OrganizationID: scope.OrganizationID}, testQueryBudget(), now)
	if err != nil || len(result.Rows) != total {
		t.Fatalf("rows=%d err=%v", len(result.Rows), err)
	}
}

func TestProjectorFailureIsolatedFromAcknowledgementAndOtherOrganization(t *testing.T) {
	ctx := t.Context()
	store := testStore(t)
	defer store.Close()
	now := time.Now().UTC()
	for index, organizationID := range []string{"organization-a", "organization-b"} {
		sourceID := "source-" + string(rune('a'+index))
		scope := model.Scope{OrganizationID: organizationID, ProjectID: "project", EnvironmentID: "production", ServiceID: "service"}
		token, err := store.CreateSource(ctx, sourceID, scope)
		if err != nil {
			t.Fatal(err)
		}
		batch := model.Batch{Version: model.BatchVersion, SourceID: sourceID, StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "application.request"}}}
		if _, err = store.Ingest(ctx, token, batch, now); err != nil {
			t.Fatal(err)
		}
	}
	var corruptPath string
	if err := store.control.QueryRowContext(ctx, `SELECT path FROM segments WHERE organization_id='organization-a'`).Scan(&corruptPath); err != nil {
		t.Fatal(err)
	}
	corruptBody, err := os.ReadFile(corruptPath)
	if err != nil {
		t.Fatal(err)
	}
	corruptBody[0] ^= 0xff
	if err := os.WriteFile(corruptPath, corruptBody, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := store.ProjectPending(ctx)
	if err == nil || report.ProjectedSegments != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	var projectedA, projectedB int
	if err = store.control.QueryRowContext(ctx, `SELECT COUNT(projected_at) FROM segments WHERE organization_id='organization-a'`).Scan(&projectedA); err != nil {
		t.Fatal(err)
	}
	if err = store.control.QueryRowContext(ctx, `SELECT COUNT(projected_at) FROM segments WHERE organization_id='organization-b'`).Scan(&projectedB); err != nil {
		t.Fatal(err)
	}
	if projectedA != 0 || projectedB != 1 {
		t.Fatalf("projected organization-a=%d organization-b=%d", projectedA, projectedB)
	}
	if err = store.RecoverRaw(ctx); err != nil {
		t.Fatalf("raw reconciliation decoded catalogued pending evidence: %v", err)
	}
}

func TestRunProjectorWakesOnAcceptedBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	store := testStore(t)
	defer store.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.RunProjector(ctx, time.Minute, func(err error) { t.Errorf("projector: %v", err) })
	}()
	now := time.Now().UTC()
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "application.request"}}}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, statusErr := store.ProjectionStatus(t.Context(), time.Now().UTC())
		if statusErr != nil {
			t.Fatal(statusErr)
		}
		if status.PendingSegments == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("projection remained pending: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("projector did not stop after cancellation")
	}
}
