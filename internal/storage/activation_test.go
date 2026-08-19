// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
)

func TestIndexedTimeValuesUseFixedChronologicalUTCText(t *testing.T) {
	earlier, _, ok := indexValue("2026-08-17T09:00:00Z", schema.TypeTime)
	if !ok {
		t.Fatal("earlier time rejected")
	}
	later, _, ok := indexValue("2026-08-17T09:00:00.1Z", schema.TypeTime)
	if !ok {
		t.Fatal("later time rejected")
	}
	if len(earlier) != len(later) || strings.Compare(earlier, later) >= 0 || earlier != "2026-08-17T09:00:00.000000000Z" {
		t.Fatalf("earlier=%q later=%q", earlier, later)
	}
}

func TestDescriptorActivationAndIngestionSerializeAcrossStoreInstances(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	second, err := Open(store.root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	now := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	first := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "metrics", Sequence: 1, ObservedAt: now, Signal: model.SignalMetrics, Records: []model.Observation{{Timestamp: now, Name: "queue.depth", Value: floatPointer(1), Attributes: map[string]string{"workshop.queue_depth": "1"}}}}
	if _, err = store.Ingest(ctx, token, first, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	reviewed := schema.Descriptor{Version: schema.DescriptorVersion, Signal: model.SignalMetrics, Field: "workshop.queue_depth", Type: schema.TypeInteger, Meaning: "Number of work items waiting in the selected service queue.", Sensitivity: schema.SensitivityInternal, Cardinality: schema.CardinalityLow, Index: schema.IndexRange, Retention: schema.RetentionRaw, ProjectionVersion: 1}
	secondBatch := first
	secondBatch.Sequence = 2
	secondBatch.ObservedAt = now.Add(time.Second)
	secondBatch.Records = []model.Observation{{Timestamp: secondBatch.ObservedAt, Name: "queue.depth", Value: floatPointer(2), Attributes: map[string]string{"workshop.queue_depth": "2"}}}
	start := make(chan struct{})
	errorsFound := make(chan error, 2)
	go func() {
		<-start
		_, activateErr := store.ActivateDescriptor(ctx, "organization-a", reviewed, now.Add(2*time.Second))
		errorsFound <- activateErr
	}()
	go func() {
		<-start
		_, ingestErr := second.Ingest(ctx, token, secondBatch, now.Add(2*time.Second))
		errorsFound <- ingestErr
	}()
	close(start)
	for range 2 {
		if runErr := <-errorsFound; runErr != nil {
			t.Fatal(runErr)
		}
	}
	projectAll(t, store)
	path := filepath.Join(store.root, "organizations", "organization-a", "projection.sqlite")
	db := openTestProjection(t, path)
	defer db.Close()
	var indexed int
	if err = db.QueryRow(`SELECT COUNT(*) FROM indexed_fields_v000002`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != 2 {
		t.Fatalf("indexed=%d", indexed)
	}
}

func TestDescriptorActivationBuildsBesideCurrentAndFeedsQueriesAndIngestion(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "metrics", Sequence: 1, ObservedAt: now, Signal: model.SignalMetrics, Records: []model.Observation{
		{Timestamp: now, Name: "queue.depth", Value: floatPointer(10), Attributes: map[string]string{"workshop.queue_depth": "10", "workshop.mode": "fast"}},
		{Timestamp: now.Add(time.Second), Name: "queue.depth", Value: floatPointer(11), Attributes: map[string]string{"workshop.queue_depth": "not-an-integer", "workshop.mode": "slow"}},
	}}
	if _, err = store.Ingest(ctx, token, batch, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	ast, err := query.Parse(`metrics | where workshop.queue_depth >= 9 | limit 50`, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a"}, testQueryBudget(), now.Add(time.Minute)); !errors.Is(err, query.ErrSensitivePermissionRequired) {
		t.Fatalf("unreviewed query err=%v", err)
	}
	reviewed := schema.Descriptor{
		Version: schema.DescriptorVersion, Signal: model.SignalMetrics, Field: "workshop.queue_depth",
		Type: schema.TypeInteger, Meaning: "Number of work items waiting in the selected service queue.",
		Sensitivity: schema.SensitivityInternal, Cardinality: schema.CardinalityLow,
		Index: schema.IndexRange, Retention: schema.RetentionRaw, ProjectionVersion: 1,
	}
	activation, err := store.ActivateDescriptor(ctx, "organization-a", reviewed, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if activation.Previous != 1 || activation.Active != 2 || activation.IndexedRows != 1 || activation.Descriptor.ProjectionVersion != 2 {
		t.Fatalf("activation=%+v", activation)
	}
	registry, version, err := store.ActiveDescriptors(ctx, "organization-a")
	if err != nil || version != 2 {
		t.Fatalf("version=%d registry=%+v err=%v", version, registry, err)
	}
	descriptor, ok := registry.Lookup(model.SignalMetrics, "workshop.queue_depth")
	if !ok || descriptor.ProjectionVersion != 2 || descriptor.Sensitivity != schema.SensitivityInternal || descriptor.Index != schema.IndexRange {
		t.Fatalf("descriptor=%+v ok=%t", descriptor, ok)
	}
	result, err := store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a"}, testQueryBudget(), now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || len(result.Explain.Fields) != 1 || !result.Explain.Fields[0].Indexed || result.Explain.Fields[0].Unknown {
		t.Fatalf("result=%+v", result)
	}

	batch.Sequence = 2
	batch.ObservedAt = now.Add(4 * time.Minute)
	batch.Records = []model.Observation{{Timestamp: batch.ObservedAt, Name: "queue.depth", Value: floatPointer(12), Attributes: map[string]string{"workshop.queue_depth": "12", "workshop.mode": "fast"}}}
	if _, err = store.Ingest(ctx, token, batch, batch.ObservedAt); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	result, err = store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a"}, testQueryBudget(), now.Add(5*time.Minute))
	if err != nil || len(result.Rows) != 2 {
		t.Fatalf("rows=%d err=%v", len(result.Rows), err)
	}

	path := filepath.Join(store.root, "organizations", "organization-a", "projection.sqlite")
	db := openTestProjection(t, path)
	defer db.Close()
	var active, indexed int
	if err = db.QueryRow(`SELECT active_version FROM projection_state WHERE id=1`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM indexed_fields_v000002`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if active != 2 || indexed != 2 {
		t.Fatalf("active=%d indexed=%d", active, indexed)
	}
	statement, arguments, err := projectionSelection(ast, query.Scope{OrganizationID: "organization-a"}, registry, version, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	planRows, err := db.Query(`EXPLAIN QUERY PLAN `+statement, arguments...)
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for planRows.Next() {
		var id, parent, unused int
		var detail string
		if err = planRows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail)
		plan.WriteByte('\n')
	}
	if err = planRows.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "indexed_fields_v000002_number") {
		t.Fatalf("custom range index absent from query plan:\n%s", plan.String())
	}

	preActivationDescriptor, err := json.Marshal(reviewed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.control.Exec(`UPDATE descriptor_proposals SET descriptor_json=?,status='pending' WHERE organization_id='organization-a' AND signal='metrics' AND field='workshop.queue_depth'`, string(preActivationDescriptor)); err != nil {
		t.Fatal(err)
	}
	retry, err := store.ActivateDescriptor(ctx, "organization-a", reviewed, now.Add(6*time.Minute))
	if err != nil || retry.Active != 2 || retry.Previous != 2 || retry.IndexedRows != 0 {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	mode := schema.Descriptor{
		Version: schema.DescriptorVersion, Signal: model.SignalMetrics, Field: "workshop.mode",
		Type: schema.TypeString, Meaning: "Reviewed operating mode label for the workshop queue.",
		Sensitivity: schema.SensitivityInternal, Cardinality: schema.CardinalityLow,
		Index: schema.IndexExact, Retention: schema.RetentionRaw, ProjectionVersion: 1,
	}
	second, err := store.ActivateDescriptor(ctx, "organization-a", mode, now.Add(7*time.Minute))
	if err != nil || second.Previous != 2 || second.Active != 3 || second.IndexedRows != 5 {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	var retained, current int
	if err = db.QueryRow(`SELECT COUNT(*) FROM indexed_fields_v000002`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM indexed_fields_v000003`).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if retained != 2 || current != 5 {
		t.Fatalf("retained=%d current=%d", retained, current)
	}
	result, err = store.Query(ctx, ast, query.Scope{OrganizationID: "organization-a"}, testQueryBudget(), now.Add(8*time.Minute))
	if err != nil || len(result.Rows) != 2 {
		t.Fatalf("version-three rows=%d err=%v", len(result.Rows), err)
	}
	proposals, err := store.DescriptorProposals(ctx, "organization-a")
	if err != nil || len(proposals) != 2 || proposals[0].Status != "activated" || proposals[1].Status != "activated" {
		t.Fatalf("proposals=%+v err=%v", proposals, err)
	}
}

func TestDescriptorActivationFailureKeepsPriorVersion(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request", Attributes: map[string]string{"workshop.label": "ready"}}}}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	path := filepath.Join(store.root, "organizations", "organization-a", "projection.sqlite")
	db := openTestProjection(t, path)
	if _, err = db.Exec(`DROP TABLE observations`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	reviewed := schema.Descriptor{Version: schema.DescriptorVersion, Signal: model.SignalLogs, Field: "workshop.label", Type: schema.TypeString, Meaning: "Reviewed workshop state label.", Sensitivity: schema.SensitivityInternal, Cardinality: schema.CardinalityLow, Index: schema.IndexExact, Retention: schema.RetentionRaw, ProjectionVersion: 1}
	if _, err = store.ActivateDescriptor(ctx, "organization-a", reviewed, now.Add(time.Minute)); err == nil {
		t.Fatal("activation unexpectedly succeeded without the source projection")
	}
	db = openTestProjection(t, path)
	defer db.Close()
	var active, versions int
	if err = db.QueryRow(`SELECT active_version FROM projection_state WHERE id=1`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM projection_versions`).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if active != 1 || versions != 1 {
		t.Fatalf("active=%d versions=%d", active, versions)
	}
	proposal, err := store.descriptorProposal(ctx, "organization-a", model.SignalLogs, "workshop.label")
	if err != nil || proposal.Status != "pending" {
		t.Fatalf("proposal=%+v err=%v", proposal, err)
	}
}

func TestDescriptorProposalRejectionIsIdempotentAndBlocksActivation(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request", Attributes: map[string]string{"workshop.label": "ready"}}}}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	if err = store.RejectDescriptorProposal(ctx, "organization-a", model.SignalLogs, "workshop.label"); err != nil {
		t.Fatal(err)
	}
	if err = store.RejectDescriptorProposal(ctx, "organization-a", model.SignalLogs, "workshop.label"); err != nil {
		t.Fatal(err)
	}
	reviewed := schema.Descriptor{Version: schema.DescriptorVersion, Signal: model.SignalLogs, Field: "workshop.label", Type: schema.TypeString, Meaning: "Reviewed workshop state label.", Sensitivity: schema.SensitivityInternal, Cardinality: schema.CardinalityLow, Index: schema.IndexExact, Retention: schema.RetentionRaw, ProjectionVersion: 1}
	if _, err = store.ActivateDescriptor(ctx, "organization-a", reviewed, now.Add(time.Minute)); err == nil {
		t.Fatal("rejected proposal was activated")
	}
}

func openTestProjection(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}
