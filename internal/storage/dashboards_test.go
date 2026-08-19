// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSavedQueriesAreTypedVersionedAndOptimisticallyUpdated(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	input := SavedQueryInput{
		OrganizationID: "organization-a", Name: "Recent failures",
		Description: "Recent failed application requests grouped by route.",
		Query:       `logs | where status >= 500 | window 1h | summarize count() by route | sort count desc | limit 50`,
		Scope:       ResourceScope{ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"},
		ActorUserID: "operator-a", MaxRows: 1000,
	}
	created, err := store.SaveQuery(ctx, input, now)
	if err != nil {
		t.Fatal(err)
	}
	if created.Version != SavedQueryVersion || created.Revision != 1 || created.ID == "" || created.AST.Signal != "logs" || created.AST.Window != time.Hour || created.CreatedAt != now || created.UpdatedAt != now {
		t.Fatalf("created=%+v", created)
	}
	input.ID, input.ExpectedRevision = created.ID, created.Revision
	input.Description = "Reviewed application failures grouped by normalized route."
	updated, err := store.SaveQuery(ctx, input, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.Description != input.Description || updated.UpdatedBy != "operator-a" || !updated.UpdatedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("updated=%+v", updated)
	}
	if _, err = store.SaveQuery(ctx, input, now.Add(2*time.Minute)); err == nil {
		t.Fatal("stale saved-query revision was accepted")
	}
	queries, err := store.SavedQueries(ctx, "organization-a")
	if err != nil || len(queries) != 1 || queries[0].Revision != 2 {
		t.Fatalf("queries=%+v err=%v", queries, err)
	}
	if _, err = store.control.Exec(`UPDATE saved_queries SET ast_json='{}' WHERE organization_id='organization-a' AND id=?`, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SavedQuery(ctx, "organization-a", created.ID); err == nil {
		t.Fatal("query text and stored AST disagreement was accepted")
	}
}

func TestDashboardPanelsRemainOrganizationScopedAndExportSafeDefinitions(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	queryA, err := store.SaveQuery(ctx, SavedQueryInput{OrganizationID: "organization-a", Name: "Request rate", Description: "Five-minute request counts.", Query: `logs | window 1h | summarize count() by window(5m) | limit 50`, ActorUserID: "operator-a", MaxRows: 1000}, now)
	if err != nil {
		t.Fatal(err)
	}
	queryB, err := store.SaveQuery(ctx, SavedQueryInput{OrganizationID: "organization-b", Name: "Other organization", Description: "Must not cross the tenant boundary.", Query: `logs | limit 10`, ActorUserID: "operator-b", MaxRows: 1000}, now)
	if err != nil {
		t.Fatal(err)
	}
	input := DashboardInput{
		OrganizationID: "organization-a", Slug: "operations", Name: "Operations",
		Description: "Recent service activity and evidence.", ActorUserID: "operator-a",
		Panels: []DashboardPanel{{Position: 0, Title: "Request rate", Visualization: "timeseries", SavedQueryID: queryA.ID}},
	}
	created, err := store.SaveDashboard(ctx, input, now)
	if err != nil {
		t.Fatal(err)
	}
	if created.Version != DashboardVersion || created.Revision != 1 || len(created.Panels) != 1 || created.Panels[0].ID == "" {
		t.Fatalf("created=%+v", created)
	}
	unsafe := input
	unsafe.Slug = "cross-tenant"
	unsafe.Panels = []DashboardPanel{{Position: 0, Title: "Other", Visualization: "table", SavedQueryID: queryB.ID}}
	if _, err = store.SaveDashboard(ctx, unsafe, now); err == nil {
		t.Fatal("cross-organization saved query entered dashboard")
	}
	input.ID, input.ExpectedRevision = created.ID, created.Revision
	input.Name = "Service operations"
	input.Panels[0].ID = created.Panels[0].ID
	updated, err := store.SaveDashboard(ctx, input, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.Name != input.Name {
		t.Fatalf("updated=%+v", updated)
	}
	if _, err = store.SaveDashboard(ctx, input, now.Add(2*time.Minute)); !errors.Is(err, ErrDashboardRevisionConflict) {
		t.Fatalf("stale dashboard revision err=%v", err)
	}
	exported, err := store.ExportDashboard(ctx, "organization-a", "operations")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(exported)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"organization-a", "operator-a", "created_at", "updated_at", "ast"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("private runtime metadata %q entered export: %s", forbidden, body)
		}
	}
	if !strings.Contains(string(body), `"version":1`) || !strings.Contains(string(body), `"query":"logs | window 1h`) {
		t.Fatalf("export=%s", body)
	}
}

func TestDashboardValidationBoundsScopePanelsAndServerGeneratedIdentity(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	if _, err := store.SaveQuery(ctx, SavedQueryInput{OrganizationID: "organization-a", Name: "Invalid scope", Query: `logs | limit 10`, Scope: ResourceScope{ServiceID: "service-a"}, ActorUserID: "operator-a", MaxRows: 1000}, now); err == nil {
		t.Fatal("service-only query scope was accepted")
	}
	queryValue, err := store.SaveQuery(ctx, SavedQueryInput{OrganizationID: "organization-a", Name: "Valid", Query: `logs | limit 10`, ActorUserID: "operator-a", MaxRows: 1000}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.SaveDashboard(ctx, DashboardInput{ID: "caller-selected", OrganizationID: "organization-a", Slug: "invalid-id", Name: "Invalid", ActorUserID: "operator-a"}, now); err == nil {
		t.Fatal("caller-selected new dashboard identity was accepted")
	}
	duplicate := DashboardInput{OrganizationID: "organization-a", Slug: "duplicate-panels", Name: "Duplicate panels", ActorUserID: "operator-a", Panels: []DashboardPanel{
		{Position: 0, Title: "First", Visualization: "table", SavedQueryID: queryValue.ID},
		{Position: 0, Title: "Second", Visualization: "stat", SavedQueryID: queryValue.ID},
	}}
	if _, err = store.SaveDashboard(ctx, duplicate, now); err == nil {
		t.Fatal("duplicate dashboard panel positions were accepted")
	}
}

func TestDashboardImportIsAtomicTenantIndependentAndRevalidated(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 11, 0, 0, 0, time.UTC)
	bundle := DashboardExport{
		Version: DashboardVersion,
		Dashboard: DashboardDefinition{Slug: "operations", Name: "Operations", Description: "A portable service view.", Panels: []DashboardPanel{
			{ID: "old-panel-1", Position: 0, Title: "Recent failures", Visualization: "table", SavedQueryID: "portable-query-1"},
		}},
		SavedQueries: []SavedQueryDefinition{{ID: "portable-query-1", Name: "Recent failures", Description: "Bounded failures.", Query: `logs | where status >= 500 | window 1h | limit 50`}},
	}
	imported, err := store.ImportDashboard(ctx, DashboardImportInput{OrganizationID: "organization-b", ActorUserID: "operator-b", MaxRows: 1_000, Bundle: bundle}, now)
	if err != nil {
		t.Fatal(err)
	}
	if imported.OrganizationID != "organization-b" || imported.CreatedBy != "operator-b" || imported.ID == "" || len(imported.Panels) != 1 || imported.Panels[0].ID == "old-panel-1" || imported.Panels[0].SavedQueryID == "portable-query-1" {
		t.Fatalf("imported=%+v", imported)
	}
	queries, err := store.SavedQueries(ctx, "organization-b")
	if err != nil || len(queries) != 1 || queries[0].OrganizationID != "organization-b" || queries[0].CreatedBy != "operator-b" || queries[0].ID != imported.Panels[0].SavedQueryID {
		t.Fatalf("queries=%+v err=%v", queries, err)
	}
	invalid := bundle
	invalid.Dashboard.Slug = "partial-import"
	invalid.SavedQueries = append(invalid.SavedQueries, SavedQueryDefinition{ID: "unused-query-2", Name: "Unused", Query: `logs | limit 10`})
	if _, err = store.ImportDashboard(ctx, DashboardImportInput{OrganizationID: "organization-b", ActorUserID: "operator-b", MaxRows: 1_000, Bundle: invalid}, now); err == nil {
		t.Fatal("unreferenced imported query was accepted")
	}
	if dashboards, listErr := store.Dashboards(ctx, "organization-b"); listErr != nil || len(dashboards) != 1 {
		t.Fatalf("failed import left partial dashboard: dashboards=%+v err=%v", dashboards, listErr)
	}
	if queries, listErr := store.SavedQueries(ctx, "organization-b"); listErr != nil || len(queries) != 1 {
		t.Fatalf("failed import left partial queries: queries=%+v err=%v", queries, listErr)
	}
	incompatible := bundle
	incompatible.Dashboard.Slug = "invalid-presentation"
	incompatible.Dashboard.Panels[0].Visualization = "timeseries"
	if _, err = store.ImportDashboard(ctx, DashboardImportInput{OrganizationID: "organization-b", ActorUserID: "operator-b", MaxRows: 1_000, Bundle: incompatible}, now); err == nil {
		t.Fatal("timeseries dashboard without a bucketed summary was accepted")
	}
}
