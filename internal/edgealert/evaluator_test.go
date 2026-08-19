// SPDX-License-Identifier: AGPL-3.0-only

package edgealert

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gamertan.com/observatory/internal/config"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/storage"
)

func TestEvaluateMatchesBoundedBatchWithoutIO(t *testing.T) {
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	ast, err := query.Parse("logs | where status >= 500 | limit 10", model.MaxRecords)
	if err != nil {
		t.Fatal(err)
	}
	rule := config.AgentAlertRule{Version: 1, ID: "rule-a", Revision: 1, StreamID: "requests", Query: "logs | where status >= 500 | limit 10", MinimumMatches: 2, AST: ast}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 4, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{
		{Timestamp: now.Add(-time.Second), Name: "request", Attributes: map[string]string{"http.status_code": "503"}},
		{Timestamp: now, Name: "request", Attributes: map[string]string{"http.status_code": "502"}},
	}}
	evaluation, err := Evaluate(rule, batch)
	if err != nil || evaluation.State != "matched" || evaluation.Matches != 2 || !evaluation.WindowStart.Equal(now.Add(-time.Second)) || !evaluation.WindowEnd.Equal(now) || !evaluation.ObservedAt.Equal(now) {
		t.Fatalf("evaluation=%+v err=%v", evaluation, err)
	}
	batch.Records[1].Attributes["http.status_code"] = "200"
	evaluation, err = Evaluate(rule, batch)
	if err != nil || evaluation.State != "clear" || evaluation.Matches != 1 {
		t.Fatalf("evaluation=%+v err=%v", evaluation, err)
	}
}

func TestEdgeEvaluationMatchesCentralOracleForExactBatch(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 19, 0, 5, 0, 0, time.UTC)
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	queryText := "logs | where status >= 500 | limit 10"
	ast, err := query.Parse(queryText, model.MaxRecords)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := store.SaveQuery(ctx, storage.SavedQueryInput{OrganizationID: scope.OrganizationID, ActorUserID: "operator-a", MaxRows: 100, Name: "Failures", Query: queryText, Scope: storage.ResourceScope{ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID, ServiceID: scope.ServiceID}}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.SaveAlertRule(ctx, storage.AlertRuleInput{OrganizationID: scope.OrganizationID, ActorUserID: "operator-a", SavedQueryID: saved.ID, Name: "Failures", Severity: "warning", MinimumMatches: 1, RequiredConsecutive: 1, EvaluationInterval: 15 * time.Second, Enabled: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request", Attributes: map[string]string{"http.status_code": "503"}}, {Timestamp: now, Name: "request", Attributes: map[string]string{"http.status_code": "200"}}}}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	for {
		report, projectErr := store.ProjectPending(ctx)
		if projectErr != nil {
			t.Fatal(projectErr)
		}
		if report.ProjectedSegments == 0 {
			break
		}
	}
	edge, err := Evaluate(config.AgentAlertRule{Version: 1, ID: "rule-a", Revision: 1, StreamID: "requests", Query: queryText, MinimumMatches: 1, AST: ast}, batch)
	if err != nil {
		t.Fatal(err)
	}
	central, err := store.EvaluateDueAlertRules(ctx, query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 16 << 20, MaxMemoryBytes: 8 << 20}, now)
	if err != nil || len(central) != 1 || (edge.State == "matched") != central[0].Matched || edge.Matches != central[0].Rows {
		t.Fatalf("edge=%+v central=%+v err=%v", edge, central, err)
	}
}

func TestEvaluateReturnsBoundedErrorStateForTypedMismatch(t *testing.T) {
	now := time.Now().UTC()
	ast, err := query.Parse("logs | where status >= nope | limit 10", model.MaxRecords)
	if err != nil {
		t.Fatal(err)
	}
	rule := config.AgentAlertRule{Version: 1, ID: "rule-a", Revision: 1, StreamID: "requests", Query: "logs | where status >= nope | limit 10", MinimumMatches: 1, AST: ast}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request", Attributes: map[string]string{"http.status_code": "503"}}}}
	evaluation, err := Evaluate(rule, batch)
	if err != nil || evaluation.State != "error" || evaluation.Matches != 0 {
		t.Fatalf("evaluation=%+v err=%v", evaluation, err)
	}
}
