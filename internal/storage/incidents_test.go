// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"sync"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

func TestAlertRuleEvaluationAndIncidentLifecycle(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	organizationID := "organization-a"
	actor := "operator-a"
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	saved, err := store.SaveQuery(ctx, SavedQueryInput{
		OrganizationID: organizationID, ActorUserID: actor, MaxRows: 100,
		Name: "Recent failures", Description: "Recent HTTP failures for an alert.",
		Query: "logs | where status >= 500 | window 1h | limit 50",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := store.SaveAlertRule(ctx, AlertRuleInput{
		OrganizationID: organizationID, ActorUserID: actor, SavedQueryID: saved.ID,
		Name: "HTTP failures", Description: "Open after two consecutive matching evaluations.",
		Severity: "critical", MinimumMatches: 1, RequiredConsecutive: 2,
		EvaluationInterval: 15 * time.Second, Enabled: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	budget := query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 16 << 20, MaxMemoryBytes: 8 << 20}

	empty, err := store.EvaluateDueAlertRules(ctx, budget, now)
	if err != nil || len(empty) != 1 || empty[0].Matched || empty[0].Rows != 0 || empty[0].IncidentID != "" {
		t.Fatalf("empty evaluation=%+v err=%v", empty, err)
	}
	if incidents, listErr := store.Incidents(ctx, organizationID, false, 100); listErr != nil || len(incidents) != 0 {
		t.Fatalf("empty incidents=%+v err=%v", incidents, listErr)
	}

	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: organizationID, ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	observed := now.Add(10 * time.Second)
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: observed, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: observed, Name: "http.request", Attributes: map[string]string{"http.status_code": "503", "http.route": "/failed"}}}}
	if _, err = store.Ingest(ctx, token, batch, observed); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)

	first, err := store.EvaluateDueAlertRules(ctx, budget, now.Add(15*time.Second))
	if err != nil || len(first) != 1 || !first[0].Matched || first[0].IncidentState != "pending" {
		t.Fatalf("first evaluation=%+v err=%v", first, err)
	}
	second, err := store.EvaluateDueAlertRules(ctx, budget, now.Add(30*time.Second))
	if err != nil || len(second) != 1 || second[0].IncidentID != first[0].IncidentID || second[0].IncidentState != "firing" {
		t.Fatalf("second evaluation=%+v err=%v", second, err)
	}
	incidentID := second[0].IncidentID
	third, err := store.EvaluateDueAlertRules(ctx, budget, now.Add(45*time.Second))
	if err != nil || len(third) != 1 || third[0].IncidentChanged || third[0].IncidentState != "firing" {
		t.Fatalf("steady evaluation=%+v err=%v", third, err)
	}
	steadyEvents, err := store.IncidentEvents(ctx, organizationID, incidentID)
	if err != nil || len(steadyEvents) != 2 {
		t.Fatalf("steady events=%+v err=%v", steadyEvents, err)
	}

	acknowledged, err := store.TransitionIncident(ctx, organizationID, incidentID, "acknowledge", actor, nil, now.Add(46*time.Second))
	if err != nil || acknowledged.State != "acknowledged" || acknowledged.AcknowledgedBy != actor {
		t.Fatalf("acknowledged=%+v err=%v", acknowledged, err)
	}
	silenceUntil := now.Add(time.Hour)
	silenced, err := store.TransitionIncident(ctx, organizationID, incidentID, "silence", actor, &silenceUntil, now.Add(47*time.Second))
	if err != nil || silenced.State != "silenced" || silenced.SilencedUntil == nil || !silenced.SilencedUntil.Equal(silenceUntil) {
		t.Fatalf("silenced=%+v err=%v", silenced, err)
	}
	resolved, err := store.TransitionIncident(ctx, organizationID, incidentID, "resolve", actor, nil, now.Add(48*time.Second))
	if err != nil || resolved.State != "resolved" || resolved.ResolvedAt == nil {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	if _, err = store.TransitionIncident(ctx, organizationID, incidentID, "acknowledge", actor, nil, now.Add(49*time.Second)); err == nil {
		t.Fatal("resolved incident accepted another transition")
	}

	events, err := store.IncidentEvents(ctx, organizationID, incidentID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"opened", "promoted", "acknowledged", "silenced", "resolved"}
	if len(events) != len(want) {
		t.Fatalf("events=%+v", events)
	}
	for index, event := range events {
		if event.Sequence != index+1 || event.Event != want[index] {
			t.Fatalf("events=%+v", events)
		}
	}
	all, err := store.Incidents(ctx, organizationID, true, 100)
	if err != nil || len(all) != 1 || all[0].State != "resolved" {
		t.Fatalf("all incidents=%+v err=%v", all, err)
	}
	loadedRule, err := store.AlertRule(ctx, organizationID, rule.ID)
	if err != nil || loadedRule.LastEvaluatedAt == nil || loadedRule.LastResult == nil || *loadedRule.LastResult != 1 || loadedRule.LastError != "" {
		t.Fatalf("rule=%+v err=%v", loadedRule, err)
	}
}

func TestAlertQueryFailureDoesNotOpenOrResolveAnIncident(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 14, 0, 0, 0, time.UTC)
	saved, err := store.SaveQuery(ctx, SavedQueryInput{OrganizationID: "organization-a", ActorUserID: "operator-a", MaxRows: 100, Name: "Unknown field", Description: "Requires reviewed sensitive-field access.", Query: "logs | where private.value == secret | limit 10"}, now)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := store.SaveAlertRule(ctx, AlertRuleInput{OrganizationID: "organization-a", ActorUserID: "operator-a", SavedQueryID: saved.ID, Name: "Fail closed", Description: "A query failure is not a healthy result.", Severity: "critical", MinimumMatches: 1, RequiredConsecutive: 1, EvaluationInterval: 15 * time.Second, Enabled: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	budget := query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 16 << 20, MaxMemoryBytes: 8 << 20}
	evaluations, err := store.EvaluateDueAlertRules(ctx, budget, now)
	if err != nil || len(evaluations) != 1 || evaluations[0].Error != "query_unavailable" || evaluations[0].IncidentID != "" || evaluations[0].IncidentChanged {
		t.Fatalf("evaluations=%+v err=%v", evaluations, err)
	}
	loaded, err := store.AlertRule(ctx, "organization-a", rule.ID)
	if err != nil || loaded.LastError != "query_unavailable" || loaded.LastResult != nil {
		t.Fatalf("rule=%+v err=%v", loaded, err)
	}
	incidents, err := store.Incidents(ctx, "organization-a", true, 10)
	if err != nil || len(incidents) != 0 {
		t.Fatalf("incidents=%+v err=%v", incidents, err)
	}
}

func TestDueAlertRuleClaimPreventsConcurrentDuplicateEvaluation(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 13, 0, 0, 0, time.UTC)
	saved, err := store.SaveQuery(ctx, SavedQueryInput{OrganizationID: "organization-a", ActorUserID: "operator-a", MaxRows: 100, Name: "Any logs", Description: "Any recent log.", Query: "logs | window 1h | limit 10"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.SaveAlertRule(ctx, AlertRuleInput{OrganizationID: "organization-a", ActorUserID: "operator-a", SavedQueryID: saved.ID, Name: "Any log", Description: "Concurrency claim test.", Severity: "warning", MinimumMatches: 1, RequiredConsecutive: 1, EvaluationInterval: 15 * time.Second, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	budget := query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 16 << 20, MaxMemoryBytes: 8 << 20}
	var group sync.WaitGroup
	results := make(chan []AlertEvaluation, 2)
	errors := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			value, evaluationErr := store.EvaluateDueAlertRules(ctx, budget, now)
			results <- value
			errors <- evaluationErr
		}()
	}
	group.Wait()
	close(results)
	close(errors)
	total := 0
	for err = range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	for result := range results {
		total += len(result)
	}
	if total != 1 {
		t.Fatalf("evaluations=%d, want 1", total)
	}
}

func TestAlertRulesRejectCrossOrganizationAndUnboundedInputs(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Now().UTC()
	saved, err := store.SaveQuery(ctx, SavedQueryInput{OrganizationID: "organization-a", ActorUserID: "operator-a", MaxRows: 100, Name: "Query", Description: "Scoped query.", Query: "logs | limit 10"}, now)
	if err != nil {
		t.Fatal(err)
	}
	base := AlertRuleInput{OrganizationID: "organization-b", ActorUserID: "operator-b", SavedQueryID: saved.ID, Name: "Cross scope", Description: "Must fail.", Severity: "warning", MinimumMatches: 1, RequiredConsecutive: 1, EvaluationInterval: 15 * time.Second, Enabled: true}
	if _, err = store.SaveAlertRule(ctx, base, now); err == nil {
		t.Fatal("cross-organization saved query was accepted")
	}
	base.OrganizationID = "organization-a"
	base.EvaluationInterval = 14 * time.Second
	if _, err = store.SaveAlertRule(ctx, base, now); err == nil {
		t.Fatal("too-frequent evaluation was accepted")
	}
	base.EvaluationInterval = 15 * time.Second
	base.RequiredConsecutive = 11
	if _, err = store.SaveAlertRule(ctx, base, now); err == nil {
		t.Fatal("unbounded confirmation count was accepted")
	}
}
