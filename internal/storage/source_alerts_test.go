// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

func TestSourceAlertTransitionBindsAuthenticatedBatchEvidence(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 18, 23, 0, 0, 0, time.UTC)
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := store.SaveQuery(ctx, SavedQueryInput{
		OrganizationID: scope.OrganizationID,
		ActorUserID:    "operator-a",
		MaxRows:        100,
		Name:           "Source failures",
		Description:    "Exact source-scoped failures for differential evaluation.",
		Query:          "logs | where status >= 500 | window 1h | limit 50",
		Scope:          ResourceScope{ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID, ServiceID: scope.ServiceID},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := store.SaveAlertRule(ctx, AlertRuleInput{
		OrganizationID: scope.OrganizationID, ActorUserID: "operator-a", SavedQueryID: saved.ID,
		Name: "Source failures", Description: "Source and server comparison rule.", Severity: "warning",
		MinimumMatches: 1, RequiredConsecutive: 1, EvaluationInterval: 15 * time.Second, Enabled: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	observed := now.Add(time.Second)
	batch := model.Batch{
		Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1,
		ObservedAt: observed, Signal: model.SignalLogs,
		Records: []model.Observation{{Timestamp: observed, Name: "http.request", Attributes: map[string]string{"http.status_code": "503", "http.route": "/failed"}}},
	}
	ingested, err := store.Ingest(ctx, token, batch, observed)
	if err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	budget := query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 16 << 20, MaxMemoryBytes: 8 << 20}
	central, err := store.EvaluateDueAlertRules(ctx, budget, now.Add(15*time.Second))
	if err != nil || len(central) != 1 || !central[0].Matched {
		t.Fatalf("central=%+v err=%v", central, err)
	}

	transition := model.AlertTransition{
		Version: model.AlertTransitionVersion, RuleID: rule.ID, RuleRevision: rule.Revision,
		AgentEpoch: strings.Repeat("a", 32), Sequence: 7, StreamID: batch.StreamID,
		BatchSequence: batch.Sequence, SegmentDigest: ingested.Digest,
		WindowStart: observed, WindowEnd: observed, State: "matched", ObservedAt: now.Add(16 * time.Second),
	}
	ack, err := store.RecordSourceAlertTransition(ctx, token, transition, now.Add(16*time.Second))
	if err != nil || ack.SourceID != batch.SourceID || ack.RuleID != rule.ID || ack.Sequence != 7 || ack.Digest == "" || ack.Duplicate {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}
	replay, err := store.RecordSourceAlertTransition(ctx, token, transition, now.Add(17*time.Second))
	if err != nil || !replay.Duplicate || replay.Digest != ack.Digest {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}

	conflict := transition
	conflict.State = "clear"
	if _, err = store.RecordSourceAlertTransition(ctx, token, conflict, now.Add(17*time.Second)); err == nil || !strings.Contains(err.Error(), "reused with different content") {
		t.Fatalf("conflicting replay err=%v", err)
	}
	gap := transition
	gap.Sequence = 9
	if _, err = store.RecordSourceAlertTransition(ctx, token, gap, now.Add(17*time.Second)); err == nil || !strings.Contains(err.Error(), "sequence gap") {
		t.Fatalf("sequence gap err=%v", err)
	}
	wrongEvidence := transition
	wrongEvidence.Sequence = 8
	wrongEvidence.SegmentDigest = strings.Repeat("b", 64)
	if _, err = store.RecordSourceAlertTransition(ctx, token, wrongEvidence, now.Add(17*time.Second)); err == nil || !strings.Contains(err.Error(), "evidence is unavailable") {
		t.Fatalf("wrong evidence err=%v", err)
	}

	otherToken, err := store.CreateSource(ctx, "source-b", model.Scope{OrganizationID: scope.OrganizationID, ProjectID: "project-b", EnvironmentID: "production", ServiceID: "service-b"})
	if err != nil {
		t.Fatal(err)
	}
	other := transition
	other.Sequence = 8
	if _, err = store.RecordSourceAlertTransition(ctx, otherToken, other, now.Add(17*time.Second)); err == nil || !strings.Contains(err.Error(), "not scoped to this source") {
		t.Fatalf("cross-source transition err=%v", err)
	}
}

func TestSourceAlertTransitionRequiresEvidenceCoveringItsWindow(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 18, 23, 30, 0, 0, time.UTC)
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := store.SaveQuery(ctx, SavedQueryInput{OrganizationID: scope.OrganizationID, ActorUserID: "operator-a", MaxRows: 100, Name: "Logs", Query: "logs | limit 10", Scope: ResourceScope{ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID, ServiceID: scope.ServiceID}}, now)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := store.SaveAlertRule(ctx, AlertRuleInput{OrganizationID: scope.OrganizationID, ActorUserID: "operator-a", SavedQueryID: saved.ID, Name: "Logs", Severity: "warning", MinimumMatches: 1, RequiredConsecutive: 1, EvaluationInterval: 15 * time.Second, Enabled: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	first, last := now.Add(-time.Minute), now
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: last, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: first, Name: "first"}, {Timestamp: last, Name: "last"}}}
	ingested, err := store.Ingest(ctx, token, batch, now)
	if err != nil {
		t.Fatal(err)
	}
	transition := model.AlertTransition{Version: model.AlertTransitionVersion, RuleID: rule.ID, RuleRevision: rule.Revision, AgentEpoch: strings.Repeat("c", 32), Sequence: 1, StreamID: batch.StreamID, BatchSequence: batch.Sequence, SegmentDigest: ingested.Digest, WindowStart: first.Add(time.Second), WindowEnd: last, State: "matched", ObservedAt: now}
	if _, err = store.RecordSourceAlertTransition(ctx, token, transition, now); err == nil || !strings.Contains(err.Error(), "does not match transition") {
		t.Fatalf("partial evidence window err=%v", err)
	}
}
