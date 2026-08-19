// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/storage"
)

func TestAgentAlertTransitionIsAuthenticatedBoundedAndEvidenceBacked(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identities, err := identity.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer identities.Close()
	now := time.Date(2026, 8, 18, 23, 45, 0, 0, time.UTC)
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(context.Background(), "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := store.SaveQuery(context.Background(), storage.SavedQueryInput{OrganizationID: scope.OrganizationID, ActorUserID: "operator-a", MaxRows: 100, Name: "Logs", Query: "logs | limit 10", Scope: storage.ResourceScope{ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID, ServiceID: scope.ServiceID}}, now)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := store.SaveAlertRule(context.Background(), storage.AlertRuleInput{OrganizationID: scope.OrganizationID, ActorUserID: "operator-a", SavedQueryID: saved.ID, Name: "Logs", Severity: "warning", MinimumMatches: 1, RequiredConsecutive: 1, EvaluationInterval: 15 * time.Second, Enabled: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request"}}}
	ingested, err := store.Ingest(context.Background(), token, batch, now)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(store, identities, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	handler := server.Handler()
	transition := model.AlertTransition{Version: model.AlertTransitionVersion, RuleID: rule.ID, RuleRevision: rule.Revision, AgentEpoch: strings.Repeat("a", 32), Sequence: 1, StreamID: batch.StreamID, BatchSequence: batch.Sequence, SegmentDigest: ingested.Digest, WindowStart: now, WindowEnd: now, State: "matched", ObservedAt: now}
	payload, err := json.Marshal(transition)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://observatory.example/api/v1/agent/alert-transition", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var ack storage.SourceAlertTransitionAck
	if err = json.Unmarshal(response.Body.Bytes(), &ack); err != nil || ack.SourceID != "source-a" || ack.RuleID != rule.ID || ack.Duplicate {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}

	unauthorized := httptest.NewRequest(http.MethodPost, "https://observatory.example/api/v1/agent/alert-transition", bytes.NewReader([]byte(`{"state":"do-not-echo"}`)))
	unauthorizedResult := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResult, unauthorized)
	if unauthorizedResult.Code != http.StatusUnauthorized || strings.Contains(unauthorizedResult.Body.String(), "do-not-echo") {
		t.Fatalf("unauthorized status=%d body=%q", unauthorizedResult.Code, unauthorizedResult.Body.String())
	}
	oversized := httptest.NewRequest(http.MethodPost, "https://observatory.example/api/v1/agent/alert-transition", strings.NewReader(strings.Repeat("x", (64<<10)+1)))
	oversized.Header.Set("Authorization", "Bearer "+token)
	oversizedResult := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResult, oversized)
	if oversizedResult.Code != http.StatusBadRequest {
		t.Fatalf("oversized status=%d body=%q", oversizedResult.Code, oversizedResult.Body.String())
	}
}
