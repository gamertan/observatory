// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/schema"
)

func TestDescriptorProposalsAreSegmentIdempotentAndDefaultSensitive(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 7, 30, 0, 0, time.UTC)
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "metrics", Sequence: 1, ObservedAt: now, Signal: model.SignalMetrics, Records: []model.Observation{
		{Timestamp: now, Name: "custom.metric", Value: floatPointer(1), Attributes: map[string]string{"workshop.queue_depth": "9238471928374", "http.route": "/known", "invalid-field": "ignored"}},
		{Timestamp: now, Name: "custom.metric", Value: floatPointer(2), Attributes: map[string]string{"workshop.queue_depth": "9238471928375"}},
	}}
	ack, err := store.Ingest(ctx, token, batch, now)
	if err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	proposals, err := store.DescriptorProposals(ctx, "organization-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(proposals) != 1 {
		t.Fatalf("proposals=%+v", proposals)
	}
	proposal := proposals[0]
	if proposal.Proposal.Descriptor.Field != "workshop.queue_depth" || proposal.Proposal.Descriptor.Type != schema.TypeInteger || proposal.Proposal.Descriptor.Sensitivity != schema.SensitivitySensitive || proposal.Proposal.Descriptor.Index != schema.IndexNone || proposal.Proposal.ObservedValues != 2 || proposal.Status != "pending" {
		t.Fatalf("proposal=%+v", proposal)
	}
	if len(proposal.Proposal.ExampleQueries) != 1 || proposal.Proposal.ExampleQueries[0] != `metrics | where workshop.queue_depth == "value" | limit 50` {
		t.Fatalf("examples=%v", proposal.Proposal.ExampleQueries)
	}
	encoded, err := json.Marshal(proposals)
	if err != nil || strings.Contains(string(encoded), "9238471928374") || strings.Contains(string(encoded), "9238471928375") {
		t.Fatalf("observed values entered proposal metadata: %s err=%v", encoded, err)
	}
	if err = store.recordDescriptorProposals(ctx, "organization-a", batch, ack.Digest, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	proposals, err = store.DescriptorProposals(ctx, "organization-a")
	if err != nil || proposals[0].Proposal.ObservedValues != 2 || !proposals[0].LastSeenAt.Equal(now) {
		t.Fatalf("idempotent proposals=%+v err=%v", proposals, err)
	}
}

func TestDescriptorProposalTypesWidenWithoutMixingOrganizations(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 7, 30, 0, 0, time.UTC)
	for index, organization := range []string{"organization-a", "organization-b"} {
		source := "source-" + string(rune('a'+index))
		token, err := store.CreateSource(ctx, source, model.Scope{OrganizationID: organization, ProjectID: "project", EnvironmentID: "production", ServiceID: "service"})
		if err != nil {
			t.Fatal(err)
		}
		value := "10"
		if organization == "organization-b" {
			value = "label"
		}
		batch := model.Batch{Version: model.BatchVersion, SourceID: source, StreamID: "metrics", Sequence: 1, ObservedAt: now, Signal: model.SignalMetrics, Records: []model.Observation{{Timestamp: now, Name: "custom.metric", Value: floatPointer(1), Attributes: map[string]string{"workshop.value": value}}}}
		if _, err = store.Ingest(ctx, token, batch, now); err != nil {
			t.Fatal(err)
		}
		if organization == "organization-a" {
			batch.Sequence = 2
			batch.Records[0].Attributes["workshop.value"] = "10.5"
			if _, err = store.Ingest(ctx, token, batch, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		}
	}
	projectAll(t, store)
	proposalA, err := store.DescriptorProposals(ctx, "organization-a")
	if err != nil {
		t.Fatal(err)
	}
	proposalB, err := store.DescriptorProposals(ctx, "organization-b")
	if err != nil {
		t.Fatal(err)
	}
	if proposalA[0].Proposal.Descriptor.Type != schema.TypeFloat || proposalB[0].Proposal.Descriptor.Type != schema.TypeString {
		t.Fatalf("organization-a=%+v organization-b=%+v", proposalA, proposalB)
	}
}

func floatPointer(value float64) *float64 { return &value }
