// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
)

func TestCommittedSegmentRecordsBoundedBatchMetadata(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	ctx := context.Background()
	now := time.Date(2026, 8, 19, 0, 10, 0, 0, time.UTC)
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now.Add(-time.Second), Name: "first"}, {Timestamp: now, Name: "second"}}}
	ack, err := store.Ingest(ctx, token, batch, now)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	var first, last string
	if err = store.control.QueryRowContext(ctx, `SELECT record_count,first_observed_at,last_observed_at FROM segments WHERE digest=?`, ack.Digest).Scan(&count, &first, &last); err != nil {
		t.Fatal(err)
	}
	if count != 2 || first != now.Add(-time.Second).Format(time.RFC3339Nano) || last != now.Format(time.RFC3339Nano) {
		t.Fatalf("count=%d first=%q last=%q", count, first, last)
	}
}
