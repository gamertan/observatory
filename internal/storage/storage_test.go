// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
)

func TestNativeEnvelopeReplayUsesBatchIdentityAndAllowsOverlappingTime(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	token, err := store.CreateSource(ctx, "source-framed", model.Scope{OrganizationID: "organization", ProjectID: "project", EnvironmentID: "production", ServiceID: "service"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 20, 0, 0, 0, time.UTC)
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source-framed", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request"}}}
	body, _ := json.Marshal(batch)
	envelope, _ := batch.Envelope(body)
	ack, err := store.IngestNative(ctx, token, batch, envelope, body, now)
	if err != nil || ack.Duplicate {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}
	preflight, exact, err := store.CheckNativeReplay(ctx, token, envelope)
	if err != nil || !exact || !preflight.Duplicate || preflight.Digest != ack.Digest {
		t.Fatalf("preflight=%+v exact=%t err=%v", preflight, exact, err)
	}
	// A known exact retry remains acknowledgeable after its original ingest
	// clock window; the immutable bytes and persisted envelope are authoritative.
	confirmed, err := store.ConfirmNativeReplay(ctx, token, envelope)
	if err != nil || !confirmed.Duplicate || confirmed.BatchDigest != envelope.BatchDigest {
		t.Fatalf("confirmed=%+v err=%v", confirmed, err)
	}
	conflict := envelope
	conflict.RecordCount++
	if _, _, err = store.CheckNativeReplay(ctx, token, conflict); err == nil {
		t.Fatal("same sequence with conflicting envelope was accepted")
	}

	// A second batch may overlap the first batch's timestamps. Time is a
	// partition hint, not a deduplication key.
	batch.Sequence = 2
	batch.ObservedAt = now.Add(time.Second)
	body, _ = json.Marshal(batch)
	envelope, _ = batch.Envelope(body)
	if _, err = store.IngestNative(ctx, token, batch, envelope, body, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var batchDigest, wireDigest string
	var recordCount int
	if err = store.control.QueryRow(`SELECT last_batch_digest,last_wire_digest,last_record_count FROM streams WHERE source_id=? AND stream_id=?`, batch.SourceID, batch.StreamID).Scan(&batchDigest, &wireDigest, &recordCount); err != nil || batchDigest != envelope.BatchDigest || wireDigest != envelope.WireDigest || recordCount != 1 {
		t.Fatalf("batch=%q wire=%q count=%d err=%v", batchDigest, wireDigest, recordCount, err)
	}
}

func TestIngestAutoSerializesConcurrentSequenceAssignment(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	token, err := store.CreateSource(ctx, "source-auto", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	const requests = 16
	results := make(chan Ack, requests)
	errors := make(chan error, requests)
	var group sync.WaitGroup
	for index := 0; index < requests; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			ack, ingestErr := store.IngestAuto(ctx, token, "otlp-logs", model.SignalLogs, []model.Observation{{Timestamp: now, Name: "http.request"}}, now)
			if ingestErr != nil {
				errors <- ingestErr
				return
			}
			results <- ack
		}()
	}
	group.Wait()
	close(results)
	close(errors)
	for ingestErr := range errors {
		t.Errorf("ingest: %v", ingestErr)
	}
	var sequences []int
	for ack := range results {
		if ack.Duplicate || ack.Digest == "" || ack.StreamID != "otlp-logs" {
			t.Errorf("ack=%+v", ack)
		}
		sequences = append(sequences, int(ack.Sequence))
	}
	sort.Ints(sequences)
	if len(sequences) != requests {
		t.Fatalf("sequences=%v", sequences)
	}
	for index, sequence := range sequences {
		if sequence != index+1 {
			t.Fatalf("sequences=%v", sequences)
		}
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func projectAll(t testing.TB, store *Store) {
	t.Helper()
	for {
		report, err := store.ProjectPending(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if report.ProjectedSegments == 0 {
			return
		}
	}
}

func TestStorageRejectsSymlinkedSQLiteFilesAndProjectionDirectories(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "target.sqlite")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "control.sqlite")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil {
		t.Fatal("symlink control database was accepted")
	}
	if err := os.Remove(filepath.Join(root, "control.sqlite")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(root, "control.sqlite")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil {
		t.Fatal("hard-linked control database was accepted")
	}
	if err := os.Remove(filepath.Join(root, "control.sqlite")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "organizations"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, filepath.Join(root, "organizations", "organization-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := openProjection(context.Background(), filepath.Join(root, "organizations", "organization-a", "projection.sqlite")); err == nil {
		t.Fatal("symlink organization directory was accepted")
	}
	if err := os.Remove(filepath.Join(root, "organizations", "organization-a")); err != nil {
		t.Fatal(err)
	}
	organization := filepath.Join(root, "organizations", "organization-a")
	if err := os.Mkdir(organization, 0o700); err != nil {
		t.Fatal(err)
	}
	projection := filepath.Join(organization, "projection.sqlite")
	if err := os.Symlink(target, projection+"-wal"); err != nil {
		t.Fatal(err)
	}
	if _, err := openProjection(context.Background(), projection); err == nil {
		t.Fatal("symlink projection sidecar was accepted")
	}
}

func TestScopedIngestionDeduplicationAndReplay(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	scope := model.Scope{OrganizationID: "org-a", ProjectID: "site", EnvironmentID: "prod", ServiceID: "web"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source-a", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "http.request", Attributes: map[string]string{"route": "/"}}}}
	ack, err := store.Ingest(ctx, token, batch, now)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Duplicate || ack.Digest == "" {
		t.Fatalf("unexpected acknowledgement: %#v", ack)
	}
	duplicate, err := store.Ingest(ctx, token, batch, now)
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.Duplicate || duplicate.Digest != ack.Digest {
		t.Fatalf("unexpected duplicate acknowledgement: %#v", duplicate)
	}
	batch.Records[0].Name = "changed"
	if _, err := store.Ingest(ctx, token, batch, now); err == nil {
		t.Fatal("expected conflicting duplicate rejection")
	}
	entries, err := store.segments.List()
	if err != nil || len(entries) != 1 || entries[0].Committed.Digest != ack.Digest {
		t.Fatalf("conflicting replay left raw evidence behind: entries=%+v err=%v", entries, err)
	}
	batch.Sequence = 3
	if _, err := store.Ingest(ctx, token, batch, now); err == nil {
		t.Fatal("expected sequence gap rejection")
	}
}

func TestProjectorReusesProjectionHandleAndRejectsPathReplacement(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ingest := func(sequence uint64) error {
		batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "logs", Sequence: sequence, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "application.request"}}}
		_, ingestErr := store.Ingest(ctx, token, batch, now)
		return ingestErr
	}
	if err = ingest(1); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	store.projectionMu.Lock()
	first := store.projections[scope.OrganizationID]
	store.projectionMu.Unlock()
	if first.db == nil {
		t.Fatal("projection handle was not retained")
	}
	if err = ingest(2); err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	store.projectionMu.Lock()
	second := store.projections[scope.OrganizationID]
	store.projectionMu.Unlock()
	if second.db != first.db || second.device != first.device || second.inode != first.inode {
		t.Fatal("projection handle was reopened for an unchanged organization")
	}

	projection := filepath.Join(store.root, "organizations", scope.OrganizationID, "projection.sqlite")
	replaced := projection + ".replaced"
	if err = os.Rename(projection, replaced); err != nil {
		t.Fatal(err)
	}
	if err = ingest(3); err != nil {
		t.Fatalf("durable ingestion depended on projection path: %v", err)
	}
	if _, err = store.ProjectPending(ctx); err == nil {
		t.Fatal("replaced projection path was accepted by projector")
	}
	if err = os.Rename(replaced, projection); err != nil {
		t.Fatal(err)
	}
	if err = store.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	var projected int
	if err = second.db.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&projected); err != nil {
		t.Fatal(err)
	}
	if projected != 3 {
		t.Fatalf("projected=%d", projected)
	}
}

func TestCredentialScopeCannotBeOverridden(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "org-a", ProjectID: "p", EnvironmentID: "prod", ServiceID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source-b", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request"}}}
	if _, err := store.Ingest(ctx, token, batch, now); err == nil {
		t.Fatal("expected source mismatch rejection")
	}
}

func TestRecoveryIndexesRawSegmentMissingFromControlDatabase(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	token, err := store.CreateSource(ctx, "source-a", model.Scope{OrganizationID: "org-a", ProjectID: "p", EnvironmentID: "prod", ServiceID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source-a", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request"}}}
	if _, err := store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.control.Exec(`DELETE FROM streams; DELETE FROM segments`); err != nil {
		t.Fatal(err)
	}
	if err := store.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	var segments, projected int
	if err := store.control.QueryRow(`SELECT COUNT(*), COUNT(projected_at) FROM segments`).Scan(&segments, &projected); err != nil {
		t.Fatal(err)
	}
	if segments != 1 || projected != 1 {
		t.Fatalf("segments=%d projected=%d", segments, projected)
	}
}

func TestRecoveryRejectsCataloguedRawMetadataMismatchWithoutDecoding(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	scope := model.Scope{OrganizationID: "org-a", ProjectID: "p", EnvironmentID: "prod", ServiceID: "s"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source-a", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request"}}}
	if _, err = store.Ingest(ctx, token, batch, now); err != nil {
		t.Fatal(err)
	}
	var original string
	if err = store.control.QueryRow(`SELECT path FROM segments`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(store.root, "raw", "org-a", "source-b", "access", filepath.Base(original))
	if err = os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(original, destination); err != nil {
		t.Fatal(err)
	}
	if err = store.Recover(ctx); err == nil {
		t.Fatal("catalogued segment identity mismatch was accepted")
	}
}

func TestRecoveryDoesNotDecodeAlreadyCataloguedRawSegments(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	scope := model.Scope{OrganizationID: "org-a", ProjectID: "p", EnvironmentID: "prod", ServiceID: "s"}
	token, err := store.CreateSource(ctx, "source-a", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source-a", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request"}}}
	ack, err := store.Ingest(ctx, token, batch, now)
	if err != nil {
		t.Fatal(err)
	}
	projectAll(t, store)
	var path string
	if err = store.control.QueryRow(`SELECT path FROM segments WHERE digest=?`, ack.Digest).Scan(&path); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[0] ^= 0xff
	if err = os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = store.Recover(ctx); err != nil {
		t.Fatalf("startup decoded catalogued evidence: %v", err)
	}
	if _, err = store.segments.Read(path, ack.Digest); err == nil {
		t.Fatal("explicit forensic read accepted corrupt evidence")
	}
}

func TestRecoveryProcessesUnprojectedSegmentsInBoundedPages(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	if _, err := store.CreateSource(ctx, "source-a", scope); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	const count = recoveryPageSize + 3
	for sequence := uint64(1); sequence <= count; sequence++ {
		batch := model.Batch{Version: model.BatchVersion, SourceID: "source-a", StreamID: "logs", Sequence: sequence, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "application.request"}}}
		committed, err := store.segments.Commit(scope, batch)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.recordCommitted(ctx, scope, batch, committed); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	var segments, projected int
	if err := store.control.QueryRow(`SELECT COUNT(*), COUNT(projected_at) FROM segments`).Scan(&segments, &projected); err != nil {
		t.Fatal(err)
	}
	if segments != count || projected != count {
		t.Fatalf("segments=%d projected=%d", segments, projected)
	}
}

func TestCommittedAdmissionRejectsInvalidTimeWithoutControlState(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	if _, err := store.CreateSource(ctx, "source-a", scope); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{
		Version: model.BatchVersion, SourceID: "source-a", StreamID: "logs", Sequence: 1,
		ObservedAt: now, Signal: model.SignalLogs,
		Records: []model.Observation{{Timestamp: now, Name: "application.request", Attributes: map[string]string{"workshop.unknown": "value"}}},
	}
	committed, err := store.segments.Commit(scope, batch)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.admitCommitted(ctx, scope, batch, committed, time.Time{}); err == nil {
		t.Fatal("invalid committed time was accepted")
	}
	var segments, streams, proposals int
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM segments`).Scan(&segments); err != nil {
		t.Fatal(err)
	}
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM streams`).Scan(&streams); err != nil {
		t.Fatal(err)
	}
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM descriptor_proposals`).Scan(&proposals); err != nil {
		t.Fatal(err)
	}
	if segments != 0 || streams != 0 || proposals != 0 {
		t.Fatalf("partial durable control state: segments=%d streams=%d proposals=%d", segments, streams, proposals)
	}
	if err = store.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	var projected int
	if err = store.control.QueryRow(`SELECT COUNT(*), COUNT(projected_at) FROM segments`).Scan(&segments, &projected); err != nil {
		t.Fatal(err)
	}
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM streams`).Scan(&streams); err != nil {
		t.Fatal(err)
	}
	if err = store.control.QueryRow(`SELECT COUNT(*) FROM descriptor_proposals`).Scan(&proposals); err != nil {
		t.Fatal(err)
	}
	if segments != 1 || projected != 1 || streams != 1 || proposals != 1 {
		t.Fatalf("recovery did not complete durable projection state: segments=%d projected=%d streams=%d proposals=%d", segments, projected, streams, proposals)
	}
}

func TestEnrollmentIsScopedExpiringAndSingleUse(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 2, 0, 0, 0, time.UTC)
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, enrollment, err := store.CreateEnrollment(ctx, "source-a", scope, "operator-a", 15*time.Minute, now)
	if err != nil || token == "" || enrollment.Scope != scope {
		t.Fatalf("token_present=%t enrollment=%+v err=%v", token != "", enrollment, err)
	}
	got, credential, err := store.RedeemEnrollment(ctx, token, now.Add(time.Minute))
	if err != nil || got.SourceID != "source-a" || credential == "" {
		t.Fatalf("enrollment=%+v credential_present=%t err=%v", got, credential != "", err)
	}
	source, err := store.Authenticate(ctx, credential)
	if err != nil || source.Scope != scope {
		t.Fatalf("source=%+v err=%v", source, err)
	}
	if _, _, err = store.RedeemEnrollment(ctx, token, now.Add(2*time.Minute)); err == nil {
		t.Fatal("single-use enrollment redeemed twice")
	}
	expired, _, err := store.CreateEnrollment(ctx, "source-b", scope, "operator-a", 5*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.RedeemEnrollment(ctx, expired, now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired enrollment accepted")
	}
}
