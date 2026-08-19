// SPDX-License-Identifier: AGPL-3.0-only

package segment

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
)

func TestCommitReadAndCorruption(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "http.request", Body: "safe"}}}
	scope := model.Scope{OrganizationID: "org", ProjectID: "project", EnvironmentID: "prod", ServiceID: "site"}
	committed, err := store.Commit(scope, batch)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Read(committed.Path, committed.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != 1 || got.SourceID != "source" {
		t.Fatalf("unexpected batch: %#v", got)
	}
	before, err := os.Stat(committed.Path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.Commit(scope, batch)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(again.Path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("idempotent commit changed segment mtime")
	}
	if err := os.WriteFile(committed.Path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(committed.Path, committed.Digest); err == nil {
		t.Fatal("expected checksum failure")
	}
}

func TestConcurrentCommitsCreateOnePrivateDirectoryChain(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 64
	now := time.Now().UTC()
	scope := model.Scope{OrganizationID: "org", ProjectID: "project", EnvironmentID: "prod", ServiceID: "site"}
	start := make(chan struct{})
	errorsChannel := make(chan error, writers)
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		wait.Add(1)
		go func(sequence uint64) {
			defer wait.Done()
			<-start
			batch := model.Batch{Version: 1, SourceID: "source", StreamID: "access", Sequence: sequence, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "http.request"}}}
			if _, commitErr := store.Commit(scope, batch); commitErr != nil {
				errorsChannel <- commitErr
			}
		}(uint64(index + 1))
	}
	close(start)
	wait.Wait()
	close(errorsChannel)
	for commitErr := range errorsChannel {
		t.Errorf("concurrent commit: %v", commitErr)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != writers {
		t.Fatalf("committed entries=%d want=%d", len(entries), writers)
	}
}

func TestListFindsCommittedSegments(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "http.request"}}}
	_, err = store.Commit(model.Scope{OrganizationID: "org", ProjectID: "project", EnvironmentID: "prod", ServiceID: "site"}, batch)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Batch.Sequence != 1 || entries[0].Committed.Digest == "" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestWalkMetadataDoesNotDecodeSegmentContents(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "http.request"}}}
	committed, err := store.Commit(model.Scope{OrganizationID: "org", ProjectID: "project", EnvironmentID: "prod", ServiceID: "site"}, batch)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(committed.Path)
	if err != nil {
		t.Fatal(err)
	}
	body[0] ^= 0xff
	if err = os.WriteFile(committed.Path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var metadata Metadata
	if err = store.WalkMetadata(func(candidate Metadata) error {
		metadata = candidate
		return nil
	}); err != nil {
		t.Fatalf("metadata walk decoded content: %v", err)
	}
	if metadata.Path != committed.Path || metadata.Digest != committed.Digest || metadata.Compressed != committed.Compressed {
		t.Fatalf("metadata=%+v committed=%+v", metadata, committed)
	}
	if _, err = store.ReadEntry(metadata); err == nil {
		t.Fatal("corrupt segment decoded successfully")
	}
}

func TestInterruptedTemporarySegmentIsIgnoredUntilAtomicCommit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "raw", "organization", "source", "stream")
	if err = os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(dir, ".segment-interrupted")
	if err = os.WriteFile(partial, []byte("partial compressed bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	if body, readErr := os.ReadFile(partial); readErr != nil || string(body) != "partial compressed bytes" {
		t.Fatalf("partial=%q err=%v", body, readErr)
	}
}

func TestReadRejectsSymlinksAndOversizedEncodedSegments(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(root, "raw"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "raw", "target")
	if err = os.WriteFile(target, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "raw", "link")
	if err = os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Read(link, "unused"); err == nil {
		t.Fatal("symlink segment accepted")
	}
	oversized := filepath.Join(root, "raw", "oversized")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(MaxEncodedSegment + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Read(oversized, "unused"); err == nil {
		t.Fatal("oversized encoded segment accepted")
	}
}

func TestCommitRejectsSymlinkedDirectoryChain(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(root, "raw"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "outside")
	if err = os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, filepath.Join(root, "raw", "org")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "http.request"}}}
	if _, err = store.Commit(model.Scope{OrganizationID: "org", ProjectID: "project", EnvironmentID: "prod", ServiceID: "site"}, batch); err == nil {
		t.Fatal("symlinked segment directory was accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatalf("symlink target was changed: entries=%v err=%v", entries, err)
	}
}

func TestMoveToColdIsVerifiedAndCrashIdempotent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "http.request"}}}
	committed, err := store.Commit(model.Scope{OrganizationID: "org", ProjectID: "project", EnvironmentID: "prod", ServiceID: "site"}, batch)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "cold", "org", "logs", "source", "access", filepath.Base(committed.Path))
	if err = store.MoveToCold(committed.Path, target, committed.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(committed.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hot segment still exists: %v", err)
	}
	if got, readErr := store.Read(target, committed.Digest); readErr != nil || got.Sequence != 1 {
		t.Fatalf("cold batch=%+v err=%v", got, readErr)
	}
	if err = store.MoveToCold(committed.Path, target, committed.Digest); err != nil {
		t.Fatalf("idempotent archive: %v", err)
	}
	if err = store.MoveToCold(target, committed.Path, committed.Digest); err == nil {
		t.Fatal("reverse cold-to-hot move was accepted")
	}
}

func TestMoveToColdRejectsSymlinkedDestination(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "data")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "http.request"}}}
	committed, err := store.Commit(model.Scope{OrganizationID: "org", ProjectID: "project", EnvironmentID: "prod", ServiceID: "site"}, batch)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err = os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(root, "cold")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	target := filepath.Join(root, "cold", "org", "logs", "source", "access", filepath.Base(committed.Path))
	if err = store.MoveToCold(committed.Path, target, committed.Digest); err == nil {
		t.Fatal("symlinked cold destination was accepted")
	}
	if _, err = os.Stat(committed.Path); err != nil {
		t.Fatalf("hot segment changed: %v", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("outside entries=%v err=%v", entries, err)
	}
}
