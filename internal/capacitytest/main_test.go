//go:build observatory_capacity_fixture && linux

// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/storage"
)

func TestMeasureStorageClassifiesFilesAndSQLiteObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "dataset")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scope := model.Scope{OrganizationID: "capacity-org-1", ProjectID: "observatory", EnvironmentID: "capacity", ServiceID: "server"}
	token, err := store.CreateSource(t.Context(), "capacity-source-1", scope)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "capacity-source-1", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: syntheticRecords(2, model.SignalLogs, now, new(atomic.Uint64))}
	if _, err = store.Ingest(context.Background(), token, batch, now); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if _, err = store.ProjectPending(t.Context()); err != nil {
		store.Close()
		t.Fatal(err)
	}
	report, err := measureStorage(root, scope.OrganizationID)
	if closeErr := store.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if report.Raw.Files == 0 || report.Raw.Bytes == 0 || report.Projection.Files == 0 || report.Projection.Bytes == 0 || report.Control.Files == 0 || report.Control.Bytes == 0 {
		t.Fatalf("incomplete breakdown: %+v", report)
	}
	if report.Total.Files != report.Raw.Files+report.Projection.Files+report.Control.Files+report.Other.Files {
		t.Fatalf("file total mismatch: %+v", report)
	}
	if report.Total.Bytes != report.Raw.Bytes+report.Projection.Bytes+report.Control.Bytes+report.Other.Bytes {
		t.Fatalf("byte total mismatch: %+v", report)
	}
	if report.SQLiteBytes["observations"] == 0 || report.SQLiteBytes["observations_signal_time"] == 0 {
		t.Fatalf("SQLite object accounting missing: %+v", report.SQLiteBytes)
	}
	if report.SQLitePageClasses.Tables == 0 || report.SQLitePageClasses.Indexes == 0 || report.SQLitePageClasses.Total != report.SQLitePageClasses.Tables+report.SQLitePageClasses.Indexes+report.SQLitePageClasses.Internal {
		t.Fatalf("SQLite page classes incomplete: %+v", report.SQLitePageClasses)
	}
}

func TestMeasureStorageRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("unsafe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := measureStorage(root, "capacity-org-1"); err == nil {
		t.Fatal("symlinked capacity evidence was accepted")
	}
}
