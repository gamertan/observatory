// SPDX-License-Identifier: AGPL-3.0-only

package spool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
)

func TestSpoolRoundTripAndExactAcknowledgement(t *testing.T) {
	root := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	spool, err := Open(root, 1<<20, 72*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request"}}}
	checkpoint := []byte(`{"offset":42,"sequence":1}`)
	entry, err := spool.PutWithCheckpoint(batch, checkpoint, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := spool.Read(entry)
	if err != nil || got.Sequence != 1 {
		t.Fatalf("batch=%+v err=%v", got, err)
	}
	_, gotCheckpoint, err := spool.ReadWithCheckpoint(entry)
	if err != nil || string(gotCheckpoint) != string(checkpoint) {
		t.Fatalf("checkpoint=%s err=%v", gotCheckpoint, err)
	}
	if err := spool.Acknowledge(entry, "wrong"); err == nil {
		t.Fatal("expected digest mismatch")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := spool.Acknowledge(Entry{Path: outside, Digest: entry.Digest}, entry.Digest); err == nil {
		t.Fatal("expected acknowledgement path rejection")
	}
	if err := spool.Acknowledge(entry, entry.Digest); err != nil {
		t.Fatal(err)
	}
	if entries, err := spool.List(now); err != nil || len(entries) != 0 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
}

func TestSpoolRejectsQuotaAndSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	spool, err := Open(root, 1<<20, 72*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "pending", "bad")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Skip(err)
	}
	if _, err := spool.List(time.Now().UTC()); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestSpoolRejectsOversizedFileBeforeRead(t *testing.T) {
	root := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	queue, err := Open(root, 1<<20, 72*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "pending", "access")
	if err = os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "00000000000000000001-"+strings.Repeat("a", 64)+".zst")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(maxEncodedBatchBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = queue.List(time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "compressed size limit") {
		t.Fatalf("expected compressed-size rejection, got %v", err)
	}
}
