// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcessLockSeparatesLiveServerFromOfflineMigration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	first, err := AcquireProcessLock(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := AcquireProcessLock(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = AcquireProcessLock(root, true); err == nil {
		t.Fatal("exclusive migration lock overlapped live server locks")
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	exclusive, err := AcquireProcessLock(root, true)
	if err != nil {
		t.Fatal(err)
	}
	defer exclusive.Close()
	if _, err = AcquireProcessLock(root, false); err == nil {
		t.Fatal("server lock overlapped exclusive migration lock")
	}
}

func TestProcessLockRejectsUnsafeFilesystemObjects(t *testing.T) {
	base := t.TempDir()
	private := filepath.Join(base, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkRoot := filepath.Join(base, "symlink-root")
	if err := os.Symlink(private, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireProcessLock(symlinkRoot, false); err == nil {
		t.Fatal("symlink process-lock root was accepted")
	}
	public := filepath.Join(base, "public")
	if err := os.Mkdir(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireProcessLock(public, false); err == nil {
		t.Fatal("public process-lock root was accepted")
	}
	lockPath := filepath.Join(private, "process.lock")
	target := filepath.Join(private, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lockPath); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireProcessLock(private, false); err == nil {
		t.Fatal("symlink process-lock file was accepted")
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, lockPath); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireProcessLock(private, false); err == nil {
		t.Fatal("hard-linked process-lock file was accepted")
	}
}
