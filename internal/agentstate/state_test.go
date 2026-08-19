// SPDX-License-Identifier: AGPL-3.0-only

package agentstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateAtomicRoundTripAndSymlinkRefusal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(root, "state.json")
	store, state, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	state.Streams["access"] = Cursor{Device: 1, Inode: 2, Offset: 99, Sequence: 3, DroppedRecords: 4}
	if err = store.Save(state); err != nil {
		t.Fatal(err)
	}
	_, loaded, err := Open(path)
	if err != nil || loaded.Streams["access"] != state.Streams["access"] {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state info=%v err=%v", info, err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err = os.WriteFile(outside, []byte(`{"version":1,"streams":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, path); err != nil {
		t.Skip(err)
	}
	if _, _, err = Open(path); err == nil {
		t.Fatal("symlinked state accepted")
	}
}
