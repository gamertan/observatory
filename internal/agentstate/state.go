// SPDX-License-Identifier: AGPL-3.0-only

package agentstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const Version = 1

type Cursor struct {
	Device          uint64 `json:"device"`
	Inode           uint64 `json:"inode"`
	Offset          int64  `json:"offset"`
	Sequence        uint64 `json:"sequence"`
	DiscardingLine  bool   `json:"discarding_line"`
	DroppedRecords  uint64 `json:"dropped_records"`
	Discontinuities uint64 `json:"discontinuities"`
}

type State struct {
	Version int               `json:"version"`
	Streams map[string]Cursor `json:"streams"`
}

type Store struct{ path string }

func Open(path string) (*Store, State, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, State{}, errors.New("agent state path must be absolute and clean")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, State{}, fmt.Errorf("create agent state directory: %w", err)
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o077 != 0 {
		return nil, State{}, errors.New("agent state directory must be private and must not be a symlink")
	}
	store := &Store{path: path}
	state, err := store.Load()
	return store, state, err
}

func (store *Store) Load() (State, error) {
	info, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return State{Version: Version, Streams: map[string]Cursor{}}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("inspect agent state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return State{}, errors.New("agent state must be a mode-0600 regular non-symlink file")
	}
	body, err := os.ReadFile(store.path)
	if err != nil {
		return State{}, fmt.Errorf("read agent state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var state State
	if err = decoder.Decode(&state); err != nil {
		return State{}, errors.New("decode agent state")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return State{}, errors.New("agent state contains trailing data")
	}
	if err = state.Validate(); err != nil {
		return State{}, err
	}
	return state, nil
}

func (store *Store) Save(state State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	dir := filepath.Dir(store.path)
	temporary, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(body)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write agent state: %w", err)
	}
	if existing, inspectErr := os.Lstat(store.path); inspectErr == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 {
			return errors.New("agent state destination is not a regular file")
		}
	} else if !errors.Is(inspectErr, os.ErrNotExist) {
		return inspectErr
	}
	if err = os.Rename(name, store.path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (state State) Validate() error {
	if state.Version != Version || state.Streams == nil || len(state.Streams) > 64 {
		return errors.New("agent state identity is invalid")
	}
	for stream, cursor := range state.Streams {
		if !safeID(stream) || cursor.Offset < 0 || (cursor.Device == 0) != (cursor.Inode == 0) {
			return errors.New("agent state cursor is invalid")
		}
	}
	return nil
}

func safeID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-", character)) {
			return false
		}
	}
	return true
}
