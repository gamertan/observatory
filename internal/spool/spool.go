// SPDX-License-Identifier: AGPL-3.0-only

package spool

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gamertan.com/observatory/internal/model"
	"github.com/klauspost/compress/zstd"
)

type Spool struct {
	root     string
	maxBytes int64
	maxAge   time.Duration
}

type Entry struct {
	Path     string
	Digest   string
	StreamID string
	Sequence uint64
	Size     int64
	ModTime  time.Time
}

type envelope struct {
	Version    int             `json:"version"`
	Batch      model.Batch     `json:"batch"`
	Checkpoint json.RawMessage `json:"checkpoint,omitempty"`
}

const maxEncodedBatchBytes = 64 << 20

func Open(root string, maxBytes int64, maxAge time.Duration) (*Spool, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || maxBytes < 1<<20 || maxBytes > 5<<30 || maxAge < time.Hour || maxAge > 72*time.Hour {
		return nil, errors.New("invalid spool configuration")
	}
	if err := os.MkdirAll(filepath.Join(root, "pending"), 0o700); err != nil {
		return nil, fmt.Errorf("create spool: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("spool root must be a private non-symlink directory")
	}
	return &Spool{root: root, maxBytes: maxBytes, maxAge: maxAge}, nil
}

func (s *Spool) Put(batch model.Batch, now time.Time) (Entry, error) {
	return s.PutWithCheckpoint(batch, nil, now)
}

func (s *Spool) PutWithCheckpoint(batch model.Batch, checkpoint []byte, now time.Time) (Entry, error) {
	if err := batch.Validate(now); err != nil {
		return Entry{}, err
	}
	if len(checkpoint) > 4096 || len(checkpoint) != 0 && !json.Valid(checkpoint) {
		return Entry{}, errors.New("spool checkpoint is invalid")
	}
	raw, err := json.Marshal(envelope{Version: 1, Batch: batch, Checkpoint: checkpoint})
	if err != nil {
		return Entry{}, err
	}
	if len(raw) > maxEncodedBatchBytes {
		return Entry{}, errors.New("spool batch exceeds encoded size limit")
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		return Entry{}, err
	}
	compressed := encoder.EncodeAll(raw, nil)
	encoder.Close()
	entries, err := s.List(now)
	if err != nil {
		return Entry{}, err
	}
	var used int64
	for _, entry := range entries {
		used += entry.Size
	}
	if used+int64(len(compressed)) > s.maxBytes {
		return Entry{}, errors.New("agent spool quota exhausted")
	}
	sum := sha256.Sum256(compressed)
	digest := hex.EncodeToString(sum[:])
	dir := filepath.Join(s.root, "pending", batch.StreamID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Entry{}, err
	}
	final := filepath.Join(dir, fmt.Sprintf("%020d-%s.zst", batch.Sequence, digest))
	if info, err := os.Lstat(final); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return Entry{}, errors.New("existing spool batch is not a regular file")
		}
		existing, err := os.ReadFile(final)
		if err != nil || !bytes.Equal(existing, compressed) {
			return Entry{}, errors.New("existing spool batch does not match content")
		}
		return Entry{Path: final, Digest: digest, StreamID: batch.StreamID, Sequence: batch.Sequence, Size: info.Size(), ModTime: info.ModTime()}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Entry{}, err
	}
	tmp, err := os.CreateTemp(dir, ".batch-*")
	if err != nil {
		return Entry{}, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return Entry{}, err
	}
	if _, err := tmp.Write(compressed); err != nil {
		_ = tmp.Close()
		return Entry{}, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return Entry{}, err
	}
	if err := tmp.Close(); err != nil {
		return Entry{}, err
	}
	if err := os.Rename(name, final); err != nil {
		return Entry{}, err
	}
	if err := syncDir(dir); err != nil {
		return Entry{}, err
	}
	return Entry{Path: final, Digest: digest, StreamID: batch.StreamID, Sequence: batch.Sequence, Size: int64(len(compressed)), ModTime: now}, nil
}

func (s *Spool) List(now time.Time) ([]Entry, error) {
	base := filepath.Join(s.root, "pending")
	var entries []Entry
	err := filepath.WalkDir(base, func(path string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.Type()&os.ModeSymlink != 0 {
			return errors.New("spool contains a symlink")
		}
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".zst") {
			return nil
		}
		if !item.Type().IsRegular() {
			return errors.New("spool batch is not a regular file")
		}
		parts := strings.Split(strings.TrimSuffix(item.Name(), ".zst"), "-")
		if len(parts) != 2 || len(parts[0]) != 20 || len(parts[1]) != 64 {
			return errors.New("spool contains an invalid batch filename")
		}
		sequence, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return err
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		if info.Size() < 1 || info.Size() > maxEncodedBatchBytes {
			return errors.New("spool batch exceeds compressed size limit")
		}
		if now.Sub(info.ModTime()) > s.maxAge {
			return errors.New("agent spool contains data older than its outage budget")
		}
		entries = append(entries, Entry{Path: path, Digest: parts[1], StreamID: filepath.Base(filepath.Dir(path)), Sequence: sequence, Size: info.Size(), ModTime: info.ModTime()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].StreamID == entries[j].StreamID {
			return entries[i].Sequence < entries[j].Sequence
		}
		return entries[i].StreamID < entries[j].StreamID
	})
	return entries, nil
}

func (s *Spool) Read(entry Entry) (model.Batch, error) {
	batch, _, err := s.ReadWithCheckpoint(entry)
	return batch, err
}

func (s *Spool) ReadWithCheckpoint(entry Entry) (model.Batch, []byte, error) {
	if !strings.HasPrefix(filepath.Clean(entry.Path), filepath.Join(s.root, "pending")+string(os.PathSeparator)) {
		return model.Batch{}, nil, errors.New("spool entry escapes root")
	}
	info, err := os.Lstat(entry.Path)
	if err != nil {
		return model.Batch{}, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxEncodedBatchBytes {
		return model.Batch{}, nil, errors.New("spool batch is outside compressed size limit")
	}
	b, err := os.ReadFile(entry.Path)
	if err != nil {
		return model.Batch{}, nil, err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != entry.Digest {
		return model.Batch{}, nil, errors.New("spool checksum mismatch")
	}
	decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxEncodedBatchBytes), zstd.WithDecodeAllCapLimit(true))
	if err != nil {
		return model.Batch{}, nil, err
	}
	raw, err := decoder.DecodeAll(b, make([]byte, 0, maxEncodedBatchBytes))
	decoder.Close()
	if err != nil || len(raw) > maxEncodedBatchBytes {
		return model.Batch{}, nil, errors.New("invalid compressed spool batch")
	}
	var payload envelope
	jsonDecoder := json.NewDecoder(bytes.NewReader(raw))
	jsonDecoder.DisallowUnknownFields()
	if err := jsonDecoder.Decode(&payload); err != nil {
		return model.Batch{}, nil, err
	}
	if err := jsonDecoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return model.Batch{}, nil, errors.New("spool batch has trailing JSON")
	}
	if payload.Version != 1 || len(payload.Checkpoint) > 4096 {
		return model.Batch{}, nil, errors.New("spool envelope is invalid")
	}
	batch := payload.Batch
	if batch.StreamID != entry.StreamID || batch.Sequence != entry.Sequence {
		return model.Batch{}, nil, errors.New("spool path does not match batch identity")
	}
	return batch, append([]byte(nil), payload.Checkpoint...), nil
}

func (s *Spool) Acknowledge(entry Entry, digest string) error {
	if digest != entry.Digest {
		return errors.New("acknowledgement digest does not match spool entry")
	}
	if !strings.HasPrefix(filepath.Clean(entry.Path), filepath.Join(s.root, "pending")+string(os.PathSeparator)) {
		return errors.New("spool acknowledgement path escapes root")
	}
	info, err := os.Lstat(entry.Path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("spool acknowledgement target is not a regular file")
	}
	if err := os.Remove(entry.Path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(entry.Path))
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
