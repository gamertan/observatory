// SPDX-License-Identifier: AGPL-3.0-only

package segment

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

	"gamertan.com/observatory/internal/model"
	"github.com/klauspost/compress/zstd"
)

const (
	MaxDecodedSegment = 64 << 20
	MaxEncodedSegment = MaxDecodedSegment + 1<<20
	metadataReadBatch = 128
)

type Store struct {
	root string
}

type Committed struct {
	Path         string
	Digest       string
	Compressed   int64
	Uncompressed int64
}

type Entry struct {
	OrganizationID string
	Committed      Committed
	Batch          model.Batch
}

// Metadata identifies one immutable raw object without reading, checksumming,
// decompressing, or decoding its contents. It is safe to retain while walking
// a large store because it contains no telemetry records.
type Metadata struct {
	OrganizationID string
	SourceID       string
	StreamID       string
	Sequence       uint64
	Path           string
	Digest         string
	Compressed     int64
}

func New(root string) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("segment root must be an absolute clean path")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create segment root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("segment root must be a private non-symlink directory")
	}
	return &Store{root: root}, nil
}

func (s *Store) Commit(scope model.Scope, batch model.Batch) (Committed, error) {
	if err := scope.Validate(); err != nil {
		return Committed{}, err
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		return Committed{}, fmt.Errorf("encode batch: %w", err)
	}
	if len(raw) > MaxDecodedSegment {
		return Committed{}, errors.New("decoded segment exceeds limit")
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		return Committed{}, fmt.Errorf("create compressor: %w", err)
	}
	compressed := enc.EncodeAll(raw, nil)
	enc.Close()
	if len(compressed) > MaxEncodedSegment {
		return Committed{}, errors.New("encoded segment exceeds limit")
	}
	sum := sha256.Sum256(compressed)
	digest := hex.EncodeToString(sum[:])
	dir := filepath.Join(s.root, "raw", scope.OrganizationID, batch.SourceID, batch.StreamID)
	if err := ensurePrivateDirectoryChain(s.root, dir); err != nil {
		return Committed{}, err
	}
	name := fmt.Sprintf("%020d-%s.zst", batch.Sequence, digest)
	final := filepath.Join(dir, name)
	if existing, err := readRegular(final, MaxEncodedSegment); err == nil {
		if bytes.Equal(existing, compressed) {
			return Committed{Path: final, Digest: digest, Compressed: int64(len(compressed)), Uncompressed: int64(len(raw))}, nil
		}
		return Committed{}, errors.New("existing segment digest collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Committed{}, fmt.Errorf("inspect existing segment: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".segment-*")
	if err != nil {
		return Committed{}, fmt.Errorf("create segment temporary file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	defer cleanup()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return Committed{}, fmt.Errorf("set segment mode: %w", err)
	}
	if _, err := tmp.Write(compressed); err != nil {
		_ = tmp.Close()
		return Committed{}, fmt.Errorf("write segment: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return Committed{}, fmt.Errorf("sync segment: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return Committed{}, fmt.Errorf("close segment: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return Committed{}, fmt.Errorf("commit segment: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return Committed{}, fmt.Errorf("open segment directory: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return Committed{}, fmt.Errorf("sync segment directory: %w", err)
	}
	if err := d.Close(); err != nil {
		return Committed{}, fmt.Errorf("close segment directory: %w", err)
	}
	return Committed{Path: final, Digest: digest, Compressed: int64(len(compressed)), Uncompressed: int64(len(raw))}, nil
}

func (s *Store) Read(path, expectedDigest string) (model.Batch, error) {
	var batch model.Batch
	cleanRoot := filepath.Clean(s.root) + string(os.PathSeparator)
	cleanPath := filepath.Clean(path)
	if !strings.HasPrefix(cleanPath, cleanRoot) {
		return batch, errors.New("segment path escapes store")
	}
	if err := validatePrivateDirectoryChain(s.root, filepath.Dir(cleanPath)); err != nil {
		return batch, err
	}
	b, err := readRegular(cleanPath, MaxEncodedSegment)
	if err != nil {
		return batch, fmt.Errorf("read segment: %w", err)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != expectedDigest {
		return batch, errors.New("segment checksum mismatch")
	}
	dec, err := zstd.NewReader(bytes.NewReader(b), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(MaxDecodedSegment))
	if err != nil {
		return batch, fmt.Errorf("create decompressor: %w", err)
	}
	decompressed, err := io.ReadAll(io.LimitReader(dec, MaxDecodedSegment+1))
	dec.Close()
	if err != nil {
		return batch, fmt.Errorf("decompress segment: %w", err)
	}
	if len(decompressed) > MaxDecodedSegment {
		return batch, errors.New("decoded segment exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(decompressed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		return batch, fmt.Errorf("decode segment: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return batch, errors.New("segment contains trailing JSON")
	}
	return batch, nil
}

// ReadEntry validates and decodes exactly one object previously returned by
// WalkMetadata. Callers can therefore keep startup discovery bounded and pay
// the decompression cost only for an object that actually needs recovery.
func (s *Store) ReadEntry(metadata Metadata) (Entry, error) {
	actual, err := s.metadata(metadata.Path)
	if err != nil {
		return Entry{}, err
	}
	if actual != metadata {
		return Entry{}, errors.New("segment metadata changed before decode")
	}
	batch, err := s.Read(metadata.Path, metadata.Digest)
	if err != nil {
		return Entry{}, err
	}
	if batch.SourceID != metadata.SourceID || batch.StreamID != metadata.StreamID || batch.Sequence != metadata.Sequence {
		return Entry{}, errors.New("segment path does not match batch identity")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		return Entry{}, fmt.Errorf("measure decoded segment: %w", err)
	}
	return Entry{
		OrganizationID: metadata.OrganizationID,
		Committed: Committed{
			Path:         metadata.Path,
			Digest:       metadata.Digest,
			Compressed:   metadata.Compressed,
			Uncompressed: int64(len(raw)),
		},
		Batch: batch,
	}, nil
}

// Delete removes one already-retired segment after verifying that the path,
// filename, file type, and content digest still identify the exact committed
// object. A missing object is an idempotent success for crash recovery.
func (s *Store) Delete(path, expectedDigest string) error {
	if len(expectedDigest) != 64 {
		return errors.New("segment deletion digest is invalid")
	}
	rawRoot := filepath.Join(filepath.Clean(s.root), "raw") + string(os.PathSeparator)
	coldRoot := filepath.Join(filepath.Clean(s.root), "cold") + string(os.PathSeparator)
	cleanPath := filepath.Clean(path)
	if (!strings.HasPrefix(cleanPath, rawRoot) && !strings.HasPrefix(cleanPath, coldRoot)) || !strings.HasSuffix(filepath.Base(cleanPath), "-"+expectedDigest+".zst") {
		return errors.New("segment deletion path is invalid")
	}
	if err := validatePrivateDirectoryChain(s.root, filepath.Dir(cleanPath)); err != nil {
		return err
	}
	if _, err := os.Lstat(cleanPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect retired segment: %w", err)
	}
	if _, err := s.Read(cleanPath, expectedDigest); err != nil {
		return fmt.Errorf("verify retired segment: %w", err)
	}
	if err := os.Remove(cleanPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove retired segment: %w", err)
	}
	directory, err := os.Open(filepath.Dir(cleanPath))
	if err != nil {
		return fmt.Errorf("open retired segment directory: %w", err)
	}
	if err = directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync retired segment directory: %w", err)
	}
	if err = directory.Close(); err != nil {
		return fmt.Errorf("close retired segment directory: %w", err)
	}
	return nil
}

// MoveToCold atomically relocates one verified hot object beneath the cold
// archive. It is idempotent across a crash after rename: when the source is
// absent, the exact destination must already exist and match its digest.
func (s *Store) MoveToCold(path, target, expectedDigest string) error {
	if len(expectedDigest) != 64 {
		return errors.New("segment archive digest is invalid")
	}
	cleanPath, cleanTarget := filepath.Clean(path), filepath.Clean(target)
	rawRoot := filepath.Join(filepath.Clean(s.root), "raw") + string(os.PathSeparator)
	coldRoot := filepath.Join(filepath.Clean(s.root), "cold") + string(os.PathSeparator)
	if !strings.HasPrefix(cleanPath, rawRoot) || !strings.HasPrefix(cleanTarget, coldRoot) || filepath.Base(cleanPath) != filepath.Base(cleanTarget) || !strings.HasSuffix(filepath.Base(cleanPath), "-"+expectedDigest+".zst") {
		return errors.New("segment archive path is invalid")
	}
	if err := validatePrivateDirectoryChain(s.root, filepath.Dir(cleanPath)); err != nil {
		return err
	}
	if err := ensurePrivateDirectoryChain(s.root, filepath.Dir(cleanTarget)); err != nil {
		return err
	}
	if _, err := os.Lstat(cleanPath); errors.Is(err, os.ErrNotExist) {
		if _, readErr := s.Read(cleanTarget, expectedDigest); readErr != nil {
			return fmt.Errorf("recover archived segment: %w", readErr)
		}
		for _, directory := range []string{filepath.Dir(cleanTarget), filepath.Dir(cleanPath)} {
			if syncErr := syncDirectory(directory); syncErr != nil {
				return syncErr
			}
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect hot segment: %w", err)
	}
	if _, err := os.Lstat(cleanTarget); err == nil {
		return errors.New("cold segment destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect cold segment destination: %w", err)
	}
	if _, err := s.Read(cleanPath, expectedDigest); err != nil {
		return fmt.Errorf("verify hot segment: %w", err)
	}
	if err := os.Rename(cleanPath, cleanTarget); err != nil {
		return fmt.Errorf("archive segment: %w", err)
	}
	for _, directory := range []string{filepath.Dir(cleanTarget), filepath.Dir(cleanPath)} {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open segment directory: %w", err)
	}
	if err = directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync segment directory: %w", err)
	}
	if err = directory.Close(); err != nil {
		return fmt.Errorf("close segment directory: %w", err)
	}
	return nil
}

func validatePrivateDirectoryChain(root, directory string) error {
	root = filepath.Clean(root)
	directory = filepath.Clean(directory)
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("segment directory escapes store")
	}
	candidates := []string{root}
	current := root
	if relative != "." {
		for _, component := range strings.Split(relative, string(os.PathSeparator)) {
			if component == "" || component == "." || component == ".." {
				return errors.New("segment directory path is invalid")
			}
			current = filepath.Join(current, component)
			candidates = append(candidates, current)
		}
	}
	for _, candidate := range candidates {
		info, inspectErr := os.Lstat(candidate)
		if inspectErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("segment directory chain must be private and non-symlinked")
		}
	}
	return nil
}

func ensurePrivateDirectoryChain(root, directory string) error {
	root = filepath.Clean(root)
	directory = filepath.Clean(directory)
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("segment directory path is invalid")
	}
	current := root
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		if component == "" || component == "." || component == ".." {
			return errors.New("segment directory path is invalid")
		}
		current = filepath.Join(current, component)
		info, inspectErr := os.Lstat(current)
		if errors.Is(inspectErr, os.ErrNotExist) {
			if inspectErr = os.Mkdir(current, 0o700); inspectErr != nil && !errors.Is(inspectErr, os.ErrExist) {
				return fmt.Errorf("create segment directory: %w", inspectErr)
			}
			info, inspectErr = os.Lstat(current)
		}
		if inspectErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("segment directory chain must be private and non-symlinked")
		}
	}
	return nil
}

func readRegular(path string, maximum int) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > int64(maximum) {
		return nil, errors.New("segment is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("segment changed during open")
	}
	body, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maximum {
		return nil, errors.New("encoded segment exceeds limit")
	}
	return body, nil
}

// WalkMetadata derives bounded committed-object identities from the filesystem
// so a crash after rename but before control-database bookkeeping cannot hide
// a segment. It deliberately does not read or decode segment contents.
func (s *Store) WalkMetadata(visit func(Metadata) error) error {
	if visit == nil {
		return errors.New("segment metadata visitor is required")
	}
	base := filepath.Join(s.root, "raw")
	if _, err := os.Lstat(base); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect raw segment root: %w", err)
	}
	if err := validatePrivateDirectoryChain(s.root, base); err != nil {
		return err
	}
	err := s.walkMetadataDirectory(base, 0, visit)
	if err != nil {
		return fmt.Errorf("walk raw segments: %w", err)
	}
	return nil
}

func (s *Store) walkMetadataDirectory(directoryPath string, depth int, visit func(Metadata) error) error {
	directory, err := os.Open(directoryPath)
	if err != nil {
		return fmt.Errorf("open raw segment directory: %w", err)
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("raw segment directory must be private")
	}
	for {
		entries, readErr := directory.ReadDir(metadataReadBatch)
		for _, entry := range entries {
			path := filepath.Join(directoryPath, entry.Name())
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("raw segment tree contains a symlink")
			}
			if entry.IsDir() {
				if depth >= 3 {
					return errors.New("raw segment tree has invalid depth")
				}
				if err = s.walkMetadataDirectory(path, depth+1, visit); err != nil {
					return err
				}
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".zst") {
				continue
			}
			metadata, metadataErr := s.metadata(path)
			if metadataErr != nil {
				return metadataErr
			}
			if visitErr := visit(metadata); visitErr != nil {
				return visitErr
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read raw segment directory: %w", readErr)
		}
	}
	if err = directory.Close(); err != nil {
		return fmt.Errorf("close raw segment directory: %w", err)
	}
	return nil
}

func (s *Store) metadata(path string) (Metadata, error) {
	base := filepath.Join(s.root, "raw")
	cleanPath := filepath.Clean(path)
	relative, err := filepath.Rel(base, cleanPath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return Metadata{}, errors.New("segment path escapes raw store")
	}
	pathParts := strings.Split(filepath.ToSlash(relative), "/")
	if len(pathParts) != 4 {
		return Metadata{}, errors.New("raw segment path has invalid depth")
	}
	if err = model.ValidateSourceID(pathParts[0]); err != nil {
		return Metadata{}, errors.New("raw segment organization is invalid")
	}
	if err = model.ValidateSourceID(pathParts[1]); err != nil {
		return Metadata{}, errors.New("raw segment source is invalid")
	}
	if err = model.ValidateStreamID(pathParts[2]); err != nil {
		return Metadata{}, errors.New("raw segment stream is invalid")
	}
	name := strings.TrimSuffix(pathParts[3], ".zst")
	parts := strings.Split(name, "-")
	if len(parts) != 2 || len(parts[0]) != 20 || len(parts[1]) != 64 || strings.ToLower(parts[1]) != parts[1] {
		return Metadata{}, fmt.Errorf("invalid segment filename %q", pathParts[3])
	}
	sequence, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || sequence == 0 {
		return Metadata{}, fmt.Errorf("invalid segment sequence %q", parts[0])
	}
	if _, err = hex.DecodeString(parts[1]); err != nil {
		return Metadata{}, errors.New("segment filename digest is invalid")
	}
	if err = validatePrivateDirectoryChain(s.root, filepath.Dir(cleanPath)); err != nil {
		return Metadata{}, err
	}
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return Metadata{}, fmt.Errorf("inspect raw segment: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > MaxEncodedSegment {
		return Metadata{}, errors.New("raw segment must be a private bounded regular file")
	}
	return Metadata{
		OrganizationID: pathParts[0],
		SourceID:       pathParts[1],
		StreamID:       pathParts[2],
		Sequence:       sequence,
		Path:           cleanPath,
		Digest:         parts[1],
		Compressed:     info.Size(),
	}, nil
}

// List retains the complete decoding API for explicit forensic callers and
// tests. Startup recovery uses WalkMetadata and decodes only missing work.
func (s *Store) List() ([]Entry, error) {
	var entries []Entry
	err := s.WalkMetadata(func(metadata Metadata) error {
		entry, readErr := s.ReadEntry(metadata)
		if readErr != nil {
			return readErr
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Committed.Path < entries[j].Committed.Path })
	return entries, nil
}
