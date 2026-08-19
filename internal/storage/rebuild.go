// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
)

const maxRebuildSegments = 1_000_000

type RebuildReport struct {
	OrganizationID string `json:"organization_id"`
	Segments       int    `json:"segments"`
	Observations   int64  `json:"observations"`
	ActiveVersion  int    `json:"active_projection_version"`
	IndexedRows    int64  `json:"indexed_rows"`
}

type rebuildSegment struct {
	digest string
	path   string
}

// RebuildOrganization reconstructs one disposable organization projection
// from checksummed raw truth beside the live database, then atomically replaces
// it. The caller must hold the data directory's exclusive process lock.
func (s *Store) RebuildOrganization(ctx context.Context, organizationID string, now time.Time) (RebuildReport, error) {
	if err := model.ValidateSourceID(organizationID); err != nil || now.IsZero() {
		return RebuildReport{}, errors.New("projection rebuild input is invalid")
	}
	lock := s.namedLock("organization:" + organizationID)
	lock.Lock()
	defer lock.Unlock()

	dir := filepath.Join(s.root, "organizations", organizationID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return RebuildReport{}, errors.New("create projection rebuild directory")
	}
	live := filepath.Join(dir, "projection.sqlite")
	if err := requireProjectionTarget(live); err != nil {
		return RebuildReport{}, err
	}
	exists, err := s.organizationHasSource(ctx, organizationID)
	if err != nil {
		return RebuildReport{}, err
	}
	if !exists {
		return RebuildReport{}, errors.New("projection rebuild organization has no enrolled sources")
	}
	segments, err := s.rebuildSegments(ctx, organizationID)
	if err != nil {
		return RebuildReport{}, err
	}
	temporary, err := os.CreateTemp(dir, ".projection-rebuild-*.sqlite")
	if err != nil {
		return RebuildReport{}, errors.New("create projection rebuild target")
	}
	stage := temporary.Name()
	if err = temporary.Close(); err != nil {
		_ = os.Remove(stage)
		return RebuildReport{}, errors.New("close projection rebuild target")
	}
	if err = os.Remove(stage); err != nil {
		return RebuildReport{}, errors.New("prepare projection rebuild target")
	}
	defer removeProjectionFiles(stage)

	db, err := openProjection(ctx, stage)
	if err != nil {
		return RebuildReport{}, err
	}
	if err = db.Close(); err != nil {
		return RebuildReport{}, errors.New("close empty projection rebuild target")
	}
	report := RebuildReport{OrganizationID: organizationID, ActiveVersion: 1}
	for _, entry := range segments {
		if err = ctx.Err(); err != nil {
			return RebuildReport{}, err
		}
		batch, readErr := s.segments.Read(entry.path, entry.digest)
		if readErr != nil {
			return RebuildReport{}, fmt.Errorf("read projection rebuild segment: %w", readErr)
		}
		if err = batch.Validate(batch.ObservedAt); err != nil {
			return RebuildReport{}, errors.New("projection rebuild segment is invalid")
		}
		source, sourceErr := s.sourceByID(ctx, batch.SourceID)
		if sourceErr != nil {
			return RebuildReport{}, sourceErr
		}
		if source.Scope.OrganizationID != organizationID {
			return RebuildReport{}, errors.New("projection rebuild segment organization mismatch")
		}
		if err = projectAt(ctx, stage, source.Scope, batch, entry.digest); err != nil {
			return RebuildReport{}, err
		}
		if int64(len(batch.Records)) > math.MaxInt64-report.Observations {
			return RebuildReport{}, errors.New("projection rebuild observation count overflow")
		}
		report.Observations += int64(len(batch.Records))
		report.Segments++
	}
	descriptors, err := s.activatedDescriptors(ctx, organizationID)
	if err != nil {
		return RebuildReport{}, err
	}
	if len(descriptors) > 0 {
		report.ActiveVersion, report.IndexedRows, err = activateRebuiltDescriptors(ctx, stage, descriptors, now)
		if err != nil {
			return RebuildReport{}, err
		}
	}
	if err = finalizeProjection(stage); err != nil {
		return RebuildReport{}, err
	}
	if err = s.closeProjection(organizationID); err != nil {
		return RebuildReport{}, errors.New("close live projection before replacement")
	}
	if err = requireProjectionTarget(live); err != nil {
		return RebuildReport{}, err
	}
	if err = removeProjectionSidecars(live); err != nil {
		return RebuildReport{}, err
	}
	if err = os.Rename(stage, live); err != nil {
		return RebuildReport{}, errors.New("activate rebuilt projection")
	}
	if err = syncProjectionDirectory(dir); err != nil {
		return RebuildReport{}, errors.New("sync rebuilt projection directory")
	}
	return report, nil
}

func (s *Store) organizationHasSource(ctx context.Context, organizationID string) (bool, error) {
	var exists int
	err := s.control.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sources WHERE organization_id=? LIMIT 1)`, organizationID).Scan(&exists)
	if err != nil {
		return false, errors.New("verify projection rebuild organization")
	}
	return exists == 1, nil
}

func (s *Store) rebuildSegments(ctx context.Context, organizationID string) ([]rebuildSegment, error) {
	rows, err := s.control.QueryContext(ctx, `SELECT digest,path FROM segments WHERE organization_id=? AND tier='hot' AND retiring_at IS NULL ORDER BY source_id,stream_id,sequence`, organizationID)
	if err != nil {
		return nil, errors.New("list projection rebuild segments")
	}
	defer rows.Close()
	segments := make([]rebuildSegment, 0)
	for rows.Next() {
		if len(segments) >= maxRebuildSegments {
			return nil, errors.New("projection rebuild segment limit exceeded")
		}
		var entry rebuildSegment
		if err = rows.Scan(&entry.digest, &entry.path); err != nil {
			return nil, errors.New("read projection rebuild segment")
		}
		segments = append(segments, entry)
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New("list projection rebuild segments")
	}
	return segments, nil
}

func (s *Store) activatedDescriptors(ctx context.Context, organizationID string) ([]schema.Descriptor, error) {
	rows, err := s.control.QueryContext(ctx, `SELECT descriptor_json FROM descriptor_proposals WHERE organization_id=? AND status='activated' ORDER BY signal,field`, organizationID)
	if err != nil {
		return nil, errors.New("list activated descriptors for rebuild")
	}
	defer rows.Close()
	descriptors := make([]schema.Descriptor, 0)
	seen := map[string]bool{}
	for rows.Next() {
		if len(descriptors) >= model.MaxDistinctFields {
			return nil, errors.New("activated descriptor rebuild limit exceeded")
		}
		var encoded string
		var descriptor schema.Descriptor
		if err = rows.Scan(&encoded); err != nil || json.Unmarshal([]byte(encoded), &descriptor) != nil || descriptor.Validate() != nil {
			return nil, errors.New("activated descriptor rebuild data is invalid")
		}
		key := string(descriptor.Signal) + ":" + query.CanonicalField(descriptor.Field)
		if seen[key] {
			return nil, errors.New("activated descriptor rebuild data is duplicated")
		}
		seen[key] = true
		descriptor.ProjectionVersion = 2
		descriptors = append(descriptors, descriptor)
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New("list activated descriptors for rebuild")
	}
	sort.Slice(descriptors, func(left, right int) bool {
		if descriptors[left].Signal == descriptors[right].Signal {
			return descriptors[left].Field < descriptors[right].Field
		}
		return descriptors[left].Signal < descriptors[right].Signal
	})
	return descriptors, nil
}

func activateRebuiltDescriptors(ctx context.Context, path string, descriptors []schema.Descriptor, now time.Time) (int, int64, error) {
	db, err := openProjection(ctx, path)
	if err != nil {
		return 0, 0, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, errors.New("begin rebuilt descriptor activation")
	}
	defer tx.Rollback()
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, `INSERT INTO projection_versions(version,created_at,activated_at) VALUES(2,?,?)`, timestamp, timestamp); err != nil {
		return 0, 0, errors.New("create rebuilt projection version")
	}
	for _, descriptor := range descriptors {
		encoded, marshalErr := json.Marshal(descriptor)
		if marshalErr != nil {
			return 0, 0, errors.New("encode rebuilt active descriptor")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO projection_descriptors(version,signal,field,descriptor_json) VALUES(2,?,?,?)`, descriptor.Signal, descriptor.Field, string(encoded)); err != nil {
			return 0, 0, errors.New("store rebuilt active descriptor")
		}
	}
	indexed, err := buildProjectionIndex(ctx, tx, 2, descriptors)
	if err != nil {
		return 0, 0, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE projection_state SET active_version=2 WHERE id=1 AND active_version=1`); err != nil {
		return 0, 0, errors.New("activate rebuilt projection version")
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, errors.New("commit rebuilt descriptor activation")
	}
	return 2, indexed, nil
}

func requireProjectionTarget(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("organization projection must be a regular non-symlink file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect organization projection")
	}
	return nil
}

func removeProjectionSidecars(path string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		sidecar := path + suffix
		info, err := os.Lstat(sidecar)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("projection sidecar is not a regular non-symlink file")
		}
		if err = os.Remove(sidecar); err != nil {
			return errors.New("remove inactive projection sidecar")
		}
	}
	return nil
}

func finalizeProjection(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return errors.New("open rebuilt projection for finalization")
	}
	if _, err = db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err == nil {
		_, err = db.Exec(`PRAGMA journal_mode=DELETE`)
	}
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		return errors.New("finalize rebuilt projection")
	}
	if err = os.Chmod(path, 0o600); err != nil {
		return errors.New("set rebuilt projection mode")
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err = os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			return errors.New("rebuilt projection retained a sidecar")
		}
	}
	return nil
}

func removeProjectionFiles(path string) {
	_ = os.Remove(path)
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
}

func syncProjectionDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
