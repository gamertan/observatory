// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/segment"
	_ "modernc.org/sqlite"
)

const controlSchema = 11

const recoveryPageSize = 128

type Store struct {
	root           string
	control        *sql.DB
	segments       *segment.Store
	locks          sync.Map
	projectionMu   sync.Mutex
	projectorMu    sync.Mutex
	projections    map[string]projectionHandle
	projectionWake chan struct{}
}

type projectionHandle struct {
	db     *sql.DB
	device uint64
	inode  uint64
}

type Source struct {
	ID     string
	Scope  model.Scope
	Active bool
}

type Ack struct {
	SourceID    string `json:"source_id"`
	StreamID    string `json:"stream_id"`
	Sequence    uint64 `json:"sequence"`
	Digest      string `json:"digest"`
	BatchDigest string `json:"batch_digest"`
	Duplicate   bool   `json:"duplicate"`
}

type Enrollment struct {
	SourceID, CreatedByUserID string
	Scope                     model.Scope
	CreatedAt, ExpiresAt      time.Time
}

func Open(root string) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("data root must be an absolute clean path")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create data root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect data root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("data root must be a non-symlink directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("data root must not grant group or other permissions")
	}
	controlPath := filepath.Join(root, "control.sqlite")
	if err := validateSQLiteFileSet(controlPath); err != nil {
		return nil, fmt.Errorf("inspect control database: %w", err)
	}
	db, err := sql.Open("sqlite", controlPath)
	if err != nil {
		return nil, fmt.Errorf("open control database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := migrateControl(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(controlPath, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set control database mode: %w", err)
	}
	segments, err := segment.New(root)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	store := &Store{
		root:           root,
		control:        db,
		segments:       segments,
		projections:    make(map[string]projectionHandle),
		projectionWake: make(chan struct{}, 1),
	}
	if err = store.backfillSegmentRetentionMetadata(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	s.projectionMu.Lock()
	handles := make([]projectionHandle, 0, len(s.projections))
	for organizationID, handle := range s.projections {
		handles = append(handles, handle)
		delete(s.projections, organizationID)
	}
	s.projectionMu.Unlock()
	errs := make([]error, 0, len(handles)+1)
	for _, handle := range handles {
		if err := handle.db.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.control.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// EstimateOrganizationBytes returns a conservative whole-projection scan
// estimate. Query execution will refine this with index and time-window
// statistics; planning never accepts a client-supplied cost estimate.
func (s *Store) EstimateOrganizationBytes(organizationID string) (int64, error) {
	if err := model.ValidateSourceID(organizationID); err != nil {
		return 0, errors.New("invalid organization identifier")
	}
	path := filepath.Join(s.root, "organizations", organizationID, "projection.sqlite")
	var total int64
	for _, candidate := range []string{path, path + "-wal"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("inspect organization projection: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return 0, errors.New("organization projection is not a regular file")
		}
		if info.Size() > math.MaxInt64-total {
			return 0, errors.New("organization projection size overflow")
		}
		total += info.Size()
	}
	return total, nil
}

func migrateControl(db *sql.DB) error {
	statements := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA synchronous=FULL`,
		`PRAGMA busy_timeout=5000`,
		`PRAGMA foreign_keys=ON`,
		`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`,
		`INSERT INTO schema_version(version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version)`,
		`CREATE TABLE IF NOT EXISTS sources (
			id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			environment_id TEXT NOT NULL,
			service_id TEXT NOT NULL,
			credential_digest BLOB NOT NULL UNIQUE,
			active INTEGER NOT NULL CHECK(active IN (0,1)),
			created_at TEXT NOT NULL,
			rotated_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS streams (
			source_id TEXT NOT NULL REFERENCES sources(id),
			stream_id TEXT NOT NULL,
			last_sequence INTEGER NOT NULL,
			last_digest TEXT NOT NULL,
			PRIMARY KEY(source_id, stream_id)
		)`,
		`CREATE TABLE IF NOT EXISTS segments (
			digest TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL,
			source_id TEXT NOT NULL,
			stream_id TEXT NOT NULL,
			sequence INTEGER NOT NULL,
			path TEXT NOT NULL UNIQUE,
			compressed_bytes INTEGER NOT NULL,
			uncompressed_bytes INTEGER NOT NULL,
			committed_at TEXT NOT NULL,
			projected_at TEXT,
			UNIQUE(source_id, stream_id, sequence)
		)`,
		`CREATE TABLE IF NOT EXISTS source_enrollments (
			credential_digest BLOB PRIMARY KEY,
			source_id TEXT NOT NULL UNIQUE,
			organization_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			environment_id TEXT NOT NULL,
			service_id TEXT NOT NULL,
			created_by_user_id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			used_at TEXT
		)`,
		`UPDATE schema_version SET version=2 WHERE version=1`,
		`CREATE TABLE IF NOT EXISTS descriptor_proposals (
			organization_id TEXT NOT NULL,
			signal TEXT NOT NULL,
			field TEXT NOT NULL,
			descriptor_json TEXT NOT NULL,
			observed_values INTEGER NOT NULL CHECK(observed_values > 0),
			estimated_bytes INTEGER NOT NULL CHECK(estimated_bytes >= 0),
			example_queries_json TEXT NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('pending','activated','rejected')),
			first_seen_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL,
			PRIMARY KEY(organization_id,signal,field)
		)`,
		`CREATE TABLE IF NOT EXISTS descriptor_proposal_segments (
			segment_digest TEXT NOT NULL,
			organization_id TEXT NOT NULL,
			signal TEXT NOT NULL,
			field TEXT NOT NULL,
			observed_values INTEGER NOT NULL CHECK(observed_values > 0),
			estimated_bytes INTEGER NOT NULL CHECK(estimated_bytes >= 0),
			PRIMARY KEY(segment_digest,organization_id,field)
		)`,
		`UPDATE schema_version SET version=3 WHERE version=2`,
		`CREATE TABLE IF NOT EXISTS saved_queries (
			organization_id TEXT NOT NULL,
			id TEXT NOT NULL,
			version INTEGER NOT NULL CHECK(version=1),
			revision INTEGER NOT NULL CHECK(revision >= 1),
			name TEXT NOT NULL,
			description TEXT NOT NULL,
			query_text TEXT NOT NULL,
			ast_json TEXT NOT NULL,
			project_id TEXT NOT NULL,
			environment_id TEXT NOT NULL,
			service_id TEXT NOT NULL,
			created_by TEXT NOT NULL,
			updated_by TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(organization_id,id),
			UNIQUE(organization_id,name)
		)`,
		`CREATE TABLE IF NOT EXISTS dashboards (
			organization_id TEXT NOT NULL,
			id TEXT NOT NULL,
			version INTEGER NOT NULL CHECK(version=1),
			revision INTEGER NOT NULL CHECK(revision >= 1),
			slug TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT NOT NULL,
			created_by TEXT NOT NULL,
			updated_by TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(organization_id,id),
			UNIQUE(organization_id,slug)
		)`,
		`CREATE TABLE IF NOT EXISTS dashboard_panels (
			organization_id TEXT NOT NULL,
			dashboard_id TEXT NOT NULL,
			id TEXT NOT NULL,
			position INTEGER NOT NULL CHECK(position >= 0 AND position < 64),
			title TEXT NOT NULL,
			visualization TEXT NOT NULL CHECK(visualization IN ('table','stat','timeseries')),
			saved_query_id TEXT NOT NULL,
			PRIMARY KEY(organization_id,dashboard_id,id),
			UNIQUE(organization_id,dashboard_id,position),
			FOREIGN KEY(organization_id,dashboard_id) REFERENCES dashboards(organization_id,id) ON DELETE CASCADE,
			FOREIGN KEY(organization_id,saved_query_id) REFERENCES saved_queries(organization_id,id) ON DELETE RESTRICT
		)`,
		`UPDATE schema_version SET version=4 WHERE version=3`,
		`CREATE TABLE IF NOT EXISTS alert_rules (
			organization_id TEXT NOT NULL,
			id TEXT NOT NULL,
			version INTEGER NOT NULL CHECK(version=1),
			revision INTEGER NOT NULL CHECK(revision >= 1),
			name TEXT NOT NULL,
			description TEXT NOT NULL,
			saved_query_id TEXT NOT NULL,
			severity TEXT NOT NULL CHECK(severity IN ('information','warning','critical')),
			minimum_matches INTEGER NOT NULL CHECK(minimum_matches BETWEEN 1 AND 100000),
			required_consecutive INTEGER NOT NULL CHECK(required_consecutive BETWEEN 1 AND 10),
			evaluation_interval_seconds INTEGER NOT NULL CHECK(evaluation_interval_seconds BETWEEN 15 AND 86400),
			enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
			last_evaluated_at TEXT,
			next_evaluation_at TEXT NOT NULL,
			last_result INTEGER,
			last_error TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL,
			updated_by TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(organization_id,id),
			UNIQUE(organization_id,name),
			FOREIGN KEY(organization_id,saved_query_id) REFERENCES saved_queries(organization_id,id) ON DELETE RESTRICT
		)`,
		`CREATE INDEX IF NOT EXISTS alert_rules_due ON alert_rules(enabled,next_evaluation_at,organization_id,id)`,
		`CREATE TABLE IF NOT EXISTS incidents (
			organization_id TEXT NOT NULL,
			id TEXT NOT NULL,
			version INTEGER NOT NULL CHECK(version=1),
			rule_id TEXT NOT NULL,
			state TEXT NOT NULL CHECK(state IN ('pending','firing','acknowledged','silenced','resolved')),
			severity TEXT NOT NULL CHECK(severity IN ('information','warning','critical')),
			title TEXT NOT NULL,
			consecutive_matches INTEGER NOT NULL CHECK(consecutive_matches >= 0),
			started_at TEXT NOT NULL,
			last_observed_at TEXT NOT NULL,
			acknowledged_by TEXT,
			acknowledged_at TEXT,
			silenced_by TEXT,
			silenced_until TEXT,
			resolved_at TEXT,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(organization_id,id),
			FOREIGN KEY(organization_id,rule_id) REFERENCES alert_rules(organization_id,id) ON DELETE RESTRICT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS one_open_incident_per_rule ON incidents(organization_id,rule_id) WHERE state!='resolved'`,
		`CREATE INDEX IF NOT EXISTS incidents_by_state ON incidents(organization_id,state,updated_at DESC,id)`,
		`CREATE TABLE IF NOT EXISTS incident_events (
			organization_id TEXT NOT NULL,
			incident_id TEXT NOT NULL,
			sequence INTEGER NOT NULL CHECK(sequence >= 1),
			event TEXT NOT NULL CHECK(event IN ('opened','promoted','acknowledged','silenced','unsilenced','resolved')),
			actor TEXT NOT NULL,
			created_at TEXT NOT NULL,
			PRIMARY KEY(organization_id,incident_id,sequence),
			FOREIGN KEY(organization_id,incident_id) REFERENCES incidents(organization_id,id) ON DELETE CASCADE
		)`,
		`UPDATE schema_version SET version=5 WHERE version=4`,
		`CREATE TABLE IF NOT EXISTS push_endpoints (
			id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			endpoint_digest BLOB NOT NULL UNIQUE,
			p256dh BLOB NOT NULL,
			auth_secret BLOB NOT NULL,
			active INTEGER NOT NULL CHECK(active IN (0,1)),
			failure_count INTEGER NOT NULL CHECK(failure_count >= 0),
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_sent_at TEXT,
			PRIMARY KEY(id)
		)`,
		`CREATE TABLE IF NOT EXISTS push_subscriptions (
			organization_id TEXT NOT NULL,
			id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			endpoint_id TEXT NOT NULL REFERENCES push_endpoints(id) ON DELETE CASCADE,
			created_at TEXT NOT NULL,
			PRIMARY KEY(organization_id,id),
			UNIQUE(organization_id,user_id,endpoint_id)
		)`,
		`CREATE INDEX IF NOT EXISTS push_subscriptions_by_organization ON push_subscriptions(organization_id,user_id,id)`,
		`CREATE INDEX IF NOT EXISTS push_subscriptions_by_endpoint ON push_subscriptions(endpoint_id,organization_id,id)`,
		`UPDATE schema_version SET version=6 WHERE version=5`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("migrate control database: %w", err)
		}
	}
	var version int
	if err := db.QueryRow(`SELECT version FROM schema_version`).Scan(&version); err != nil {
		return fmt.Errorf("read control schema: %w", err)
	}
	if version == 6 {
		if err := migrateControlRetention(db); err != nil {
			return err
		}
		version = 7
	}
	if version == 7 {
		if err := migrateControlForensicRetention(db); err != nil {
			return err
		}
		version = 8
	}
	if version == 8 {
		if err := migrateControlSourceAlertTransitions(db); err != nil {
			return err
		}
		version = 9
	}
	if version == 9 {
		if err := migrateControlBatchMetadata(db); err != nil {
			return err
		}
		version = 10
	}
	if version == 10 {
		if err := migrateControlBatchEnvelopes(db); err != nil {
			return err
		}
		version = 11
	}
	if version != controlSchema {
		return fmt.Errorf("unsupported control schema %d", version)
	}
	return nil
}

func (s *Store) CreateSource(ctx context.Context, id string, scope model.Scope) (string, error) {
	if err := scope.Validate(); err != nil {
		return "", err
	}
	if err := model.ValidateSourceID(id); err != nil {
		return "", err
	}
	token, err := sourceCredential(id)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(token))
	_, err = s.control.ExecContext(ctx, `INSERT INTO sources(id, organization_id, project_id, environment_id, service_id, credential_digest, active, created_at) VALUES(?,?,?,?,?,?,1,?)`, id, scope.OrganizationID, scope.ProjectID, scope.EnvironmentID, scope.ServiceID, digest[:], time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return "", fmt.Errorf("create source: %w", err)
	}
	return token, nil
}

func (s *Store) CreateEnrollment(ctx context.Context, id string, scope model.Scope, createdBy string, lifetime time.Duration, now time.Time) (string, Enrollment, error) {
	if err := model.ValidateSourceID(id); err != nil {
		return "", Enrollment{}, err
	}
	if err := scope.Validate(); err != nil {
		return "", Enrollment{}, err
	}
	if err := model.ValidateSourceID(createdBy); err != nil || lifetime < 5*time.Minute || lifetime > 24*time.Hour || now.IsZero() {
		return "", Enrollment{}, errors.New("invalid source enrollment")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", Enrollment{}, errors.New("cryptographic randomness unavailable")
	}
	token := "obse1." + hex.EncodeToString(secret)
	digest := sha256.Sum256([]byte(token))
	enrollment := Enrollment{SourceID: id, Scope: scope, CreatedByUserID: createdBy, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(lifetime)}
	_, err := s.control.ExecContext(ctx, `INSERT INTO source_enrollments(credential_digest,source_id,organization_id,project_id,environment_id,service_id,created_by_user_id,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)`, digest[:], id, scope.OrganizationID, scope.ProjectID, scope.EnvironmentID, scope.ServiceID, createdBy, enrollment.CreatedAt.Format(time.RFC3339Nano), enrollment.ExpiresAt.Format(time.RFC3339Nano))
	if err != nil {
		return "", Enrollment{}, fmt.Errorf("create source enrollment: %w", err)
	}
	return token, enrollment, nil
}

func (s *Store) RedeemEnrollment(ctx context.Context, token string, now time.Time) (Enrollment, string, error) {
	if len(token) != len("obse1.")+64 || !strings.HasPrefix(token, "obse1.") || strings.ContainsAny(token, " \t\r\n") || now.IsZero() {
		return Enrollment{}, "", errors.New("invalid or expired source enrollment")
	}
	digest := sha256.Sum256([]byte(token))
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, "", err
	}
	defer tx.Rollback()
	var enrollment Enrollment
	var created, expires string
	err = tx.QueryRowContext(ctx, `SELECT source_id,organization_id,project_id,environment_id,service_id,created_by_user_id,created_at,expires_at FROM source_enrollments WHERE credential_digest=? AND used_at IS NULL`, digest[:]).Scan(&enrollment.SourceID, &enrollment.Scope.OrganizationID, &enrollment.Scope.ProjectID, &enrollment.Scope.EnvironmentID, &enrollment.Scope.ServiceID, &enrollment.CreatedByUserID, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, "", errors.New("invalid or expired source enrollment")
	}
	if err != nil {
		return Enrollment{}, "", err
	}
	enrollment.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return Enrollment{}, "", errors.New("stored source enrollment is invalid")
	}
	enrollment.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return Enrollment{}, "", errors.New("stored source enrollment is invalid")
	}
	if !now.UTC().Before(enrollment.ExpiresAt) {
		return Enrollment{}, "", errors.New("invalid or expired source enrollment")
	}
	credential, err := sourceCredential(enrollment.SourceID)
	if err != nil {
		return Enrollment{}, "", err
	}
	credentialDigest := sha256.Sum256([]byte(credential))
	if _, err = tx.ExecContext(ctx, `INSERT INTO sources(id,organization_id,project_id,environment_id,service_id,credential_digest,active,created_at) VALUES(?,?,?,?,?,?,1,?)`, enrollment.SourceID, enrollment.Scope.OrganizationID, enrollment.Scope.ProjectID, enrollment.Scope.EnvironmentID, enrollment.Scope.ServiceID, credentialDigest[:], now.UTC().Format(time.RFC3339Nano)); err != nil {
		return Enrollment{}, "", errors.New("source enrollment failed")
	}
	result, err := tx.ExecContext(ctx, `UPDATE source_enrollments SET used_at=? WHERE credential_digest=? AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano), digest[:])
	if err != nil {
		return Enrollment{}, "", err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return Enrollment{}, "", errors.New("invalid or expired source enrollment")
	}
	if err = tx.Commit(); err != nil {
		return Enrollment{}, "", err
	}
	return enrollment, credential, nil
}

func (s *Store) CancelEnrollment(ctx context.Context, token string) error {
	if len(token) != len("obse1.")+64 || !strings.HasPrefix(token, "obse1.") || strings.ContainsAny(token, " \t\r\n") {
		return errors.New("invalid source enrollment")
	}
	digest := sha256.Sum256([]byte(token))
	result, err := s.control.ExecContext(ctx, `DELETE FROM source_enrollments WHERE credential_digest=? AND used_at IS NULL`, digest[:])
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("source enrollment not found")
	}
	return nil
}

func sourceCredential(id string) (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", errors.New("cryptographic randomness unavailable")
	}
	return "obs1." + id + "." + hex.EncodeToString(secret), nil
}

func (s *Store) Authenticate(ctx context.Context, token string) (Source, error) {
	if len(token) < 48 || len(token) > 512 || !strings.HasPrefix(token, "obs1.") {
		return Source{}, errors.New("invalid source credential")
	}
	digest := sha256.Sum256([]byte(token))
	var source Source
	var active int
	err := s.control.QueryRowContext(ctx, `SELECT id, organization_id, project_id, environment_id, service_id, active FROM sources WHERE credential_digest = ?`, digest[:]).Scan(&source.ID, &source.Scope.OrganizationID, &source.Scope.ProjectID, &source.Scope.EnvironmentID, &source.Scope.ServiceID, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return Source{}, errors.New("invalid source credential")
	}
	if err != nil {
		return Source{}, fmt.Errorf("authenticate source: %w", err)
	}
	source.Active = active == 1
	if !source.Active {
		return Source{}, errors.New("source credential revoked")
	}
	return source, nil
}

func (s *Store) RevokeSource(ctx context.Context, id string) error {
	result, err := s.control.ExecContext(ctx, `UPDATE sources SET active=0, rotated_at=? WHERE id=? AND active=1`, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("revoke source: %w", err)
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("active source not found")
	}
	return nil
}

func (s *Store) Ingest(ctx context.Context, token string, batch model.Batch, now time.Time) (Ack, error) {
	source, err := s.Authenticate(ctx, token)
	if err != nil {
		return Ack{}, err
	}
	if batch.SourceID != source.ID {
		return Ack{}, errors.New("batch source does not match credential")
	}
	lock := s.sourceLock(source.ID)
	lock.Lock()
	defer lock.Unlock()
	return s.ingestAuthenticated(ctx, source, batch, nil, now)
}

// IngestNative validates the exact encoded request against its transport
// envelope before committing a new batch. A concurrently acknowledged exact
// replay is returned without recompressing or rewriting raw evidence.
func (s *Store) IngestNative(ctx context.Context, token string, batch model.Batch, envelope model.BatchEnvelope, encoded []byte, now time.Time) (Ack, error) {
	if err := envelope.Match(batch, encoded); err != nil {
		return Ack{}, err
	}
	source, err := s.Authenticate(ctx, token)
	if err != nil {
		return Ack{}, err
	}
	if batch.SourceID != source.ID {
		return Ack{}, errors.New("batch source does not match credential")
	}
	lock := s.sourceLock(source.ID)
	lock.Lock()
	defer lock.Unlock()
	if ack, exact, checkErr := s.checkEnvelope(ctx, source, envelope); checkErr != nil {
		return Ack{}, checkErr
	} else if exact {
		return ack, nil
	}
	return s.ingestAuthenticated(ctx, source, batch, &envelope, now)
}

func (s *Store) IngestAuto(ctx context.Context, token, streamID string, signal model.Signal, records []model.Observation, now time.Time) (Ack, error) {
	source, err := s.Authenticate(ctx, token)
	if err != nil {
		return Ack{}, err
	}
	if err = model.ValidateStreamID(streamID); err != nil {
		return Ack{}, err
	}
	lock := s.sourceLock(source.ID)
	lock.Lock()
	defer lock.Unlock()
	lastSequence, _, found, err := s.watermark(ctx, source.ID, streamID)
	if err != nil {
		return Ack{}, err
	}
	if lastSequence == ^uint64(0) {
		return Ack{}, errors.New("stream sequence exhausted")
	}
	sequence := uint64(1)
	if found {
		sequence = lastSequence + 1
	}
	if len(records) == 0 {
		return Ack{}, errors.New("automatic ingestion requires records")
	}
	// Derive the batch observation time from its records so a retry of the
	// same OTLP payload produces the same content-addressed segment even if a
	// prior attempt stopped after the atomic raw commit.
	observedAt := records[0].Timestamp
	for _, record := range records[1:] {
		if record.Timestamp.After(observedAt) {
			observedAt = record.Timestamp
		}
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: source.ID, StreamID: streamID, Sequence: sequence, ObservedAt: observedAt.UTC(), Signal: signal, Records: records}
	return s.ingestAuthenticated(ctx, source, batch, nil, now)
}

func (s *Store) sourceLock(sourceID string) *sync.Mutex {
	return s.namedLock("source:" + sourceID)
}

func (s *Store) ingestAuthenticated(ctx context.Context, source Source, batch model.Batch, envelope *model.BatchEnvelope, now time.Time) (Ack, error) {
	if err := batch.Validate(now); err != nil {
		return Ack{}, err
	}
	batchDigest, err := batch.Digest()
	if err != nil {
		return Ack{}, err
	}
	if err := validateMetricRollupCardinality(batch); err != nil {
		return Ack{}, err
	}
	lastSequence, lastDigest, found, err := s.watermark(ctx, source.ID, batch.StreamID)
	if err != nil {
		return Ack{}, err
	}
	if found && batch.Sequence < lastSequence {
		return Ack{}, errors.New("sequence replay is older than acknowledged watermark")
	}
	if (!found && batch.Sequence != 1) || (found && batch.Sequence > lastSequence+1) {
		return Ack{}, errors.New("sequence gap")
	}
	committed, err := s.segments.Commit(source.Scope, batch)
	if err != nil {
		return Ack{}, err
	}
	if found && batch.Sequence == lastSequence {
		if committed.Digest != lastDigest {
			if deleteErr := s.segments.Delete(committed.Path, committed.Digest); deleteErr != nil {
				return Ack{}, fmt.Errorf("acknowledged sequence reused with different content; remove rejected raw object: %w", deleteErr)
			}
			return Ack{}, errors.New("acknowledged sequence reused with different content")
		}
		if envelope != nil {
			if err = s.backfillAcknowledgedEnvelope(ctx, batch, committed.Digest, *envelope); err != nil {
				return Ack{}, err
			}
		}
		return Ack{SourceID: source.ID, StreamID: batch.StreamID, Sequence: batch.Sequence, Digest: committed.Digest, BatchDigest: batchDigest, Duplicate: true}, nil
	}
	if err := s.admitCommittedEnvelope(ctx, source.Scope, batch, committed, envelope, now); err != nil {
		return Ack{}, err
	}
	s.notifyProjector()
	return Ack{SourceID: source.ID, StreamID: batch.StreamID, Sequence: batch.Sequence, Digest: committed.Digest, BatchDigest: batchDigest}, nil
}

func (s *Store) notifyProjector() {
	select {
	case s.projectionWake <- struct{}{}:
	default:
	}
}

func (s *Store) watermark(ctx context.Context, sourceID, streamID string) (uint64, string, bool, error) {
	var sequence uint64
	var digest string
	err := s.control.QueryRowContext(ctx, `SELECT last_sequence, last_digest FROM streams WHERE source_id=? AND stream_id=?`, sourceID, streamID).Scan(&sequence, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, fmt.Errorf("read stream watermark: %w", err)
	}
	return sequence, digest, true, nil
}

func (s *Store) recordCommitted(ctx context.Context, scope model.Scope, batch model.Batch, committed segment.Committed) error {
	return s.recordCommittedAt(ctx, scope, batch, committed, time.Now().UTC())
}

func (s *Store) recordCommittedAt(ctx context.Context, scope model.Scope, batch model.Batch, committed segment.Committed, committedAt time.Time) error {
	return s.recordCommittedAtEnvelope(ctx, scope, batch, committed, nil, committedAt)
}

func (s *Store) recordCommittedAtEnvelope(ctx context.Context, scope model.Scope, batch model.Batch, committed segment.Committed, envelope *model.BatchEnvelope, committedAt time.Time) error {
	if committedAt.IsZero() {
		return errors.New("committed segment time is required")
	}
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin committed segment record: %w", err)
	}
	defer tx.Rollback()
	if err = recordCommittedTx(ctx, tx, scope, batch, committed, committedAt); err != nil {
		return err
	}
	if err = advanceStreamTx(ctx, tx, batch, committed.Digest, envelope); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit segment record: %w", err)
	}
	return nil
}

func recordCommittedTx(ctx context.Context, tx *sql.Tx, scope model.Scope, batch model.Batch, committed segment.Committed, committedAt time.Time) error {
	first, last := observationRange(batch)
	_, err := tx.ExecContext(ctx, `INSERT INTO segments(digest, organization_id, source_id, stream_id, sequence, path, compressed_bytes, uncompressed_bytes, committed_at, signal, first_observed_at, last_observed_at, record_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, committed.Digest, scope.OrganizationID, batch.SourceID, batch.StreamID, batch.Sequence, committed.Path, committed.Compressed, committed.Uncompressed, committedAt.UTC().Format(time.RFC3339Nano), batch.Signal, first.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano), len(batch.Records))
	if err != nil {
		return fmt.Errorf("record committed segment: %w", err)
	}
	return nil
}

func observationRange(batch model.Batch) (time.Time, time.Time) {
	first, last := batch.Records[0].Timestamp.UTC(), batch.Records[0].Timestamp.UTC()
	for _, observation := range batch.Records[1:] {
		timestamp := observation.Timestamp.UTC()
		if timestamp.Before(first) {
			first = timestamp
		}
		if timestamp.After(last) {
			last = timestamp
		}
	}
	return first, last
}

func (s *Store) project(ctx context.Context, scope model.Scope, batch model.Batch, digest string) error {
	lock := s.namedLock("organization:" + scope.OrganizationID)
	lock.Lock()
	defer lock.Unlock()

	db, err := s.projection(ctx, scope.OrganizationID)
	if err != nil {
		return err
	}
	return projectWithDB(ctx, db, scope, batch, digest)
}

func projectAt(ctx context.Context, path string, scope model.Scope, batch model.Batch, digest string) error {
	db, err := openProjection(ctx, path)
	if err != nil {
		return err
	}
	defer db.Close()
	return projectWithDB(ctx, db, scope, batch, digest)
}

type projectionItem struct {
	scope  model.Scope
	batch  model.Batch
	digest string
}

func projectWithDB(ctx context.Context, db *sql.DB, scope model.Scope, batch model.Batch, digest string) error {
	return projectGroupWithDB(ctx, db, []projectionItem{{scope: scope, batch: batch, digest: digest}})
}

func projectGroupWithDB(ctx context.Context, db *sql.DB, items []projectionItem) error {
	if len(items) == 0 {
		return errors.New("projection group is empty")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin projection: %w", err)
	}
	defer tx.Rollback()
	activeVersion, activeRegistry, activeDescriptors, err := activeProjection(ctx, tx)
	if err != nil {
		return err
	}
	insert, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO observations(organization_id, project_id, environment_id, service_id, source_id, stream_id, sequence, record_index, signal, timestamp, name, severity, body, value, trace_id, span_id, correlation_id, attributes_json, segment_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("prepare observation projection: %w", err)
	}
	defer insert.Close()
	for _, item := range items {
		batch, scope, digest := item.batch, item.scope, item.digest
		var observationBytes []int64
		if batch.Signal == model.SignalLogs {
			observationBytes = make([]int64, 0, len(batch.Records))
		}
		for index, observation := range batch.Records {
			attributes, marshalErr := json.Marshal(observation.Attributes)
			if marshalErr != nil {
				return fmt.Errorf("encode observation attributes: %w", marshalErr)
			}
			_, execErr := insert.ExecContext(ctx, scope.OrganizationID, scope.ProjectID, scope.EnvironmentID, scope.ServiceID, batch.SourceID, batch.StreamID, batch.Sequence, index, batch.Signal, observation.Timestamp.UTC().Format(time.RFC3339Nano), observation.Name, observation.Severity, observation.Body, observation.Value, observation.TraceID, observation.SpanID, observation.CorrelationID, string(attributes), digest)
			if execErr != nil {
				return fmt.Errorf("project observation: %w", execErr)
			}
			if err = indexProjectedObservation(ctx, tx, activeVersion, activeDescriptors, batch, index, observation); err != nil {
				return err
			}
			if batch.Signal == model.SignalLogs {
				observationBytes = append(observationBytes, projectedObservationBytes(scope, batch, observation, len(attributes)))
			}
		}
		if err = projectMetricRollups(ctx, tx, scope, batch, digest, activeRegistry); err != nil {
			return err
		}
		if err = projectLogRollups(ctx, tx, scope, batch, digest, observationBytes); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit projection: %w", err)
	}
	return nil
}

func (s *Store) projection(ctx context.Context, organizationID string) (*sql.DB, error) {
	path := filepath.Join(s.root, "organizations", organizationID, "projection.sqlite")
	s.projectionMu.Lock()
	handle, exists := s.projections[organizationID]
	s.projectionMu.Unlock()
	if exists {
		device, inode, err := projectionIdentity(path)
		if err != nil || device != handle.device || inode != handle.inode {
			return nil, errors.New("organization projection identity changed")
		}
		return handle.db, nil
	}
	db, err := openProjection(ctx, path)
	if err != nil {
		return nil, err
	}
	device, inode, err := projectionIdentity(path)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	s.projectionMu.Lock()
	s.projections[organizationID] = projectionHandle{db: db, device: device, inode: inode}
	s.projectionMu.Unlock()
	return db, nil
}

func (s *Store) closeProjection(organizationID string) error {
	s.projectionMu.Lock()
	handle, exists := s.projections[organizationID]
	if exists {
		delete(s.projections, organizationID)
	}
	s.projectionMu.Unlock()
	if !exists {
		return nil
	}
	return handle.db.Close()
}

func projectionIdentity(path string) (uint64, uint64, error) {
	if err := validateSQLiteFileSet(path); err != nil {
		return 0, 0, fmt.Errorf("inspect organization projection: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return 0, 0, errors.New("organization projection must be a regular non-symlink file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return 0, 0, errors.New("organization projection identity is unavailable")
	}
	return uint64(stat.Dev), uint64(stat.Ino), nil
}

func openProjection(ctx context.Context, path string) (*sql.DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create organization store: %w", err)
	}
	for _, directory := range []string{filepath.Dir(dir), dir} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("organization store path must contain private non-symlink directories")
		}
	}
	if err := validateSQLiteFileSet(path); err != nil {
		return nil, fmt.Errorf("inspect organization projection: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open organization projection: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode=WAL`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure organization projection: %w", err)
	}
	for _, statement := range []string{`PRAGMA synchronous=FULL`, `PRAGMA busy_timeout=5000`, `PRAGMA foreign_keys=ON`} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("configure organization projection: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS observations (
		organization_id TEXT NOT NULL,
		project_id TEXT NOT NULL,
		environment_id TEXT NOT NULL,
		service_id TEXT NOT NULL,
		source_id TEXT NOT NULL,
		stream_id TEXT NOT NULL,
		sequence INTEGER NOT NULL,
		record_index INTEGER NOT NULL,
		signal TEXT NOT NULL,
		timestamp TEXT NOT NULL,
		name TEXT NOT NULL,
		severity TEXT,
		body TEXT,
		value REAL,
		trace_id TEXT,
		span_id TEXT,
		correlation_id TEXT,
		attributes_json TEXT NOT NULL,
		segment_digest TEXT NOT NULL,
		PRIMARY KEY(source_id, stream_id, sequence, record_index)
	)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate organization projection: %w", err)
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS observations_signal_time ON observations(signal,timestamp)`,
		`CREATE INDEX IF NOT EXISTS observations_scope ON observations(project_id,environment_id,service_id,signal,timestamp)`,
		`CREATE INDEX IF NOT EXISTS observations_environment ON observations(environment_id,signal,timestamp)`,
		`CREATE INDEX IF NOT EXISTS observations_service ON observations(service_id,signal,timestamp)`,
		`CREATE INDEX IF NOT EXISTS observations_name ON observations(signal,name,timestamp)`,
		`CREATE INDEX IF NOT EXISTS observations_severity ON observations(signal,severity,timestamp)`,
		`CREATE INDEX IF NOT EXISTS observations_trace ON observations(trace_id) WHERE trace_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS observations_span ON observations(span_id) WHERE span_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS observations_correlation ON observations(correlation_id) WHERE correlation_id IS NOT NULL`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("index organization projection: %w", err)
		}
	}
	if err := ensureProjectionMetadata(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureMetricRollups(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureBaseIndexes(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureLogRollups(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set organization database mode: %w", err)
	}
	return db, nil
}

func validateSQLiteFileSet(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("SQLite file must be a regular non-symlink file")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 {
			return errors.New("SQLite file must not have additional hard links")
		}
	}
	return nil
}

func (s *Store) markProjected(ctx context.Context, batch model.Batch, digest string) error {
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin acknowledgement: %w", err)
	}
	defer tx.Rollback()
	if err = markProjectedTx(ctx, tx, batch, digest, time.Now().UTC()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit acknowledgement: %w", err)
	}
	return nil
}

func markProjectedTx(ctx context.Context, tx *sql.Tx, batch model.Batch, digest string, projectedAt time.Time) error {
	result, err := tx.ExecContext(ctx, `UPDATE segments SET projected_at=? WHERE digest=? AND projected_at IS NULL`, projectedAt.UTC().Format(time.RFC3339Nano), digest)
	if err != nil {
		return fmt.Errorf("mark segment projected: %w", err)
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("committed segment state changed before acknowledgement")
	}
	return nil
}

func advanceStreamTx(ctx context.Context, tx *sql.Tx, batch model.Batch, digest string, envelope *model.BatchEnvelope) error {
	var lastSequence uint64
	var lastDigest string
	err := tx.QueryRowContext(ctx, `SELECT last_sequence,last_digest FROM streams WHERE source_id=? AND stream_id=?`, batch.SourceID, batch.StreamID).Scan(&lastSequence, &lastDigest)
	if errors.Is(err, sql.ErrNoRows) {
		if batch.Sequence != 1 {
			return errors.New("sequence gap while accepting committed segment")
		}
	} else if err != nil {
		return fmt.Errorf("read stream watermark while accepting committed segment: %w", err)
	} else {
		if batch.Sequence == lastSequence && digest == lastDigest {
			return nil
		}
		if lastSequence == ^uint64(0) || batch.Sequence != lastSequence+1 {
			return errors.New("sequence gap while accepting committed segment")
		}
	}
	batchDigest, wireDigest, signal, recordCount, encodedBytes, first, last := envelopeSQL(envelope)
	_, err = tx.ExecContext(ctx, `INSERT INTO streams(source_id,stream_id,last_sequence,last_digest,last_batch_digest,last_wire_digest,last_signal,last_record_count,last_encoded_bytes,last_first_observed_at,last_last_observed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source_id,stream_id) DO UPDATE SET last_sequence=excluded.last_sequence,last_digest=excluded.last_digest,last_batch_digest=excluded.last_batch_digest,last_wire_digest=excluded.last_wire_digest,last_signal=excluded.last_signal,last_record_count=excluded.last_record_count,last_encoded_bytes=excluded.last_encoded_bytes,last_first_observed_at=excluded.last_first_observed_at,last_last_observed_at=excluded.last_last_observed_at`, batch.SourceID, batch.StreamID, batch.Sequence, digest, batchDigest, wireDigest, signal, recordCount, encodedBytes, first, last)
	if err != nil {
		return fmt.Errorf("advance stream watermark: %w", err)
	}
	return nil
}

// RecoverRaw reconciles immutable raw objects with the control catalog. It
// deliberately does not project telemetry, so a large projection backlog
// cannot delay server readiness.
func (s *Store) RecoverRaw(ctx context.Context) error {
	if err := s.finishInterruptedArchival(ctx); err != nil {
		return err
	}
	if err := s.finishInterruptedRetention(ctx); err != nil {
		return err
	}
	lookup, err := s.control.PrepareContext(ctx, `SELECT organization_id,source_id,stream_id,sequence,path,compressed_bytes,tier FROM segments WHERE digest=?`)
	if err != nil {
		return fmt.Errorf("prepare recovered segment lookup: %w", err)
	}
	var missing []segment.Metadata
	walkErr := s.segments.WalkMetadata(func(metadata segment.Metadata) error {
		var catalog segment.Metadata
		var tier string
		catalog.Digest = metadata.Digest
		lookupErr := lookup.QueryRowContext(ctx, metadata.Digest).Scan(&catalog.OrganizationID, &catalog.SourceID, &catalog.StreamID, &catalog.Sequence, &catalog.Path, &catalog.Compressed, &tier)
		if lookupErr == nil {
			if tier != "hot" || catalog != metadata {
				return errors.New("catalogued segment metadata does not match raw object")
			}
			return nil
		}
		if !errors.Is(lookupErr, sql.ErrNoRows) {
			return fmt.Errorf("inspect recovered segment: %w", lookupErr)
		}
		missing = append(missing, metadata)
		return nil
	})
	if closeErr := lookup.Close(); walkErr == nil && closeErr != nil {
		walkErr = fmt.Errorf("close recovered segment lookup: %w", closeErr)
	}
	if walkErr != nil {
		return walkErr
	}
	sort.Slice(missing, func(i, j int) bool {
		left, right := missing[i], missing[j]
		if left.SourceID != right.SourceID {
			return left.SourceID < right.SourceID
		}
		if left.StreamID != right.StreamID {
			return left.StreamID < right.StreamID
		}
		return left.Sequence < right.Sequence
	})
	for _, metadata := range missing {
		entry, readErr := s.segments.ReadEntry(metadata)
		if readErr != nil {
			return readErr
		}
		source, sourceErr := s.sourceByID(ctx, entry.Batch.SourceID)
		if sourceErr != nil {
			return sourceErr
		}
		if validateErr := entry.Batch.Validate(entry.Batch.ObservedAt); validateErr != nil {
			return fmt.Errorf("validate recovered segment: %w", validateErr)
		}
		if validateErr := validateMetricRollupCardinality(entry.Batch); validateErr != nil {
			return fmt.Errorf("validate recovered metric segment: %w", validateErr)
		}
		if source.Scope.OrganizationID != entry.OrganizationID {
			return errors.New("recovered segment organization does not match enrolled source")
		}
		if admitErr := s.admitCommitted(ctx, source.Scope, entry.Batch, entry.Committed, time.Now().UTC()); admitErr != nil {
			if errors.Is(admitErr, ErrOrganizationStorageQuotaExceeded) {
				continue
			}
			return admitErr
		}
		s.notifyProjector()
	}
	return nil
}

// Recover performs full offline recovery. The server uses RecoverRaw and a
// background projector; check and migration commands retain this blocking
// form so they can prove every durable segment is queryable before returning.
func (s *Store) Recover(ctx context.Context) error {
	if err := s.RecoverRaw(ctx); err != nil {
		return err
	}
	for {
		report, err := s.ProjectPending(ctx)
		if err != nil {
			return err
		}
		if report.ProjectedSegments == 0 {
			return nil
		}
	}
}

func (s *Store) sourceByID(ctx context.Context, id string) (Source, error) {
	var source Source
	var active int
	err := s.control.QueryRowContext(ctx, `SELECT id, organization_id, project_id, environment_id, service_id, active FROM sources WHERE id=?`, id).Scan(&source.ID, &source.Scope.OrganizationID, &source.Scope.ProjectID, &source.Scope.EnvironmentID, &source.Scope.ServiceID, &active)
	if err != nil {
		return Source{}, fmt.Errorf("load source: %w", err)
	}
	source.Active = active == 1
	return source, nil
}
