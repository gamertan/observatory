// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
)

const maxProjectionVersion = 999999
const indexedTimeFormat = "2006-01-02T15:04:05.000000000Z"

type DescriptorActivation struct {
	OrganizationID string            `json:"organization_id"`
	Signal         model.Signal      `json:"signal"`
	Field          string            `json:"field"`
	Previous       int               `json:"previous_version"`
	Active         int               `json:"active_version"`
	IndexedRows    int64             `json:"indexed_rows"`
	Descriptor     schema.Descriptor `json:"descriptor"`
}

func (s *Store) namedLock(name string) *sync.Mutex {
	value, _ := s.locks.LoadOrStore(name, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func ensureProjectionMetadata(ctx context.Context, db sqlExecutor) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS projection_versions (
			version INTEGER PRIMARY KEY CHECK(version >= 1 AND version <= 999999),
			created_at TEXT NOT NULL,
			activated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS projection_state (
			id INTEGER PRIMARY KEY CHECK(id=1),
			active_version INTEGER NOT NULL REFERENCES projection_versions(version)
		)`,
		`CREATE TABLE IF NOT EXISTS projection_descriptors (
			version INTEGER NOT NULL REFERENCES projection_versions(version),
			signal TEXT NOT NULL,
			field TEXT NOT NULL,
			descriptor_json TEXT NOT NULL,
			PRIMARY KEY(version,signal,field)
		)`,
		`INSERT OR IGNORE INTO projection_versions(version,created_at,activated_at) VALUES(1,'1970-01-01T00:00:00Z','1970-01-01T00:00:00Z')`,
		`INSERT OR IGNORE INTO projection_state(id,active_version) VALUES(1,1)`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate projection metadata: %w", err)
		}
	}
	return nil
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func activeProjection(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (int, query.MapRegistry, []schema.Descriptor, error) {
	var version int
	if err := db.QueryRowContext(ctx, `SELECT active_version FROM projection_state WHERE id=1`).Scan(&version); err != nil {
		return 0, nil, nil, errors.New("read active projection version")
	}
	if version < 1 || version > maxProjectionVersion {
		return 0, nil, nil, errors.New("active projection version is invalid")
	}
	rows, err := db.QueryContext(ctx, `SELECT descriptor_json FROM projection_descriptors WHERE version=? ORDER BY signal,field`, version)
	if err != nil {
		return 0, nil, nil, errors.New("read active projection descriptors")
	}
	defer rows.Close()
	registry := query.MapRegistry{}
	var descriptors []schema.Descriptor
	for rows.Next() {
		if len(descriptors) >= model.MaxDistinctFields {
			return 0, nil, nil, errors.New("active projection descriptor limit exceeded")
		}
		var encoded string
		if err = rows.Scan(&encoded); err != nil {
			return 0, nil, nil, errors.New("read active projection descriptor")
		}
		var descriptor schema.Descriptor
		if err = json.Unmarshal([]byte(encoded), &descriptor); err != nil || descriptor.Validate() != nil || descriptor.ProjectionVersion != version {
			return 0, nil, nil, errors.New("active projection descriptor is invalid")
		}
		key := string(descriptor.Signal) + ":" + query.CanonicalField(descriptor.Field)
		if _, exists := registry[key]; exists {
			return 0, nil, nil, errors.New("active projection descriptor is duplicated")
		}
		registry[key] = descriptor
		descriptors = append(descriptors, descriptor)
	}
	if err = rows.Err(); err != nil {
		return 0, nil, nil, errors.New("read active projection descriptors")
	}
	return version, registry, descriptors, nil
}

func projectionIndexTable(version int) (string, error) {
	if version < 2 || version > maxProjectionVersion {
		return "", errors.New("indexed projection version is invalid")
	}
	return fmt.Sprintf("indexed_fields_v%06d", version), nil
}

func (s *Store) ActiveDescriptors(ctx context.Context, organizationID string) (query.MapRegistry, int, error) {
	if err := model.ValidateSourceID(organizationID); err != nil {
		return nil, 0, errors.New("invalid organization identifier")
	}
	path := filepath.Join(s.root, "organizations", organizationID, "projection.sqlite")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return query.MapRegistry{}, 1, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, errors.New("organization projection is unavailable")
	}
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, 0, errors.New("open organization projection")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var metadataTables int
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='projection_state'`).Scan(&metadataTables); err != nil {
		return nil, 0, errors.New("inspect organization projection metadata")
	}
	if metadataTables == 0 {
		return query.MapRegistry{}, 1, nil
	}
	version, registry, _, err := activeProjection(ctx, db)
	return registry, version, err
}

func (s *Store) ActivateDescriptor(ctx context.Context, organizationID string, reviewed schema.Descriptor, now time.Time) (DescriptorActivation, error) {
	if err := model.ValidateSourceID(organizationID); err != nil || reviewed.Validate() != nil || reviewed.ProjectionVersion != 1 || now.IsZero() {
		return DescriptorActivation{}, errors.New("descriptor activation input is invalid")
	}
	proposal, err := s.descriptorProposal(ctx, organizationID, reviewed.Signal, reviewed.Field)
	if err != nil {
		return DescriptorActivation{}, err
	}
	if proposal.Status == "rejected" {
		return DescriptorActivation{}, errors.New("rejected descriptor proposal cannot be activated")
	}
	if proposal.Proposal.Descriptor.Signal != reviewed.Signal || proposal.Proposal.Descriptor.Field != reviewed.Field {
		return DescriptorActivation{}, errors.New("reviewed descriptor does not match proposal")
	}

	lock := s.namedLock("organization:" + organizationID)
	lock.Lock()
	defer lock.Unlock()

	path := filepath.Join(s.root, "organizations", organizationID, "projection.sqlite")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return DescriptorActivation{}, errors.New("organization projection is unavailable")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return DescriptorActivation{}, errors.New("open organization projection")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, statement := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL`, `PRAGMA busy_timeout=5000`, `PRAGMA foreign_keys=ON`} {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			return DescriptorActivation{}, errors.New("configure organization projection")
		}
	}
	if err = ensureProjectionMetadata(ctx, db); err != nil {
		return DescriptorActivation{}, err
	}
	currentVersion, _, current, err := activeProjection(ctx, db)
	if err != nil {
		return DescriptorActivation{}, err
	}
	for _, descriptor := range current {
		if descriptor.Signal == reviewed.Signal && descriptor.Field == reviewed.Field {
			if sameDescriptorIgnoringProjection(descriptor, reviewed) {
				if err = s.markProposalActivated(ctx, organizationID, descriptor); err != nil {
					return DescriptorActivation{}, err
				}
				return DescriptorActivation{OrganizationID: organizationID, Signal: descriptor.Signal, Field: descriptor.Field, Previous: currentVersion, Active: currentVersion, Descriptor: descriptor}, nil
			}
		}
	}
	if proposal.Status == "activated" {
		return DescriptorActivation{}, errors.New("activated descriptor revision requires a new review proposal")
	}
	controlTx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return DescriptorActivation{}, errors.New("begin descriptor proposal claim")
	}
	defer controlTx.Rollback()
	claim, err := controlTx.ExecContext(ctx, `UPDATE descriptor_proposals SET status=status WHERE organization_id=? AND signal=? AND field=? AND status='pending'`, organizationID, reviewed.Signal, reviewed.Field)
	if err != nil {
		return DescriptorActivation{}, errors.New("claim descriptor proposal")
	}
	if changed, _ := claim.RowsAffected(); changed != 1 {
		return DescriptorActivation{}, errors.New("descriptor proposal is no longer pending")
	}
	if currentVersion >= maxProjectionVersion {
		return DescriptorActivation{}, errors.New("projection version space exhausted")
	}
	nextVersion := currentVersion + 1
	reviewed.ProjectionVersion = nextVersion
	if err = reviewed.Validate(); err != nil {
		return DescriptorActivation{}, errors.New("reviewed descriptor is invalid")
	}
	byKey := map[string]schema.Descriptor{}
	for _, descriptor := range current {
		descriptor.ProjectionVersion = nextVersion
		byKey[string(descriptor.Signal)+":"+descriptor.Field] = descriptor
	}
	byKey[string(reviewed.Signal)+":"+reviewed.Field] = reviewed
	if len(byKey) > model.MaxDistinctFields {
		return DescriptorActivation{}, errors.New("active projection descriptor limit exceeded")
	}
	next := make([]schema.Descriptor, 0, len(byKey))
	for _, descriptor := range byKey {
		next = append(next, descriptor)
	}
	sort.Slice(next, func(i, j int) bool {
		if next[i].Signal == next[j].Signal {
			return next[i].Field < next[j].Field
		}
		return next[i].Signal < next[j].Signal
	})
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return DescriptorActivation{}, errors.New("begin descriptor activation")
	}
	defer tx.Rollback()
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, `INSERT INTO projection_versions(version,created_at,activated_at) VALUES(?,?,?)`, nextVersion, timestamp, timestamp); err != nil {
		return DescriptorActivation{}, errors.New("create projection version")
	}
	for _, descriptor := range next {
		encoded, marshalErr := json.Marshal(descriptor)
		if marshalErr != nil {
			return DescriptorActivation{}, errors.New("encode active descriptor")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO projection_descriptors(version,signal,field,descriptor_json) VALUES(?,?,?,?)`, nextVersion, descriptor.Signal, descriptor.Field, string(encoded)); err != nil {
			return DescriptorActivation{}, errors.New("store active descriptor")
		}
	}
	indexedRows, err := buildProjectionIndex(ctx, tx, nextVersion, next)
	if err != nil {
		return DescriptorActivation{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE projection_state SET active_version=? WHERE id=1 AND active_version=?`, nextVersion, currentVersion)
	if err != nil {
		return DescriptorActivation{}, errors.New("activate projection version")
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return DescriptorActivation{}, errors.New("active projection changed during activation")
	}
	if err = tx.Commit(); err != nil {
		return DescriptorActivation{}, errors.New("commit descriptor activation")
	}
	encoded, err := json.Marshal(reviewed)
	if err != nil {
		return DescriptorActivation{}, errors.New("encode activated descriptor")
	}
	result, err = controlTx.ExecContext(ctx, `UPDATE descriptor_proposals SET descriptor_json=?,status='activated' WHERE organization_id=? AND signal=? AND field=? AND status='pending'`, string(encoded), organizationID, reviewed.Signal, reviewed.Field)
	if err != nil {
		return DescriptorActivation{}, errors.New("acknowledge activated descriptor")
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return DescriptorActivation{}, errors.New("descriptor proposal changed during activation")
	}
	if err = controlTx.Commit(); err != nil {
		return DescriptorActivation{}, errors.New("commit activated descriptor acknowledgement")
	}
	return DescriptorActivation{OrganizationID: organizationID, Signal: reviewed.Signal, Field: reviewed.Field, Previous: currentVersion, Active: nextVersion, IndexedRows: indexedRows, Descriptor: reviewed}, nil
}

func buildProjectionIndex(ctx context.Context, tx *sql.Tx, version int, descriptors []schema.Descriptor) (int64, error) {
	table, err := projectionIndexTable(version)
	if err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE `+table+` (
		signal TEXT NOT NULL, field TEXT NOT NULL,
		source_id TEXT NOT NULL, stream_id TEXT NOT NULL,
		sequence INTEGER NOT NULL, record_index INTEGER NOT NULL,
		timestamp TEXT NOT NULL, value_text TEXT NOT NULL, value_number REAL,
		PRIMARY KEY(signal,field,source_id,stream_id,sequence,record_index)
	) WITHOUT ROWID`); err != nil {
		return 0, errors.New("create projection index")
	}
	indexed := map[string]schema.Descriptor{}
	for _, descriptor := range descriptors {
		if descriptor.Index != schema.IndexNone {
			indexed[string(descriptor.Signal)+":"+descriptor.Field] = descriptor
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT source_id,stream_id,sequence,record_index,signal,timestamp,attributes_json FROM observations ORDER BY source_id,stream_id,sequence,record_index`)
	if err != nil {
		return 0, errors.New("scan projection for index build")
	}
	statement, err := tx.PrepareContext(ctx, `INSERT INTO `+table+`(signal,field,source_id,stream_id,sequence,record_index,timestamp,value_text,value_number) VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = rows.Close()
		return 0, errors.New("prepare projection index build")
	}
	defer statement.Close()
	var count int64
	for rows.Next() {
		var sourceID, streamID, signalText, timestamp, attributesJSON string
		var sequence uint64
		var recordIndex int
		if err = rows.Scan(&sourceID, &streamID, &sequence, &recordIndex, &signalText, &timestamp, &attributesJSON); err != nil {
			_ = rows.Close()
			return 0, errors.New("read projection index source")
		}
		var attributes map[string]string
		if err = json.Unmarshal([]byte(attributesJSON), &attributes); err != nil {
			_ = rows.Close()
			return 0, errors.New("decode projection index source")
		}
		for field, raw := range attributes {
			descriptor, ok := indexed[signalText+":"+query.CanonicalField(field)]
			if !ok {
				continue
			}
			text, number, ok := indexValue(raw, descriptor.Type)
			if !ok {
				continue
			}
			if _, err = statement.ExecContext(ctx, signalText, descriptor.Field, sourceID, streamID, sequence, recordIndex, timestamp, text, number); err != nil {
				_ = rows.Close()
				return 0, errors.New("build projection index")
			}
			if count == math.MaxInt64 {
				_ = rows.Close()
				return 0, errors.New("projection index row count overflow")
			}
			count++
		}
	}
	if err = rows.Close(); err != nil {
		return 0, errors.New("close projection index source")
	}
	if err = rows.Err(); err != nil {
		return 0, errors.New("scan projection for index build")
	}
	for _, suffix := range []struct{ name, columns string }{
		{"exact", "signal,field,value_text,timestamp"},
		{"number", "signal,field,value_number,timestamp"},
		{"record", "source_id,stream_id,sequence,record_index,signal,field"},
	} {
		if _, err = tx.ExecContext(ctx, `CREATE INDEX `+table+`_`+suffix.name+` ON `+table+`(`+suffix.columns+`)`); err != nil {
			return 0, errors.New("index activated projection")
		}
	}
	return count, nil
}

func indexValue(raw string, valueType schema.Type) (string, any, bool) {
	switch valueType {
	case schema.TypeInteger:
		value, err := strconv.ParseInt(raw, 10, 64)
		return raw, value, err == nil
	case schema.TypeFloat, schema.TypeDuration:
		value, err := strconv.ParseFloat(raw, 64)
		return raw, value, err == nil && !math.IsNaN(value) && !math.IsInf(value, 0)
	case schema.TypeBoolean:
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return "", nil, false
		}
		return strconv.FormatBool(value), nil, true
	case schema.TypeTime:
		value, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return "", nil, false
		}
		return value.UTC().Format(indexedTimeFormat), nil, true
	case schema.TypeString:
		return raw, nil, true
	default:
		return "", nil, false
	}
}

func indexProjectedObservation(ctx context.Context, tx *sql.Tx, version int, descriptors []schema.Descriptor, batch model.Batch, recordIndex int, observation model.Observation) error {
	if version == 1 {
		return nil
	}
	table, err := projectionIndexTable(version)
	if err != nil {
		return err
	}
	indexed := map[string]schema.Descriptor{}
	for _, descriptor := range descriptors {
		if descriptor.Signal == batch.Signal && descriptor.Index != schema.IndexNone {
			indexed[descriptor.Field] = descriptor
		}
	}
	for field, raw := range observation.Attributes {
		descriptor, ok := indexed[query.CanonicalField(field)]
		if !ok {
			continue
		}
		text, number, ok := indexValue(raw, descriptor.Type)
		if !ok {
			continue
		}
		_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO `+table+`(signal,field,source_id,stream_id,sequence,record_index,timestamp,value_text,value_number) VALUES(?,?,?,?,?,?,?,?,?)`, batch.Signal, descriptor.Field, batch.SourceID, batch.StreamID, batch.Sequence, recordIndex, observation.Timestamp.UTC().Format(time.RFC3339Nano), text, number)
		if err != nil {
			return errors.New("index projected observation")
		}
	}
	return nil
}

func sameDescriptorIgnoringProjection(left, right schema.Descriptor) bool {
	left.ProjectionVersion = 1
	right.ProjectionVersion = 1
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}
