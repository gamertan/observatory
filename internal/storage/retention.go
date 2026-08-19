// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/segment"
)

const maximumRetentionDays = 3650

var ErrOrganizationStorageQuotaExceeded = errors.New("organization storage quota exceeded")

// RetentionPolicy is the complete storage lifecycle for one organization.
// Raw metric samples may expire before their five-minute aggregate projection.
type RetentionPolicy struct {
	RawLogsDays       int  `json:"raw_logs_days"`
	RawTracesDays     int  `json:"raw_traces_days"`
	RawMetricsDays    int  `json:"raw_metrics_days"`
	ColdRawDays       int  `json:"cold_raw_days"`
	DeleteColdRaw     bool `json:"delete_cold_raw"`
	MetricRollupsDays int  `json:"metric_rollups_days"`
	EvidenceDays      int  `json:"evidence_days"`
}

func (policy RetentionPolicy) Validate() error {
	for _, days := range []int{policy.RawLogsDays, policy.RawTracesDays, policy.RawMetricsDays, policy.ColdRawDays, policy.MetricRollupsDays, policy.EvidenceDays} {
		if days < 1 || days > maximumRetentionDays {
			return errors.New("retention values must be between 1 and 3650 days")
		}
	}
	if policy.MetricRollupsDays < policy.RawMetricsDays {
		return errors.New("metric rollup retention cannot be shorter than raw metric retention")
	}
	if policy.ColdRawDays < policy.RawLogsDays || policy.ColdRawDays < policy.RawTracesDays || policy.ColdRawDays < policy.RawMetricsDays || policy.ColdRawDays < policy.EvidenceDays {
		return errors.New("cold raw retention cannot be shorter than a hot raw or evidence retention window")
	}
	return nil
}

type OrganizationRetention struct {
	OrganizationID      string          `json:"organization_id"`
	Policy              RetentionPolicy `json:"policy"`
	QuotaBytes          int64           `json:"quota_bytes,omitempty"`
	ExtensionApproved   bool            `json:"extension_approved"`
	ExtensionApprovedBy string          `json:"extension_approved_by,omitempty"`
	UpdatedBy           string          `json:"updated_by"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

type SetRetentionInput struct {
	OrganizationID      string
	Policy              RetentionPolicy
	Defaults            RetentionPolicy
	ActorUserID         string
	ApproveExtensionFor string
	QuotaBytes          int64
}

type RetentionReport struct {
	Version                      int       `json:"version"`
	StartedAt                    time.Time `json:"started_at"`
	CompletedAt                  time.Time `json:"completed_at"`
	Organizations                int       `json:"organizations"`
	RawSegmentsRemoved           int       `json:"raw_segments_removed"`
	RawBytesRemoved              int64     `json:"raw_bytes_removed"`
	RawSegmentsArchived          int       `json:"raw_segments_archived"`
	RawBytesArchived             int64     `json:"raw_bytes_archived"`
	ProjectedObservationsRemoved int64     `json:"projected_observations_removed"`
	MetricRollupsRemoved         int64     `json:"metric_rollups_removed"`
	LogRollupsRemoved            int64     `json:"log_rollups_removed"`
	ResolvedIncidentsRemoved     int64     `json:"resolved_incidents_removed"`
	PolicyEventsRemoved          int64     `json:"policy_events_removed"`
}

func migrateControlRetention(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin retention migration: %w", err)
	}
	defer tx.Rollback()
	var segmentTable int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='segments'`).Scan(&segmentTable); err != nil {
		return fmt.Errorf("inspect segment schema: %w", err)
	}
	if segmentTable == 0 {
		if _, err = tx.Exec(`CREATE TABLE segments (
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
			signal TEXT NOT NULL DEFAULT '',
			first_observed_at TEXT NOT NULL DEFAULT '',
			last_observed_at TEXT NOT NULL DEFAULT '',
			tier TEXT NOT NULL DEFAULT 'hot' CHECK(tier IN ('hot','cold')),
			archiving_at TEXT,
			archive_path TEXT,
			cold_at TEXT,
			retiring_at TEXT,
			UNIQUE(source_id,stream_id,sequence)
		)`); err != nil {
			return fmt.Errorf("create retained segment schema: %w", err)
		}
	} else {
		columns, columnErr := sqliteColumns(tx, "segments")
		if columnErr != nil {
			return columnErr
		}
		for _, column := range []struct{ name, definition string }{
			{"signal", `TEXT NOT NULL DEFAULT ''`},
			{"first_observed_at", `TEXT NOT NULL DEFAULT ''`},
			{"last_observed_at", `TEXT NOT NULL DEFAULT ''`},
			{"tier", `TEXT NOT NULL DEFAULT 'hot' CHECK(tier IN ('hot','cold'))`},
			{"archiving_at", `TEXT`},
			{"archive_path", `TEXT`},
			{"cold_at", `TEXT`},
			{"retiring_at", `TEXT`},
		} {
			if columns[column.name] {
				continue
			}
			if _, err = tx.Exec(`ALTER TABLE segments ADD COLUMN ` + column.name + ` ` + column.definition); err != nil {
				return fmt.Errorf("add segment retention column: %w", err)
			}
		}
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS segments_retention ON segments(organization_id,tier,signal,last_observed_at,retiring_at)`,
		`CREATE INDEX IF NOT EXISTS segments_archiving ON segments(archiving_at,organization_id)`,
		`CREATE TABLE IF NOT EXISTS organization_retention_policies (
			organization_id TEXT PRIMARY KEY,
			raw_logs_days INTEGER NOT NULL CHECK(raw_logs_days BETWEEN 1 AND 3650),
			raw_traces_days INTEGER NOT NULL CHECK(raw_traces_days BETWEEN 1 AND 3650),
			raw_metrics_days INTEGER NOT NULL CHECK(raw_metrics_days BETWEEN 1 AND 3650),
			cold_raw_days INTEGER NOT NULL CHECK(cold_raw_days BETWEEN 1 AND 3650),
			delete_cold_raw INTEGER NOT NULL DEFAULT 0 CHECK(delete_cold_raw IN (0,1)),
			metric_rollups_days INTEGER NOT NULL CHECK(metric_rollups_days BETWEEN 1 AND 3650),
			evidence_days INTEGER NOT NULL CHECK(evidence_days BETWEEN 1 AND 3650),
			quota_bytes INTEGER CHECK(quota_bytes IS NULL OR quota_bytes > 0),
			extension_approved_by TEXT,
			updated_by TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS retention_policy_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			organization_id TEXT NOT NULL,
			actor_user_id TEXT NOT NULL,
			action TEXT NOT NULL CHECK(action IN ('created','updated')),
			summary TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS retention_policy_events_age ON retention_policy_events(organization_id,created_at)`,
		`UPDATE schema_version SET version=7 WHERE version=6`,
	} {
		if _, err = tx.Exec(statement); err != nil {
			return fmt.Errorf("migrate retention schema: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit retention migration: %w", err)
	}
	return nil
}

func migrateControlForensicRetention(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin forensic retention migration: %w", err)
	}
	defer tx.Rollback()
	columns, err := sqliteColumns(tx, "organization_retention_policies")
	if err != nil {
		return err
	}
	if !columns["delete_cold_raw"] {
		if _, err = tx.Exec(`ALTER TABLE organization_retention_policies ADD COLUMN delete_cold_raw INTEGER NOT NULL DEFAULT 0 CHECK(delete_cold_raw IN (0,1))`); err != nil {
			return fmt.Errorf("add forensic retention policy: %w", err)
		}
	}
	if _, err = tx.Exec(`UPDATE schema_version SET version=8 WHERE version=7`); err != nil {
		return fmt.Errorf("advance forensic retention schema: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit forensic retention migration: %w", err)
	}
	return nil
}

type columnQuery interface {
	Query(string, ...any) (*sql.Rows, error)
}

func sqliteColumns(db columnQuery, table string) (map[string]bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil, fmt.Errorf("inspect SQLite columns: %w", err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var index, notNull, primaryKey int
		var name, valueType string
		var defaultValue any
		if err = rows.Scan(&index, &name, &valueType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, fmt.Errorf("read SQLite columns: %w", err)
		}
		columns[name] = true
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("read SQLite columns: %w", err)
	}
	return columns, nil
}

func retentionExtended(policy, defaults RetentionPolicy) bool {
	return policy.RawLogsDays > defaults.RawLogsDays ||
		policy.RawTracesDays > defaults.RawTracesDays ||
		policy.RawMetricsDays > defaults.RawMetricsDays ||
		(policy.DeleteColdRaw && defaults.DeleteColdRaw && policy.ColdRawDays > defaults.ColdRawDays) ||
		(!policy.DeleteColdRaw && defaults.DeleteColdRaw) ||
		policy.MetricRollupsDays > defaults.MetricRollupsDays ||
		policy.EvidenceDays > defaults.EvidenceDays
}

// SetOrganizationRetention records a policy selected by an organization
// owner. Extending a server default additionally requires an exact approval
// string and a quota larger than current organization storage.
func (s *Store) SetOrganizationRetention(ctx context.Context, input SetRetentionInput, now time.Time) (OrganizationRetention, error) {
	if err := model.ValidateSourceID(input.OrganizationID); err != nil || model.ValidateSourceID(input.ActorUserID) != nil || input.Policy.Validate() != nil || input.Defaults.Validate() != nil || now.IsZero() {
		return OrganizationRetention{}, errors.New("retention policy input is invalid")
	}
	extended := retentionExtended(input.Policy, input.Defaults)
	if extended {
		if input.ApproveExtensionFor != input.OrganizationID || input.QuotaBytes <= 0 {
			return OrganizationRetention{}, errors.New("retention extension requires exact organization approval and a positive quota")
		}
		used, err := s.organizationStorageBytes(input.OrganizationID)
		if err != nil {
			return OrganizationRetention{}, err
		}
		if used >= input.QuotaBytes {
			return OrganizationRetention{}, errors.New("organization storage already exceeds the approved quota")
		}
	} else if input.QuotaBytes != 0 || input.ApproveExtensionFor != "" {
		return OrganizationRetention{}, errors.New("retention extension approval is not applicable")
	}
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return OrganizationRetention{}, errors.New("begin retention policy update")
	}
	defer tx.Rollback()
	var existed int
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM organization_retention_policies WHERE organization_id=?)`, input.OrganizationID).Scan(&existed); err != nil {
		return OrganizationRetention{}, errors.New("inspect retention policy")
	}
	var quota any
	var approvedBy any
	if extended {
		quota = input.QuotaBytes
		approvedBy = input.ActorUserID
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO organization_retention_policies(organization_id,raw_logs_days,raw_traces_days,raw_metrics_days,cold_raw_days,delete_cold_raw,metric_rollups_days,evidence_days,quota_bytes,extension_approved_by,updated_by,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(organization_id) DO UPDATE SET raw_logs_days=excluded.raw_logs_days,raw_traces_days=excluded.raw_traces_days,raw_metrics_days=excluded.raw_metrics_days,cold_raw_days=excluded.cold_raw_days,delete_cold_raw=excluded.delete_cold_raw,metric_rollups_days=excluded.metric_rollups_days,evidence_days=excluded.evidence_days,quota_bytes=excluded.quota_bytes,extension_approved_by=excluded.extension_approved_by,updated_by=excluded.updated_by,updated_at=excluded.updated_at`, input.OrganizationID, input.Policy.RawLogsDays, input.Policy.RawTracesDays, input.Policy.RawMetricsDays, input.Policy.ColdRawDays, input.Policy.DeleteColdRaw, input.Policy.MetricRollupsDays, input.Policy.EvidenceDays, quota, approvedBy, input.ActorUserID, timestamp)
	if err != nil {
		return OrganizationRetention{}, errors.New("store retention policy")
	}
	action := "created"
	if existed == 1 {
		action = "updated"
	}
	summary := fmt.Sprintf("Organization retention policy changed; delete_cold_raw=%t", input.Policy.DeleteColdRaw)
	if _, err = tx.ExecContext(ctx, `INSERT INTO retention_policy_events(organization_id,actor_user_id,action,summary,created_at) VALUES(?,?,?,?,?)`, input.OrganizationID, input.ActorUserID, action, summary, timestamp); err != nil {
		return OrganizationRetention{}, errors.New("record retention policy event")
	}
	if err = tx.Commit(); err != nil {
		return OrganizationRetention{}, errors.New("commit retention policy update")
	}
	return OrganizationRetention{OrganizationID: input.OrganizationID, Policy: input.Policy, QuotaBytes: input.QuotaBytes, ExtensionApproved: extended, ExtensionApprovedBy: func() string {
		if extended {
			return input.ActorUserID
		}
		return ""
	}(), UpdatedBy: input.ActorUserID, UpdatedAt: now.UTC()}, nil
}

func (s *Store) organizationStorageBytes(organizationID string) (int64, error) {
	if err := model.ValidateSourceID(organizationID); err != nil {
		return 0, errors.New("invalid organization identifier")
	}
	var raw int64
	if err := s.control.QueryRow(`SELECT COALESCE(SUM(compressed_bytes),0) FROM segments WHERE organization_id=?`, organizationID).Scan(&raw); err != nil {
		return 0, errors.New("measure organization raw storage")
	}
	projected, err := s.EstimateOrganizationBytes(organizationID)
	if err != nil {
		return 0, err
	}
	if raw > int64(^uint64(0)>>1)-projected {
		return 0, errors.New("organization storage size overflow")
	}
	return raw + projected, nil
}

func (s *Store) checkCommittedQuota(ctx context.Context, organizationID string, committed segment.Committed) error {
	var recorded int
	if err := s.control.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM segments WHERE digest=?)`, committed.Digest).Scan(&recorded); err != nil {
		return errors.New("inspect committed segment quota state")
	}
	if recorded == 1 {
		return nil
	}
	var quota sql.NullInt64
	err := s.control.QueryRowContext(ctx, `SELECT quota_bytes FROM organization_retention_policies WHERE organization_id=?`, organizationID).Scan(&quota)
	if errors.Is(err, sql.ErrNoRows) || !quota.Valid {
		return nil
	}
	if err != nil {
		return errors.New("read organization storage quota")
	}
	used, err := s.organizationStorageBytes(organizationID)
	if err != nil {
		return err
	}
	addition := committed.Compressed + committed.Uncompressed
	if addition < 0 || used > quota.Int64-addition {
		return ErrOrganizationStorageQuotaExceeded
	}
	return nil
}

// admitCommitted serializes quota admission across every source belonging to
// one organization. The raw object is already durable at this point; a quota
// rejection removes that exact checksummed object before returning. The
// segment catalog row and stream watermark are committed together before an
// acknowledgement can be returned. Projection is intentionally independent.
func (s *Store) admitCommitted(ctx context.Context, scope model.Scope, batch model.Batch, committed segment.Committed, committedAt time.Time) error {
	return s.admitCommittedEnvelope(ctx, scope, batch, committed, nil, committedAt)
}

func (s *Store) admitCommittedEnvelope(ctx context.Context, scope model.Scope, batch model.Batch, committed segment.Committed, envelope *model.BatchEnvelope, committedAt time.Time) error {
	lock := s.namedLock("quota:" + scope.OrganizationID)
	lock.Lock()
	defer lock.Unlock()
	if err := s.checkCommittedQuota(ctx, scope.OrganizationID, committed); err != nil {
		if deleteErr := s.segments.Delete(committed.Path, committed.Digest); deleteErr != nil {
			return fmt.Errorf("%w; remove rejected segment: %v", err, deleteErr)
		}
		return err
	}
	return s.recordCommittedAtEnvelope(ctx, scope, batch, committed, envelope, committedAt)
}

func (s *Store) effectiveRetention(ctx context.Context, organizationID string, defaults RetentionPolicy) (RetentionPolicy, error) {
	if err := defaults.Validate(); err != nil {
		return RetentionPolicy{}, err
	}
	policy := defaults
	err := s.control.QueryRowContext(ctx, `SELECT raw_logs_days,raw_traces_days,raw_metrics_days,cold_raw_days,delete_cold_raw,metric_rollups_days,evidence_days FROM organization_retention_policies WHERE organization_id=?`, organizationID).Scan(&policy.RawLogsDays, &policy.RawTracesDays, &policy.RawMetricsDays, &policy.ColdRawDays, &policy.DeleteColdRaw, &policy.MetricRollupsDays, &policy.EvidenceDays)
	if errors.Is(err, sql.ErrNoRows) {
		return defaults, nil
	}
	if err != nil || policy.Validate() != nil {
		return RetentionPolicy{}, errors.New("organization retention policy is invalid")
	}
	return policy, nil
}

// ApplyRetention materializes five-minute metric rollups before removing
// expired raw projections, then retires only raw segments whose newest record
// is outside the applicable window. Segment retirement is crash-recoverable.
func (s *Store) ApplyRetention(ctx context.Context, defaults RetentionPolicy, now time.Time) (RetentionReport, error) {
	if defaults.Validate() != nil || now.IsZero() {
		return RetentionReport{}, errors.New("retention run input is invalid")
	}
	report := RetentionReport{Version: 1, StartedAt: now.UTC()}
	organizations, err := s.retentionOrganizations(ctx)
	if err != nil {
		return report, err
	}
	for _, organizationID := range organizations {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		policy, policyErr := s.effectiveRetention(ctx, organizationID, defaults)
		if policyErr != nil {
			return report, policyErr
		}
		lock := s.namedLock("organization:" + organizationID)
		lock.Lock()
		organizationReport, applyErr := s.applyOrganizationRetention(ctx, organizationID, policy, now.UTC())
		lock.Unlock()
		if applyErr != nil {
			return report, applyErr
		}
		report.Organizations++
		report.RawSegmentsRemoved += organizationReport.RawSegmentsRemoved
		report.RawBytesRemoved += organizationReport.RawBytesRemoved
		report.RawSegmentsArchived += organizationReport.RawSegmentsArchived
		report.RawBytesArchived += organizationReport.RawBytesArchived
		report.ProjectedObservationsRemoved += organizationReport.ProjectedObservationsRemoved
		report.MetricRollupsRemoved += organizationReport.MetricRollupsRemoved
		report.LogRollupsRemoved += organizationReport.LogRollupsRemoved
		report.ResolvedIncidentsRemoved += organizationReport.ResolvedIncidentsRemoved
		report.PolicyEventsRemoved += organizationReport.PolicyEventsRemoved
	}
	report.CompletedAt = time.Now().UTC()
	return report, nil
}

func (s *Store) retentionOrganizations(ctx context.Context) ([]string, error) {
	rows, err := s.control.QueryContext(ctx, `SELECT organization_id FROM sources UNION SELECT organization_id FROM segments UNION SELECT organization_id FROM organization_retention_policies ORDER BY organization_id`)
	if err != nil {
		return nil, errors.New("list retention organizations")
	}
	defer rows.Close()
	var organizations []string
	for rows.Next() {
		var organizationID string
		if err = rows.Scan(&organizationID); err != nil || model.ValidateSourceID(organizationID) != nil {
			return nil, errors.New("retention organization is invalid")
		}
		organizations = append(organizations, organizationID)
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New("list retention organizations")
	}
	return organizations, nil
}

func retentionCutoff(now time.Time, days int) string {
	return now.Add(-time.Duration(days) * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
}

func (s *Store) applyOrganizationRetention(ctx context.Context, organizationID string, policy RetentionPolicy, now time.Time) (RetentionReport, error) {
	report := RetentionReport{Version: 1}
	path := s.organizationProjectionPath(organizationID)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return report, errors.New("organization projection is unavailable")
		}
		db, openErr := openProjection(ctx, path)
		if openErr != nil {
			return report, openErr
		}
		tx, beginErr := db.BeginTx(ctx, nil)
		if beginErr != nil {
			_ = db.Close()
			return report, errors.New("begin organization retention")
		}
		for _, expiration := range []struct {
			signal model.Signal
			days   int
		}{
			{model.SignalLogs, policy.RawLogsDays},
			{model.SignalTraces, policy.RawTracesDays},
			{model.SignalMetrics, policy.RawMetricsDays},
			{model.SignalDeployments, policy.EvidenceDays},
		} {
			result, deleteErr := tx.ExecContext(ctx, `DELETE FROM observations WHERE organization_id=? AND signal=? AND timestamp<?`, organizationID, expiration.signal, retentionCutoff(now, expiration.days))
			if deleteErr != nil {
				_ = tx.Rollback()
				_ = db.Close()
				return report, errors.New("remove expired observation projections")
			}
			removed, _ := result.RowsAffected()
			report.ProjectedObservationsRemoved += removed
		}
		result, deleteErr := tx.ExecContext(ctx, `DELETE FROM metric_rollups_5m WHERE organization_id=? AND bucket_start<?`, organizationID, retentionCutoff(now, policy.MetricRollupsDays))
		if deleteErr != nil {
			_ = tx.Rollback()
			_ = db.Close()
			return report, errors.New("remove expired metric rollups")
		}
		report.MetricRollupsRemoved, _ = result.RowsAffected()
		logCutoff := now.Add(-time.Duration(policy.RawLogsDays) * 24 * time.Hour).UTC().Truncate(logRollupWindow).Unix()
		result, deleteErr = tx.ExecContext(ctx, `DELETE FROM log_status_route_rollups_5m WHERE organization_id=? AND bucket_start<?`, organizationID, logCutoff)
		if deleteErr != nil {
			_ = tx.Rollback()
			_ = db.Close()
			return report, errors.New("remove expired log rollups")
		}
		report.LogRollupsRemoved, _ = result.RowsAffected()
		if err = tx.Commit(); err != nil {
			_ = db.Close()
			return report, errors.New("commit organization retention")
		}
		if report.ProjectedObservationsRemoved > 0 || report.MetricRollupsRemoved > 0 || report.LogRollupsRemoved > 0 {
			if _, err = db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
				_ = db.Close()
				return report, errors.New("checkpoint retained organization projection")
			}
			if _, err = db.ExecContext(ctx, `VACUUM`); err != nil {
				_ = db.Close()
				return report, errors.New("compact retained organization projection")
			}
		}
		if err = db.Close(); err != nil {
			return report, errors.New("close retained organization projection")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return report, errors.New("inspect organization projection for retention")
	}

	evidenceCutoff := retentionCutoff(now, policy.EvidenceDays)
	result, err := s.control.ExecContext(ctx, `DELETE FROM incidents WHERE organization_id=? AND state='resolved' AND updated_at<?`, organizationID, evidenceCutoff)
	if err != nil {
		return report, errors.New("remove expired resolved incidents")
	}
	report.ResolvedIncidentsRemoved, _ = result.RowsAffected()
	result, err = s.control.ExecContext(ctx, `DELETE FROM retention_policy_events WHERE organization_id=? AND created_at<?`, organizationID, evidenceCutoff)
	if err != nil {
		return report, errors.New("remove expired retention policy events")
	}
	report.PolicyEventsRemoved, _ = result.RowsAffected()
	for _, expiration := range []struct {
		signal model.Signal
		days   int
	}{
		{model.SignalLogs, policy.RawLogsDays},
		{model.SignalTraces, policy.RawTracesDays},
		{model.SignalMetrics, policy.RawMetricsDays},
		{model.SignalDeployments, policy.EvidenceDays},
	} {
		archived, bytes, archiveErr := s.archiveHotSegments(ctx, organizationID, expiration.signal, retentionCutoff(now, expiration.days), now)
		if archiveErr != nil {
			return report, archiveErr
		}
		report.RawSegmentsArchived += archived
		report.RawBytesArchived += bytes
	}
	if policy.DeleteColdRaw {
		if _, err = s.control.ExecContext(ctx, `UPDATE segments SET retiring_at=? WHERE organization_id=? AND tier='cold' AND projected_at IS NOT NULL AND retiring_at IS NULL AND last_observed_at<?`, now.Format(time.RFC3339Nano), organizationID, retentionCutoff(now, policy.ColdRawDays)); err != nil {
			return report, errors.New("mark expired cold segments")
		}
	}
	removed, bytes, err := s.finalizeRetiring(ctx, organizationID)
	if err != nil {
		return report, err
	}
	report.RawSegmentsRemoved, report.RawBytesRemoved = removed, bytes
	return report, nil
}

type archivingSegment struct {
	digest, path, archivePath, sourceID, streamID string
	signal                                        model.Signal
	bytes                                         int64
}

func (s *Store) archiveHotSegments(ctx context.Context, organizationID string, signal model.Signal, cutoff string, now time.Time) (int, int64, error) {
	rows, err := s.control.QueryContext(ctx, `SELECT digest,path,source_id,stream_id,compressed_bytes FROM segments WHERE organization_id=? AND signal=? AND tier='hot' AND projected_at IS NOT NULL AND retiring_at IS NULL AND archiving_at IS NULL AND last_observed_at<? ORDER BY last_observed_at,digest`, organizationID, signal, cutoff)
	if err != nil {
		return 0, 0, errors.New("list hot segments for archival")
	}
	var pending []archivingSegment
	for rows.Next() {
		var candidate archivingSegment
		candidate.signal = signal
		if err = rows.Scan(&candidate.digest, &candidate.path, &candidate.sourceID, &candidate.streamID, &candidate.bytes); err != nil {
			_ = rows.Close()
			return 0, 0, errors.New("read hot segment for archival")
		}
		candidate.archivePath, err = s.coldArchivePath(organizationID, candidate)
		if err != nil {
			_ = rows.Close()
			return 0, 0, err
		}
		pending = append(pending, candidate)
	}
	if err = rows.Close(); err != nil {
		return 0, 0, errors.New("close hot segments for archival")
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	for _, candidate := range pending {
		result, updateErr := s.control.ExecContext(ctx, `UPDATE segments SET archiving_at=?,archive_path=? WHERE digest=? AND organization_id=? AND tier='hot' AND archiving_at IS NULL AND retiring_at IS NULL`, stamp, candidate.archivePath, candidate.digest, organizationID)
		if updateErr != nil {
			return 0, 0, errors.New("mark hot segment for archival")
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return 0, 0, errors.New("hot segment archival state changed")
		}
	}
	return s.finalizeArchiving(ctx, organizationID)
}

func (s *Store) coldArchivePath(organizationID string, candidate archivingSegment) (string, error) {
	if model.ValidateSourceID(organizationID) != nil || model.ValidateSourceID(candidate.sourceID) != nil || model.ValidateStreamID(candidate.streamID) != nil {
		return "", errors.New("cold archive identity is invalid")
	}
	switch candidate.signal {
	case model.SignalLogs, model.SignalMetrics, model.SignalTraces, model.SignalDeployments:
	default:
		return "", errors.New("cold archive signal is invalid")
	}
	name := filepath.Base(filepath.Clean(candidate.path))
	if name == "." || name == string(os.PathSeparator) || !strings.HasSuffix(name, "-"+candidate.digest+".zst") {
		return "", errors.New("cold archive segment name is invalid")
	}
	return filepath.Join(s.root, "cold", organizationID, string(candidate.signal), candidate.sourceID, candidate.streamID, name), nil
}

func (s *Store) finalizeArchiving(ctx context.Context, organizationID string) (int, int64, error) {
	rows, err := s.control.QueryContext(ctx, `SELECT digest,path,archive_path,source_id,stream_id,signal,compressed_bytes FROM segments WHERE organization_id=? AND archiving_at IS NOT NULL ORDER BY archiving_at,digest`, organizationID)
	if err != nil {
		return 0, 0, errors.New("list interrupted cold archives")
	}
	var pending []archivingSegment
	for rows.Next() {
		var candidate archivingSegment
		if err = rows.Scan(&candidate.digest, &candidate.path, &candidate.archivePath, &candidate.sourceID, &candidate.streamID, &candidate.signal, &candidate.bytes); err != nil {
			_ = rows.Close()
			return 0, 0, errors.New("read interrupted cold archive")
		}
		pending = append(pending, candidate)
	}
	if err = rows.Close(); err != nil {
		return 0, 0, errors.New("close interrupted cold archives")
	}
	archived := 0
	var archivedBytes int64
	for _, candidate := range pending {
		expected, pathErr := s.coldArchivePath(organizationID, candidate)
		if pathErr != nil || expected != candidate.archivePath {
			return archived, archivedBytes, errors.New("cold archive target is invalid")
		}
		if err = s.segments.MoveToCold(candidate.path, candidate.archivePath, candidate.digest); err != nil {
			return archived, archivedBytes, err
		}
		result, updateErr := s.control.ExecContext(ctx, `UPDATE segments SET path=archive_path,tier='cold',cold_at=archiving_at,archiving_at=NULL,archive_path=NULL WHERE digest=? AND organization_id=? AND tier='hot' AND archiving_at IS NOT NULL AND archive_path=?`, candidate.digest, organizationID, candidate.archivePath)
		if updateErr != nil {
			return archived, archivedBytes, errors.New("complete cold segment archival")
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return archived, archivedBytes, errors.New("cold segment archival state changed")
		}
		archived++
		if candidate.bytes > math.MaxInt64-archivedBytes {
			return archived, archivedBytes, errors.New("cold archive byte count overflow")
		}
		archivedBytes += candidate.bytes
		removeEmptyPrivateDirectory(filepath.Dir(candidate.path))
		removeEmptyPrivateDirectory(filepath.Dir(filepath.Dir(candidate.path)))
	}
	return archived, archivedBytes, nil
}

func (s *Store) finalizeRetiring(ctx context.Context, organizationID string) (int, int64, error) {
	rows, err := s.control.QueryContext(ctx, `SELECT digest,path,compressed_bytes FROM segments WHERE organization_id=? AND retiring_at IS NOT NULL ORDER BY retiring_at,digest`, organizationID)
	if err != nil {
		return 0, 0, errors.New("list retiring raw segments")
	}
	type retiringSegment struct {
		digest, path string
		bytes        int64
	}
	var pending []retiringSegment
	for rows.Next() {
		var segment retiringSegment
		if err = rows.Scan(&segment.digest, &segment.path, &segment.bytes); err != nil {
			_ = rows.Close()
			return 0, 0, errors.New("read retiring raw segment")
		}
		pending = append(pending, segment)
	}
	if err = rows.Close(); err != nil {
		return 0, 0, errors.New("close retiring raw segments")
	}
	path := s.organizationProjectionPath(organizationID)
	var projection *sql.DB
	if _, err = os.Lstat(path); err == nil {
		projection, err = openProjection(ctx, path)
		if err != nil {
			return 0, 0, err
		}
		defer projection.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, 0, errors.New("inspect retiring segment projection")
	}
	removed := 0
	var removedBytes int64
	for _, segment := range pending {
		if projection != nil {
			tx, beginErr := projection.BeginTx(ctx, nil)
			if beginErr != nil {
				return removed, removedBytes, errors.New("begin retiring segment projection")
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM observations WHERE organization_id=? AND segment_digest=?`, organizationID, segment.digest); err != nil {
				_ = tx.Rollback()
				return removed, removedBytes, errors.New("remove retiring segment projection")
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM metric_rollup_segments WHERE segment_digest=?`, segment.digest); err != nil {
				_ = tx.Rollback()
				return removed, removedBytes, errors.New("remove retiring segment rollup ledger")
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM log_rollup_segments WHERE segment_digest=?`, segment.digest); err != nil {
				_ = tx.Rollback()
				return removed, removedBytes, errors.New("remove retiring segment log rollup ledger")
			}
			if err = tx.Commit(); err != nil {
				return removed, removedBytes, errors.New("commit retiring segment projection")
			}
		}
		if err = s.segments.Delete(segment.path, segment.digest); err != nil {
			return removed, removedBytes, err
		}
		tx, beginErr := s.control.BeginTx(ctx, nil)
		if beginErr != nil {
			return removed, removedBytes, errors.New("begin retiring segment acknowledgement")
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM descriptor_proposal_segments WHERE segment_digest=?`, segment.digest); err != nil {
			_ = tx.Rollback()
			return removed, removedBytes, errors.New("remove retired segment proposal evidence")
		}
		result, deleteErr := tx.ExecContext(ctx, `DELETE FROM segments WHERE digest=? AND organization_id=? AND retiring_at IS NOT NULL`, segment.digest, organizationID)
		if deleteErr != nil {
			_ = tx.Rollback()
			return removed, removedBytes, errors.New("acknowledge retired segment")
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			_ = tx.Rollback()
			return removed, removedBytes, errors.New("retired segment state changed")
		}
		if err = tx.Commit(); err != nil {
			return removed, removedBytes, errors.New("commit retired segment acknowledgement")
		}
		removed++
		removedBytes += segment.bytes
		removeEmptyPrivateDirectory(filepath.Dir(segment.path))
		removeEmptyPrivateDirectory(filepath.Dir(filepath.Dir(segment.path)))
	}
	return removed, removedBytes, nil
}

func (s *Store) finishInterruptedRetention(ctx context.Context) error {
	rows, err := s.control.QueryContext(ctx, `SELECT DISTINCT organization_id FROM segments WHERE retiring_at IS NOT NULL ORDER BY organization_id`)
	if err != nil {
		return errors.New("list interrupted retention organizations")
	}
	var organizations []string
	for rows.Next() {
		var organizationID string
		if err = rows.Scan(&organizationID); err != nil {
			_ = rows.Close()
			return errors.New("read interrupted retention organization")
		}
		organizations = append(organizations, organizationID)
	}
	if err = rows.Close(); err != nil {
		return errors.New("close interrupted retention organizations")
	}
	for _, organizationID := range organizations {
		lock := s.namedLock("organization:" + organizationID)
		lock.Lock()
		_, _, finalizeErr := s.finalizeRetiring(ctx, organizationID)
		lock.Unlock()
		if finalizeErr != nil {
			return finalizeErr
		}
	}
	return nil
}

func (s *Store) finishInterruptedArchival(ctx context.Context) error {
	rows, err := s.control.QueryContext(ctx, `SELECT DISTINCT organization_id FROM segments WHERE archiving_at IS NOT NULL ORDER BY organization_id`)
	if err != nil {
		return errors.New("list interrupted archive organizations")
	}
	var organizations []string
	for rows.Next() {
		var organizationID string
		if err = rows.Scan(&organizationID); err != nil || model.ValidateSourceID(organizationID) != nil {
			_ = rows.Close()
			return errors.New("read interrupted archive organization")
		}
		organizations = append(organizations, organizationID)
	}
	if err = rows.Close(); err != nil {
		return errors.New("close interrupted archive organizations")
	}
	for _, organizationID := range organizations {
		lock := s.namedLock("organization:" + organizationID)
		lock.Lock()
		_, _, finalizeErr := s.finalizeArchiving(ctx, organizationID)
		lock.Unlock()
		if finalizeErr != nil {
			return finalizeErr
		}
	}
	return nil
}

func (s *Store) organizationProjectionPath(organizationID string) string {
	return filepath.Join(s.root, "organizations", organizationID, "projection.sqlite")
}

func (s *Store) backfillSegmentRetentionMetadata(ctx context.Context) error {
	rows, err := s.control.QueryContext(ctx, `SELECT digest,path FROM segments WHERE signal='' OR first_observed_at='' OR last_observed_at='' ORDER BY committed_at,digest`)
	if err != nil {
		return errors.New("list legacy segment metadata")
	}
	type legacy struct{ digest, path string }
	var pending []legacy
	for rows.Next() {
		var item legacy
		if err = rows.Scan(&item.digest, &item.path); err != nil {
			_ = rows.Close()
			return errors.New("read legacy segment metadata")
		}
		pending = append(pending, item)
	}
	if err = rows.Close(); err != nil {
		return errors.New("close legacy segment metadata")
	}
	for _, item := range pending {
		batch, readErr := s.segments.Read(item.path, item.digest)
		if readErr != nil {
			return fmt.Errorf("backfill segment metadata: %w", readErr)
		}
		if len(batch.Records) == 0 {
			return errors.New("backfill segment metadata: segment has no records")
		}
		first, last := observationRange(batch)
		result, updateErr := s.control.ExecContext(ctx, `UPDATE segments SET signal=?,first_observed_at=?,last_observed_at=? WHERE digest=? AND (signal='' OR first_observed_at='' OR last_observed_at='')`, batch.Signal, first.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano), item.digest)
		if updateErr != nil {
			return errors.New("backfill segment metadata")
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return errors.New("segment metadata changed during backfill")
		}
	}
	return nil
}

func removeEmptyPrivateDirectory(path string) {
	info, err := os.Lstat(path)
	if err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		_ = os.Remove(path)
	}
}
