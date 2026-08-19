// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"gamertan.com/observatory/internal/model"
)

const (
	projectionGroupMaxSegments = 16
	projectionGroupMaxBytes    = 32 << 20
	projectionWorkerLimit      = 4
	defaultProjectorInterval   = time.Second
)

// ProjectionReport describes one bounded projector pass. Accepted raw
// segments remain durable and replayable independently of this report.
type ProjectionReport struct {
	ProjectedSegments int   `json:"projected_segments"`
	ProjectedRecords  int   `json:"projected_records"`
	ProjectedBytes    int64 `json:"projected_bytes"`
}

// ProjectionStatus makes asynchronous query visibility explicit. Lag is the
// age of the oldest durable segment that has not yet reached the read model.
type ProjectionStatus struct {
	PendingSegments  int           `json:"pending_segments"`
	PendingBytes     int64         `json:"pending_bytes"`
	OldestCommitted  time.Time     `json:"oldest_committed_at,omitempty"`
	OldestPendingLag time.Duration `json:"oldest_pending_lag"`
}

type pendingProjection struct {
	digest            string
	path              string
	uncompressedBytes int64
	sourceID          string
	streamID          string
	sequence          uint64
	committedAt       time.Time
	catalogOrgID      string
	scope             model.Scope
}

type pendingProjectionGroup struct {
	organizationID string
	segments       []pendingProjection
	bytes          int64
}

// ProjectionStatus returns a bounded control-database view and never opens an
// organization projection.
func (s *Store) ProjectionStatus(ctx context.Context, now time.Time) (ProjectionStatus, error) {
	return s.projectionStatus(ctx, "", now)
}

// OrganizationProjectionStatus restricts lag evidence to one tenant so the
// authenticated UI never discloses another organization's ingestion volume.
func (s *Store) OrganizationProjectionStatus(ctx context.Context, organizationID string, now time.Time) (ProjectionStatus, error) {
	if err := model.ValidateSourceID(organizationID); err != nil {
		return ProjectionStatus{}, errors.New("invalid organization identifier")
	}
	return s.projectionStatus(ctx, organizationID, now)
}

func (s *Store) projectionStatus(ctx context.Context, organizationID string, now time.Time) (ProjectionStatus, error) {
	if now.IsZero() {
		return ProjectionStatus{}, errors.New("projection status time is required")
	}
	var status ProjectionStatus
	var oldest sql.NullString
	var err error
	if organizationID == "" {
		err = s.control.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(uncompressed_bytes),0),MIN(committed_at) FROM segments WHERE projected_at IS NULL`).Scan(&status.PendingSegments, &status.PendingBytes, &oldest)
	} else {
		err = s.control.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(uncompressed_bytes),0),MIN(committed_at) FROM segments WHERE projected_at IS NULL AND organization_id=?`, organizationID).Scan(&status.PendingSegments, &status.PendingBytes, &oldest)
	}
	if err != nil {
		return ProjectionStatus{}, fmt.Errorf("read projection status: %w", err)
	}
	if oldest.Valid {
		parsed, parseErr := time.Parse(time.RFC3339Nano, oldest.String)
		if parseErr != nil {
			return ProjectionStatus{}, errors.New("projection status contains an invalid timestamp")
		}
		status.OldestCommitted = parsed.UTC()
		if now.After(status.OldestCommitted) {
			status.OldestPendingLag = now.Sub(status.OldestCommitted)
		}
	}
	return status, nil
}

// ProjectPending projects a bounded set of already-durable segments. It
// groups work by organization so one SQLite transaction can safely amortize
// multiple agent batches without crossing tenant databases.
func (s *Store) ProjectPending(ctx context.Context) (ProjectionReport, error) {
	s.projectorMu.Lock()
	defer s.projectorMu.Unlock()

	pending, err := s.pendingProjections(ctx)
	if err != nil || len(pending) == 0 {
		return ProjectionReport{}, err
	}
	groups := boundedProjectionGroups(pending)
	type projectionResult struct {
		report ProjectionReport
		err    error
	}
	results := make([]projectionResult, len(groups))
	workers := min(len(groups), projectionWorkerLimit)
	jobs := make(chan int)
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for index := range jobs {
				results[index].report, results[index].err = s.projectPendingGroup(ctx, groups[index])
			}
		}()
	}
	for index := range groups {
		jobs <- index
	}
	close(jobs)
	wait.Wait()

	var report ProjectionReport
	var projectionErrors []error
	for _, result := range results {
		if result.err != nil {
			projectionErrors = append(projectionErrors, result.err)
			continue
		}
		report.ProjectedSegments += result.report.ProjectedSegments
		report.ProjectedRecords += result.report.ProjectedRecords
		report.ProjectedBytes += result.report.ProjectedBytes
	}
	return report, errors.Join(projectionErrors...)
}

func (s *Store) pendingProjections(ctx context.Context) ([]pendingProjection, error) {
	rows, err := s.control.QueryContext(ctx, `WITH ranked AS (
		SELECT g.digest,g.path,g.uncompressed_bytes,g.source_id,g.stream_id,g.sequence,g.committed_at,g.organization_id,
			s.organization_id AS source_organization_id,s.project_id,s.environment_id,s.service_id,
			ROW_NUMBER() OVER (PARTITION BY g.organization_id ORDER BY g.committed_at,g.digest) AS organization_rank
		FROM segments AS g JOIN sources AS s ON s.id=g.source_id
		WHERE g.projected_at IS NULL
	)
	SELECT digest,path,uncompressed_bytes,source_id,stream_id,sequence,committed_at,organization_id,source_organization_id,project_id,environment_id,service_id
	FROM ranked WHERE organization_rank<=? ORDER BY committed_at,digest LIMIT ?`, projectionGroupMaxSegments, recoveryPageSize)
	if err != nil {
		return nil, fmt.Errorf("list unprojected segments: %w", err)
	}
	defer rows.Close()
	pending := make([]pendingProjection, 0, recoveryPageSize)
	for rows.Next() {
		var item pendingProjection
		var committedAt string
		if err = rows.Scan(&item.digest, &item.path, &item.uncompressedBytes, &item.sourceID, &item.streamID, &item.sequence, &committedAt, &item.catalogOrgID, &item.scope.OrganizationID, &item.scope.ProjectID, &item.scope.EnvironmentID, &item.scope.ServiceID); err != nil {
			return nil, fmt.Errorf("scan unprojected segment: %w", err)
		}
		item.committedAt, err = time.Parse(time.RFC3339Nano, committedAt)
		if err != nil {
			return nil, errors.New("unprojected segment has an invalid committed time")
		}
		pending = append(pending, item)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate unprojected segments: %w", err)
	}
	return pending, nil
}

func boundedProjectionGroups(pending []pendingProjection) []pendingProjectionGroup {
	groups := make([]pendingProjectionGroup, 0)
	byOrganization := make(map[string]int)
	for _, item := range pending {
		index, exists := byOrganization[item.scope.OrganizationID]
		if !exists {
			index = len(groups)
			byOrganization[item.scope.OrganizationID] = index
			groups = append(groups, pendingProjectionGroup{organizationID: item.scope.OrganizationID})
		}
		group := &groups[index]
		if len(group.segments) >= projectionGroupMaxSegments {
			continue
		}
		if len(group.segments) > 0 && group.bytes+item.uncompressedBytes > projectionGroupMaxBytes {
			continue
		}
		group.segments = append(group.segments, item)
		group.bytes += item.uncompressedBytes
	}
	return groups
}

func (s *Store) projectPendingGroup(ctx context.Context, group pendingProjectionGroup) (ProjectionReport, error) {
	if len(group.segments) == 0 {
		return ProjectionReport{}, nil
	}
	lock := s.namedLock("organization:" + group.organizationID)
	lock.Lock()
	defer lock.Unlock()

	items := make([]projectionItem, 0, len(group.segments))
	report := ProjectionReport{ProjectedSegments: len(group.segments), ProjectedBytes: group.bytes}
	for _, pending := range group.segments {
		batch, err := s.segments.Read(pending.path, pending.digest)
		if err != nil {
			return ProjectionReport{}, fmt.Errorf("read pending projection segment: %w", err)
		}
		if batch.SourceID != pending.sourceID || batch.StreamID != pending.streamID || batch.Sequence != pending.sequence || pending.catalogOrgID != group.organizationID || pending.scope.OrganizationID != group.organizationID {
			return ProjectionReport{}, errors.New("pending projection identity does not match durable catalog")
		}
		if err = batch.Validate(batch.ObservedAt); err != nil {
			return ProjectionReport{}, fmt.Errorf("validate pending projection batch: %w", err)
		}
		if err = validateMetricRollupCardinality(batch); err != nil {
			return ProjectionReport{}, fmt.Errorf("validate pending projection cardinality: %w", err)
		}
		report.ProjectedRecords += len(batch.Records)
		items = append(items, projectionItem{scope: pending.scope, batch: batch, digest: pending.digest})
	}
	db, err := s.projection(ctx, group.organizationID)
	if err != nil {
		return ProjectionReport{}, err
	}
	if err = projectGroupWithDB(ctx, db, items); err != nil {
		return ProjectionReport{}, err
	}
	projectedAt := time.Now().UTC()
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return ProjectionReport{}, fmt.Errorf("begin projection acknowledgement: %w", err)
	}
	defer tx.Rollback()
	for index, item := range items {
		if err = recordDescriptorProposalsTx(ctx, tx, group.organizationID, item.batch, item.digest, group.segments[index].committedAt); err != nil {
			return ProjectionReport{}, err
		}
		if err = markProjectedTx(ctx, tx, item.batch, item.digest, projectedAt); err != nil {
			return ProjectionReport{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return ProjectionReport{}, fmt.Errorf("commit projection acknowledgement: %w", err)
	}
	return report, nil
}

// RunProjector continuously drains durable work, then sleeps until ingestion
// wakes it or the reconciliation interval expires. Errors leave raw segments
// pending and are retried without making acknowledgement availability depend
// on query projection health.
func (s *Store) RunProjector(ctx context.Context, interval time.Duration, onError func(error)) {
	if interval <= 0 {
		interval = defaultProjectorInterval
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-s.projectionWake:
		}
		report, err := s.ProjectPending(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && onError != nil {
			onError(err)
		}
		delay := interval
		if err == nil && report.ProjectedSegments > 0 {
			delay = 0
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(delay)
	}
}
