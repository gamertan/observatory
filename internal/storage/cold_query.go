// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

const maxRawQuerySegments = 1_000_000

type rawQuerySegment struct {
	digest, path, sourceID, streamID    string
	projectID, environmentID, serviceID string
	tier                                string
	sequence                            uint64
	uncompressedBytes                   int64
	firstObservedAt, lastObservedAt     time.Time
}

func (s *Store) coldSegmentsForQuery(ctx context.Context, ast query.AST, scope query.Scope, now time.Time) ([]rawQuerySegment, int64, error) {
	return s.rawSegmentsForQuery(ctx, ast, scope, now, false)
}

func (s *Store) allRawSegmentsForQuery(ctx context.Context, ast query.AST, scope query.Scope, now time.Time) ([]rawQuerySegment, int64, error) {
	return s.rawSegmentsForQuery(ctx, ast, scope, now, true)
}

func (s *Store) rawSegmentsForQuery(ctx context.Context, ast query.AST, scope query.Scope, now time.Time, includeHot bool) ([]rawQuerySegment, int64, error) {
	statement := `SELECT segment.digest,segment.path,segment.source_id,segment.stream_id,segment.sequence,segment.uncompressed_bytes,segment.first_observed_at,segment.last_observed_at,segment.tier,segment.archiving_at,segment.retiring_at,source.project_id,source.environment_id,source.service_id FROM segments segment JOIN sources source ON source.id=segment.source_id WHERE segment.organization_id=? AND source.organization_id=segment.organization_id AND segment.signal=?`
	if includeHot {
		statement += ` AND segment.tier IN ('hot','cold')`
	} else {
		statement += ` AND segment.tier='cold' AND segment.retiring_at IS NULL`
	}
	arguments := []any{scope.OrganizationID, ast.Signal}
	for _, selected := range []struct{ column, value string }{{"source.project_id", scope.ProjectID}, {"source.environment_id", scope.EnvironmentID}, {"source.service_id", scope.ServiceID}} {
		if selected.value != "" {
			statement += " AND " + selected.column + "=?"
			arguments = append(arguments, selected.value)
		}
	}
	if ast.Window > 0 {
		statement += " AND segment.last_observed_at>=?"
		arguments = append(arguments, now.UTC().Add(-ast.Window).Format(time.RFC3339Nano))
	}
	statement += ` ORDER BY segment.last_observed_at DESC,segment.source_id,segment.stream_id,segment.sequence DESC`
	rows, err := s.control.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, 0, errors.New("list raw query segments")
	}
	defer rows.Close()
	segments := make([]rawQuerySegment, 0)
	var estimated int64
	for rows.Next() {
		if len(segments) >= maxRawQuerySegments {
			return nil, 0, errors.New("raw query segment limit exceeded")
		}
		var segment rawQuerySegment
		var firstText, lastText string
		var archivingAt, retiringAt sql.NullString
		if err = rows.Scan(&segment.digest, &segment.path, &segment.sourceID, &segment.streamID, &segment.sequence, &segment.uncompressedBytes, &firstText, &lastText, &segment.tier, &archivingAt, &retiringAt, &segment.projectID, &segment.environmentID, &segment.serviceID); err != nil {
			return nil, 0, errors.New("read raw query segment")
		}
		if includeHot && (archivingAt.Valid || retiringAt.Valid) {
			return nil, 0, errors.New("raw query segment transition is incomplete")
		}
		segment.firstObservedAt, err = time.Parse(time.RFC3339Nano, firstText)
		if err != nil {
			return nil, 0, errors.New("raw query segment range is invalid")
		}
		segment.lastObservedAt, err = time.Parse(time.RFC3339Nano, lastText)
		if err != nil || segment.lastObservedAt.Before(segment.firstObservedAt) || segment.uncompressedBytes < 1 {
			return nil, 0, errors.New("raw query segment range is invalid")
		}
		var expected string
		var pathErr error
		if segment.tier == "cold" {
			expected, pathErr = s.coldArchivePath(scope.OrganizationID, archivingSegment{digest: segment.digest, path: segment.path, sourceID: segment.sourceID, streamID: segment.streamID, signal: ast.Signal})
		} else if segment.tier == "hot" && model.ValidateSourceID(scope.OrganizationID) == nil && model.ValidateSourceID(segment.sourceID) == nil && model.ValidateStreamID(segment.streamID) == nil {
			expected = filepath.Join(s.root, "raw", scope.OrganizationID, segment.sourceID, segment.streamID, fmt.Sprintf("%020d-%s.zst", segment.sequence, segment.digest))
		} else {
			pathErr = errors.New("unsupported raw segment tier")
		}
		if pathErr != nil || expected != segment.path {
			return nil, 0, errors.New("raw query segment path is invalid")
		}
		if segment.uncompressedBytes > math.MaxInt64-estimated {
			return nil, 0, errors.New("raw query estimate overflow")
		}
		estimated += segment.uncompressedBytes
		segments = append(segments, segment)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, errors.New("list raw query segments")
	}
	return segments, estimated, nil
}

func rawRecord(segment rawQuerySegment, batch model.Batch, index int) projectedRecord {
	observation := batch.Records[index]
	return projectedRecord{
		projectID: segment.projectID, environmentID: segment.environmentID, serviceID: segment.serviceID,
		sourceID: segment.sourceID, streamID: segment.streamID, sequence: batch.Sequence, recordIndex: index,
		signal: batch.Signal, timestamp: observation.Timestamp.UTC(), name: observation.Name, severity: observation.Severity,
		body: observation.Body, value: observation.Value, traceID: observation.TraceID, spanID: observation.SpanID,
		correlationID: observation.CorrelationID, attributes: observation.Attributes,
	}
}

func rawRecordMemory(record projectedRecord) int64 {
	total := int64(256 + len(record.projectID) + len(record.environmentID) + len(record.serviceID) + len(record.sourceID) + len(record.streamID) + len(record.name) + len(record.severity) + len(record.body) + len(record.traceID) + len(record.spanID) + len(record.correlationID))
	for key, value := range record.attributes {
		addition := int64(len(key) + len(value) + 32)
		if addition > math.MaxInt64-total {
			return math.MaxInt64
		}
		total += addition
	}
	return total
}
