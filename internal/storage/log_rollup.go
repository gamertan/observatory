// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"gamertan.com/observatory/internal/model"
)

const (
	logRollupVersion        = 1
	logRollupWindow         = 5 * time.Minute
	maxLogRollupGroupsBatch = model.MaxRecords
)

const logObservationBytesSQL = `64+LENGTH(project_id)+LENGTH(environment_id)+LENGTH(service_id)+LENGTH(source_id)+LENGTH(stream_id)+LENGTH(signal)+LENGTH(timestamp)+LENGTH(name)+COALESCE(LENGTH(severity),0)+COALESCE(LENGTH(body),0)+COALESCE(LENGTH(trace_id),0)+COALESCE(LENGTH(span_id),0)+COALESCE(LENGTH(correlation_id),0)+LENGTH(attributes_json)`

type logRollup struct {
	projectID, environmentID, serviceID, route string
	bucket                                     int64
	status, routePresent                       int
	count, scannedBytes                        int64
}

func ensureLogRollups(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin log rollup migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS log_rollup_state (id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version BETWEEN 0 AND 1))`,
		`INSERT OR IGNORE INTO log_rollup_state(id,version) VALUES(1,0)`,
		`CREATE TABLE IF NOT EXISTS log_status_route_rollups_5m (
			organization_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			environment_id TEXT NOT NULL,
			service_id TEXT NOT NULL,
			bucket_start INTEGER NOT NULL,
			status INTEGER NOT NULL CHECK(status BETWEEN 100 AND 999),
			route TEXT NOT NULL,
			route_present INTEGER NOT NULL CHECK(route_present IN (0,1)),
			observation_count INTEGER NOT NULL CHECK(typeof(observation_count)='integer' AND observation_count > 0),
			scanned_bytes INTEGER NOT NULL CHECK(typeof(scanned_bytes)='integer' AND scanned_bytes >= 0),
			PRIMARY KEY(organization_id,project_id,environment_id,service_id,bucket_start,status,route,route_present)
		)`,
		`CREATE TABLE IF NOT EXISTS log_rollup_segments (segment_digest TEXT PRIMARY KEY)`,
		`CREATE INDEX IF NOT EXISTS log_rollups_status_time ON log_status_route_rollups_5m(organization_id,status,bucket_start)`,
		`CREATE INDEX IF NOT EXISTS log_rollups_scope_time ON log_status_route_rollups_5m(organization_id,project_id,environment_id,service_id,bucket_start,status)`,
	} {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate log rollups: %w", err)
		}
	}
	var version int
	if err = tx.QueryRowContext(ctx, `SELECT version FROM log_rollup_state WHERE id=1`).Scan(&version); err != nil {
		return errors.New("read log rollup migration state")
	}
	if version == 0 {
		if _, err = tx.ExecContext(ctx, `DELETE FROM log_status_route_rollups_5m`); err != nil {
			return errors.New("clear incomplete log rollup migration")
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM log_rollup_segments`); err != nil {
			return errors.New("clear incomplete log rollup ledger")
		}
		status := `json_extract(attributes_json,'$."http.status_code"')`
		route := `json_extract(attributes_json,'$."http.route"')`
		statement := `INSERT INTO log_status_route_rollups_5m(organization_id,project_id,environment_id,service_id,bucket_start,status,route,route_present,observation_count,scanned_bytes)
			SELECT organization_id,project_id,environment_id,service_id,CAST(unixepoch(timestamp)/300 AS INTEGER)*300,CAST(` + status + ` AS INTEGER),COALESCE(CAST(` + route + ` AS TEXT),''),CASE WHEN json_type(attributes_json,'$."http.route"') IS NULL THEN 0 ELSE 1 END,COUNT(*),SUM(` + logObservationBytesSQL + `)
			FROM observations WHERE signal=? AND printf('%d',CAST(` + status + ` AS INTEGER))=` + status + ` AND CAST(` + status + ` AS INTEGER) BETWEEN 100 AND 999
			GROUP BY organization_id,project_id,environment_id,service_id,CAST(unixepoch(timestamp)/300 AS INTEGER)*300,CAST(` + status + ` AS INTEGER),COALESCE(CAST(` + route + ` AS TEXT),''),CASE WHEN json_type(attributes_json,'$."http.route"') IS NULL THEN 0 ELSE 1 END`
		if _, err = tx.ExecContext(ctx, statement, model.SignalLogs); err != nil {
			return errors.New("backfill log rollups")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO log_rollup_segments(segment_digest) SELECT DISTINCT segment_digest FROM observations WHERE signal=?`, model.SignalLogs); err != nil {
			return errors.New("record backfilled log rollup segments")
		}
		if _, err = tx.ExecContext(ctx, `UPDATE log_rollup_state SET version=? WHERE id=1 AND version=0`, logRollupVersion); err != nil {
			return errors.New("activate log rollup migration")
		}
	}
	if version != 0 && version != logRollupVersion {
		return errors.New("unsupported log rollup version")
	}
	if err = tx.Commit(); err != nil {
		return errors.New("commit log rollup migration")
	}
	return nil
}

func projectLogRollups(ctx context.Context, tx *sql.Tx, scope model.Scope, batch model.Batch, segmentDigest string, observationBytes []int64) error {
	if batch.Signal != model.SignalLogs {
		return nil
	}
	if len(observationBytes) != len(batch.Records) {
		return errors.New("log projection byte evidence is incomplete")
	}
	ledger, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO log_rollup_segments(segment_digest) VALUES(?)`, segmentDigest)
	if err != nil {
		return errors.New("record log rollup segment")
	}
	inserted, err := ledger.RowsAffected()
	if err != nil {
		return errors.New("inspect log rollup segment")
	}
	if inserted == 0 {
		return nil
	}
	groups := map[string]*logRollup{}
	for index, observation := range batch.Records {
		statusText, ok := observation.Attributes["http.status_code"]
		if !ok {
			continue
		}
		status, statusErr := strconv.Atoi(statusText)
		if statusErr != nil || strconv.Itoa(status) != statusText || status < 100 || status > 999 {
			continue
		}
		route, routeOK := observation.Attributes["http.route"]
		routePresent := 0
		if routeOK {
			routePresent = 1
		}
		bucket := observation.Timestamp.UTC().Truncate(logRollupWindow).Unix()
		key := scope.ProjectID + "\x00" + scope.EnvironmentID + "\x00" + scope.ServiceID + "\x00" + strconv.FormatInt(bucket, 10) + "\x00" + statusText + "\x00" + strconv.Itoa(routePresent) + "\x00" + route
		group := groups[key]
		if group == nil {
			group = &logRollup{projectID: scope.ProjectID, environmentID: scope.EnvironmentID, serviceID: scope.ServiceID, bucket: bucket, status: status, route: route, routePresent: routePresent}
			groups[key] = group
			if len(groups) > maxLogRollupGroupsBatch {
				return fmt.Errorf("log batch exceeds %d rollup groups", maxLogRollupGroupsBatch)
			}
		}
		bytes := observationBytes[index]
		if bytes < 0 {
			return errors.New("log projection byte evidence is invalid")
		}
		if group.count == math.MaxInt64 || bytes > math.MaxInt64-group.scannedBytes {
			return errors.New("log rollup count exceeds integer range")
		}
		group.count++
		group.scannedBytes += bytes
	}
	for _, group := range groups {
		_, err = tx.ExecContext(ctx, `INSERT INTO log_status_route_rollups_5m(organization_id,project_id,environment_id,service_id,bucket_start,status,route,route_present,observation_count,scanned_bytes) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(organization_id,project_id,environment_id,service_id,bucket_start,status,route,route_present) DO UPDATE SET observation_count=log_status_route_rollups_5m.observation_count+excluded.observation_count,scanned_bytes=log_status_route_rollups_5m.scanned_bytes+excluded.scanned_bytes`, scope.OrganizationID, group.projectID, group.environmentID, group.serviceID, group.bucket, group.status, group.route, group.routePresent, group.count, group.scannedBytes)
		if err != nil {
			return errors.New("merge log rollup")
		}
	}
	return nil
}

func projectedObservationBytes(scope model.Scope, batch model.Batch, observation model.Observation, attributesBytes int) int64 {
	return int64(64 + len(scope.ProjectID) + len(scope.EnvironmentID) + len(scope.ServiceID) + len(batch.SourceID) + len(batch.StreamID) + len(batch.Signal) + len(observation.Timestamp.UTC().Format(time.RFC3339Nano)) + len(observation.Name) + len(observation.Severity) + len(observation.Body) + len(observation.TraceID) + len(observation.SpanID) + len(observation.CorrelationID) + attributesBytes)
}
