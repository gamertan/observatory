// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const baseIndexVersion = 1

var presenceIndexStatements = []string{
	`CREATE INDEX IF NOT EXISTS observations_value ON observations(signal,value,timestamp) WHERE value IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS observations_http_route ON observations(signal,json_extract(attributes_json,'$."http.route"'),timestamp) WHERE json_extract(attributes_json,'$."http.route"') IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS observations_http_status ON observations(signal,CAST(json_extract(attributes_json,'$."http.status_code"') AS INTEGER),timestamp) WHERE CAST(json_extract(attributes_json,'$."http.status_code"') AS INTEGER) IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS observations_duration ON observations(signal,CAST(json_extract(attributes_json,'$."duration_ns"') AS REAL),timestamp) WHERE CAST(json_extract(attributes_json,'$."duration_ns"') AS REAL) IS NOT NULL`,
}

// ensureBaseIndexes migrates fields that are absent from most signal types to
// presence-only indexes. The DDL and migration marker share one SQLite
// transaction: an interrupted migration retains the complete previous index
// set and retries before the projection is served.
func ensureBaseIndexes(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin base index migration: %w", err)
	}
	defer tx.Rollback()
	columns, err := sqliteColumns(tx, "storage_projection_state")
	if err != nil {
		return err
	}
	if !columns["base_index_version"] {
		if _, err = tx.ExecContext(ctx, `ALTER TABLE storage_projection_state ADD COLUMN base_index_version INTEGER NOT NULL DEFAULT 0 CHECK(base_index_version BETWEEN 0 AND 1)`); err != nil {
			return errors.New("add base index migration state")
		}
	}
	var version int
	if err = tx.QueryRowContext(ctx, `SELECT base_index_version FROM storage_projection_state WHERE id=1`).Scan(&version); err != nil {
		return errors.New("read base index migration state")
	}
	if version < 0 || version > baseIndexVersion {
		return errors.New("unsupported base index version")
	}
	if version == 0 {
		for _, name := range []string{"observations_value", "observations_http_route", "observations_http_status", "observations_duration"} {
			if _, err = tx.ExecContext(ctx, `DROP INDEX IF EXISTS `+name); err != nil {
				return errors.New("remove superseded base index")
			}
		}
	}
	for _, statement := range presenceIndexStatements {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return errors.New("create presence-only base index")
		}
	}
	if version == 0 {
		if _, err = tx.ExecContext(ctx, `UPDATE storage_projection_state SET base_index_version=? WHERE id=1 AND base_index_version=0`, baseIndexVersion); err != nil {
			return errors.New("activate base index migration")
		}
	}
	if err = tx.Commit(); err != nil {
		return errors.New("commit base index migration")
	}
	return nil
}
