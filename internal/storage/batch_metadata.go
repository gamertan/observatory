// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"database/sql"
	"errors"
	"fmt"
)

func migrateControlBatchMetadata(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return errors.New("begin batch metadata migration")
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`ALTER TABLE segments ADD COLUMN record_count INTEGER NOT NULL DEFAULT 0 CHECK(record_count BETWEEN 0 AND 5000)`,
		`UPDATE schema_version SET version=10 WHERE version=9`,
	} {
		if _, err = tx.Exec(statement); err != nil {
			return fmt.Errorf("migrate batch metadata: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return errors.New("commit batch metadata migration")
	}
	return nil
}
