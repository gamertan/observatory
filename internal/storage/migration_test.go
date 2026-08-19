// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestControlSchemaFourMigratesThroughRetentionSchema(t *testing.T) {
	db := openSchemaDatabase(t, 4)
	defer db.Close()
	var err error
	if err = migrateControl(db); err != nil {
		t.Fatal(err)
	}
	var version int
	if err = db.QueryRow(`SELECT version FROM schema_version`).Scan(&version); err != nil || version != controlSchema {
		t.Fatalf("version=%d err=%v", version, err)
	}
	for _, table := range []string{"alert_rules", "incidents", "incident_events", "organization_retention_policies", "retention_policy_events", "source_alert_transitions"} {
		var count int
		if err = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("table=%s count=%d err=%v", table, count, err)
		}
	}
	columns, err := sqliteColumns(db, "segments")
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"signal", "first_observed_at", "last_observed_at", "record_count", "tier", "archiving_at", "archive_path", "cold_at", "retiring_at"} {
		if !columns[column] {
			t.Fatalf("missing segment column %s", column)
		}
	}
	policyColumns, err := sqliteColumns(db, "organization_retention_policies")
	if err != nil || !policyColumns["cold_raw_days"] || !policyColumns["delete_cold_raw"] {
		t.Fatalf("retention policy cold=%t delete=%t err=%v", policyColumns["cold_raw_days"], policyColumns["delete_cold_raw"], err)
	}
	streamColumns, err := sqliteColumns(db, "streams")
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"last_batch_digest", "last_wire_digest", "last_signal", "last_record_count", "last_encoded_bytes", "last_first_observed_at", "last_last_observed_at"} {
		if !streamColumns[column] {
			t.Fatalf("missing stream envelope column %s", column)
		}
	}
}

func TestControlSchemaSevenMigratesToForensicPreservation(t *testing.T) {
	db := openSchemaDatabase(t, 6)
	defer db.Close()
	if err := migrateControlRetention(db); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRow(`SELECT version FROM schema_version`).Scan(&version); err != nil || version != 7 {
		t.Fatalf("pre-migration version=%d err=%v", version, err)
	}
	if err := migrateControl(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO organization_retention_policies(organization_id,raw_logs_days,raw_traces_days,raw_metrics_days,cold_raw_days,metric_rollups_days,evidence_days,updated_by,updated_at) VALUES('org',30,30,14,400,400,400,'owner','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	var deleteColdRaw bool
	if err := db.QueryRow(`SELECT delete_cold_raw FROM organization_retention_policies WHERE organization_id='org'`).Scan(&deleteColdRaw); err != nil || deleteColdRaw {
		t.Fatalf("delete_cold_raw=%t err=%v", deleteColdRaw, err)
	}
}

func TestControlSchemaTenPreservesExistingStreamWatermark(t *testing.T) {
	db := openSchemaDatabase(t, 10)
	defer db.Close()
	if _, err := db.Exec(`
		CREATE TABLE sources (
			id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, project_id TEXT NOT NULL,
			environment_id TEXT NOT NULL, service_id TEXT NOT NULL,
			credential_digest BLOB NOT NULL UNIQUE, active INTEGER NOT NULL,
			created_at TEXT NOT NULL, rotated_at TEXT
		);
		CREATE TABLE streams (
			source_id TEXT NOT NULL REFERENCES sources(id), stream_id TEXT NOT NULL,
			last_sequence INTEGER NOT NULL, last_digest TEXT NOT NULL,
			PRIMARY KEY(source_id,stream_id)
		);
		INSERT INTO sources VALUES('source','org','project','prod','service',X'01',1,'2026-08-18T20:00:00Z',NULL);
		INSERT INTO streams VALUES('source','logs',42,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
	`); err != nil {
		t.Fatal(err)
	}
	if err := migrateControl(db); err != nil {
		t.Fatal(err)
	}
	var sequence int
	var segmentDigest, batchDigest, wireDigest string
	if err := db.QueryRow(`SELECT last_sequence,last_digest,last_batch_digest,last_wire_digest FROM streams WHERE source_id='source' AND stream_id='logs'`).Scan(&sequence, &segmentDigest, &batchDigest, &wireDigest); err != nil {
		t.Fatal(err)
	}
	if sequence != 42 || segmentDigest != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || batchDigest != "" || wireDigest != "" {
		t.Fatalf("sequence=%d segment=%q batch=%q wire=%q", sequence, segmentDigest, batchDigest, wireDigest)
	}
}

func openSchemaDatabase(t *testing.T, version int) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "control.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version(version) VALUES(?)`, version); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db
}
