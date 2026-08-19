// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"gamertan.com/observatory/internal/model"
)

func migrateControlBatchEnvelopes(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return errors.New("begin batch envelope migration")
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`ALTER TABLE streams ADD COLUMN last_batch_digest TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE streams ADD COLUMN last_wire_digest TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE streams ADD COLUMN last_signal TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE streams ADD COLUMN last_record_count INTEGER NOT NULL DEFAULT 0 CHECK(last_record_count BETWEEN 0 AND 5000)`,
		`ALTER TABLE streams ADD COLUMN last_encoded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(last_encoded_bytes >= 0)`,
		`ALTER TABLE streams ADD COLUMN last_first_observed_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE streams ADD COLUMN last_last_observed_at TEXT NOT NULL DEFAULT ''`,
		`UPDATE schema_version SET version=11 WHERE version=10`,
	} {
		if _, err = tx.Exec(statement); err != nil {
			return fmt.Errorf("migrate batch envelope metadata: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return errors.New("commit batch envelope migration")
	}
	return nil
}

type streamWatermark struct {
	sequence      uint64
	segmentDigest string
	envelope      model.BatchEnvelope
	found         bool
	framed        bool
}

func (s *Store) streamWatermark(ctx context.Context, sourceID, streamID string) (streamWatermark, error) {
	var watermark streamWatermark
	var signal, first, last string
	err := s.control.QueryRowContext(ctx, `SELECT last_sequence,last_digest,last_batch_digest,last_wire_digest,last_signal,last_record_count,last_encoded_bytes,last_first_observed_at,last_last_observed_at FROM streams WHERE source_id=? AND stream_id=?`, sourceID, streamID).Scan(
		&watermark.sequence, &watermark.segmentDigest, &watermark.envelope.BatchDigest,
		&watermark.envelope.WireDigest, &signal, &watermark.envelope.RecordCount,
		&watermark.envelope.EncodedBytes, &first, &last,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return streamWatermark{}, nil
	}
	if err != nil {
		return streamWatermark{}, fmt.Errorf("read framed stream watermark: %w", err)
	}
	watermark.found = true
	if watermark.envelope.BatchDigest == "" && watermark.envelope.WireDigest == "" {
		return watermark, nil
	}
	firstObserved, firstErr := time.Parse(time.RFC3339Nano, first)
	lastObserved, lastErr := time.Parse(time.RFC3339Nano, last)
	if firstErr != nil || lastErr != nil {
		return streamWatermark{}, errors.New("stored batch envelope time range is invalid")
	}
	watermark.envelope.Version = model.BatchEnvelopeVersion
	watermark.envelope.StreamID = streamID
	watermark.envelope.Sequence = watermark.sequence
	watermark.envelope.Signal = model.Signal(signal)
	watermark.envelope.FirstObservedAt = firstObserved.UTC()
	watermark.envelope.LastObservedAt = lastObserved.UTC()
	if err = watermark.envelope.Validate(math.MaxInt64); err != nil {
		return streamWatermark{}, errors.New("stored batch envelope is invalid")
	}
	watermark.framed = true
	return watermark, nil
}

func (s *Store) checkEnvelope(ctx context.Context, source Source, envelope model.BatchEnvelope) (Ack, bool, error) {
	watermark, err := s.streamWatermark(ctx, source.ID, envelope.StreamID)
	if err != nil {
		return Ack{}, false, err
	}
	if !watermark.found {
		if envelope.Sequence != 1 {
			return Ack{}, false, errors.New("sequence gap")
		}
		return Ack{}, false, nil
	}
	if envelope.Sequence < watermark.sequence {
		return Ack{}, false, errors.New("sequence replay is older than acknowledged watermark")
	}
	if watermark.sequence != ^uint64(0) && envelope.Sequence > watermark.sequence+1 {
		return Ack{}, false, errors.New("sequence gap")
	}
	if envelope.Sequence == watermark.sequence {
		if !watermark.framed {
			return Ack{}, false, nil
		}
		if envelope != watermark.envelope {
			return Ack{}, false, errors.New("acknowledged sequence reused with different envelope")
		}
		return Ack{SourceID: source.ID, StreamID: envelope.StreamID, Sequence: envelope.Sequence, Digest: watermark.segmentDigest, BatchDigest: envelope.BatchDigest, Duplicate: true}, true, nil
	}
	return Ack{}, false, nil
}

// CheckNativeReplay performs a cheap, read-only envelope lookup before the
// request body is decoded. Callers must still hash the complete bounded body
// and ConfirmNativeReplay before acknowledging it.
func (s *Store) CheckNativeReplay(ctx context.Context, token string, envelope model.BatchEnvelope) (Ack, bool, error) {
	if err := envelope.Validate(math.MaxInt64); err != nil {
		return Ack{}, false, err
	}
	source, err := s.Authenticate(ctx, token)
	if err != nil {
		return Ack{}, false, err
	}
	return s.checkEnvelope(ctx, source, envelope)
}

func (s *Store) ConfirmNativeReplay(ctx context.Context, token string, envelope model.BatchEnvelope) (Ack, error) {
	if err := envelope.Validate(math.MaxInt64); err != nil {
		return Ack{}, err
	}
	source, err := s.Authenticate(ctx, token)
	if err != nil {
		return Ack{}, err
	}
	lock := s.sourceLock(source.ID)
	lock.Lock()
	defer lock.Unlock()
	ack, exact, err := s.checkEnvelope(ctx, source, envelope)
	if err != nil {
		return Ack{}, err
	}
	if !exact {
		return Ack{}, errors.New("batch is not an acknowledged exact replay")
	}
	return ack, nil
}

func envelopeSQL(envelope *model.BatchEnvelope) (batchDigest, wireDigest, signal string, recordCount int, encodedBytes int64, first, last string) {
	if envelope == nil {
		return "", "", "", 0, 0, "", ""
	}
	return envelope.BatchDigest, envelope.WireDigest, string(envelope.Signal), envelope.RecordCount, envelope.EncodedBytes, envelope.FirstObservedAt.UTC().Format(time.RFC3339Nano), envelope.LastObservedAt.UTC().Format(time.RFC3339Nano)
}

func (s *Store) backfillAcknowledgedEnvelope(ctx context.Context, batch model.Batch, segmentDigest string, envelope model.BatchEnvelope) error {
	batchDigest, wireDigest, signal, recordCount, encodedBytes, first, last := envelopeSQL(&envelope)
	result, err := s.control.ExecContext(ctx, `UPDATE streams SET last_batch_digest=?,last_wire_digest=?,last_signal=?,last_record_count=?,last_encoded_bytes=?,last_first_observed_at=?,last_last_observed_at=? WHERE source_id=? AND stream_id=? AND last_sequence=? AND last_digest=? AND last_batch_digest='' AND last_wire_digest=''`, batchDigest, wireDigest, signal, recordCount, encodedBytes, first, last, batch.SourceID, batch.StreamID, batch.Sequence, segmentDigest)
	if err != nil {
		return fmt.Errorf("backfill acknowledged batch envelope: %w", err)
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("acknowledged batch envelope state changed")
	}
	return nil
}
