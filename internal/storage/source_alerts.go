// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gamertan.com/observatory/internal/model"
)

type SourceAlertTransitionAck struct {
	SourceID     string `json:"source_id"`
	RuleID       string `json:"rule_id"`
	RuleRevision int    `json:"rule_revision"`
	AgentEpoch   string `json:"agent_epoch"`
	Sequence     uint64 `json:"sequence"`
	Digest       string `json:"digest"`
	Duplicate    bool   `json:"duplicate"`
}

func migrateControlSourceAlertTransitions(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return errors.New("begin source alert transition migration")
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TABLE source_alert_transitions (
			organization_id TEXT NOT NULL,
			source_id TEXT NOT NULL,
			rule_id TEXT NOT NULL,
			rule_revision INTEGER NOT NULL CHECK(rule_revision BETWEEN 1 AND 1000000),
			agent_epoch TEXT NOT NULL CHECK(length(agent_epoch)=32),
			transition_sequence INTEGER NOT NULL CHECK(transition_sequence >= 1),
			stream_id TEXT NOT NULL,
			batch_sequence INTEGER NOT NULL CHECK(batch_sequence >= 1),
			segment_digest TEXT NOT NULL,
			window_start TEXT NOT NULL,
			window_end TEXT NOT NULL,
			state TEXT NOT NULL CHECK(state IN ('matched','clear','error')),
			observed_at TEXT NOT NULL,
			received_at TEXT NOT NULL,
			transition_digest TEXT NOT NULL CHECK(length(transition_digest)=64),
			PRIMARY KEY(source_id,rule_id,rule_revision,agent_epoch,transition_sequence),
			FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE RESTRICT,
			FOREIGN KEY(organization_id,rule_id) REFERENCES alert_rules(organization_id,id) ON DELETE RESTRICT,
			FOREIGN KEY(segment_digest) REFERENCES segments(digest) ON DELETE RESTRICT
		)`,
		`CREATE INDEX source_alert_transitions_by_rule ON source_alert_transitions(organization_id,rule_id,observed_at,source_id,agent_epoch,transition_sequence)`,
		`UPDATE schema_version SET version=9 WHERE version=8`,
	} {
		if _, err = tx.Exec(statement); err != nil {
			return fmt.Errorf("migrate source alert transitions: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return errors.New("commit source alert transition migration")
	}
	return nil
}

func (s *Store) RecordSourceAlertTransition(ctx context.Context, token string, transition model.AlertTransition, now time.Time) (SourceAlertTransitionAck, error) {
	if err := transition.Validate(now); err != nil {
		return SourceAlertTransitionAck{}, err
	}
	digest, err := transition.Digest()
	if err != nil {
		return SourceAlertTransitionAck{}, err
	}
	source, err := s.Authenticate(ctx, token)
	if err != nil {
		return SourceAlertTransitionAck{}, err
	}
	ack := SourceAlertTransitionAck{SourceID: source.ID, RuleID: transition.RuleID, RuleRevision: transition.RuleRevision, AgentEpoch: transition.AgentEpoch, Sequence: transition.Sequence, Digest: digest}
	lock := s.namedLock("source-alert:" + source.ID + ":" + transition.RuleID + ":" + transition.AgentEpoch)
	lock.Lock()
	defer lock.Unlock()

	var existing string
	err = s.control.QueryRowContext(ctx, `SELECT transition_digest FROM source_alert_transitions WHERE source_id=? AND rule_id=? AND rule_revision=? AND agent_epoch=? AND transition_sequence=?`, source.ID, transition.RuleID, transition.RuleRevision, transition.AgentEpoch, transition.Sequence).Scan(&existing)
	if err == nil {
		if existing != digest {
			return SourceAlertTransitionAck{}, errors.New("alert transition sequence reused with different content")
		}
		ack.Duplicate = true
		return ack, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return SourceAlertTransitionAck{}, errors.New("read source alert transition")
	}

	rule, err := s.AlertRule(ctx, source.Scope.OrganizationID, transition.RuleID)
	if err != nil || !rule.Enabled || rule.Revision != transition.RuleRevision {
		return SourceAlertTransitionAck{}, errors.New("source alert rule is unavailable")
	}
	saved, err := s.SavedQuery(ctx, source.Scope.OrganizationID, rule.SavedQueryID)
	if err != nil || saved.AST.Signal != model.SignalLogs || saved.Scope.ProjectID != source.Scope.ProjectID || saved.Scope.EnvironmentID != source.Scope.EnvironmentID || saved.Scope.ServiceID != source.Scope.ServiceID {
		return SourceAlertTransitionAck{}, errors.New("source alert rule is not scoped to this source")
	}

	var segmentOrganization, segmentSignal, firstText, lastText string
	err = s.control.QueryRowContext(ctx, `SELECT organization_id,signal,first_observed_at,last_observed_at FROM segments WHERE digest=? AND source_id=? AND stream_id=? AND sequence=? AND retiring_at IS NULL`, transition.SegmentDigest, source.ID, transition.StreamID, transition.BatchSequence).Scan(&segmentOrganization, &segmentSignal, &firstText, &lastText)
	if errors.Is(err, sql.ErrNoRows) {
		return SourceAlertTransitionAck{}, errors.New("source alert evidence is unavailable")
	}
	if err != nil {
		return SourceAlertTransitionAck{}, errors.New("read source alert evidence")
	}
	first, firstErr := time.Parse(time.RFC3339Nano, firstText)
	last, lastErr := time.Parse(time.RFC3339Nano, lastText)
	if firstErr != nil || lastErr != nil || segmentOrganization != source.Scope.OrganizationID || segmentSignal != string(model.SignalLogs) || transition.WindowStart.After(first) || transition.WindowEnd.Before(last) {
		return SourceAlertTransitionAck{}, errors.New("source alert evidence does not match transition")
	}

	var previous uint64
	if err = s.control.QueryRowContext(ctx, `SELECT COALESCE(MAX(transition_sequence),0) FROM source_alert_transitions WHERE source_id=? AND rule_id=? AND rule_revision=? AND agent_epoch=?`, source.ID, transition.RuleID, transition.RuleRevision, transition.AgentEpoch).Scan(&previous); err != nil {
		return SourceAlertTransitionAck{}, errors.New("read source alert transition watermark")
	}
	if previous != 0 && transition.Sequence != previous+1 {
		return SourceAlertTransitionAck{}, errors.New("source alert transition sequence gap")
	}
	_, err = s.control.ExecContext(ctx, `INSERT INTO source_alert_transitions(organization_id,source_id,rule_id,rule_revision,agent_epoch,transition_sequence,stream_id,batch_sequence,segment_digest,window_start,window_end,state,observed_at,received_at,transition_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, source.Scope.OrganizationID, source.ID, transition.RuleID, transition.RuleRevision, transition.AgentEpoch, transition.Sequence, transition.StreamID, transition.BatchSequence, transition.SegmentDigest, transition.WindowStart.UTC().Format(time.RFC3339Nano), transition.WindowEnd.UTC().Format(time.RFC3339Nano), transition.State, transition.ObservedAt.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano), digest)
	if err != nil {
		return SourceAlertTransitionAck{}, errors.New("record source alert transition")
	}
	return ack, nil
}
