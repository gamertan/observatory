// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
)

type StoredProposal struct {
	Proposal    schema.Proposal `json:"proposal"`
	Status      string          `json:"status"`
	FirstSeenAt time.Time       `json:"first_seen_at"`
	LastSeenAt  time.Time       `json:"last_seen_at"`
}

type fieldEvidence struct {
	descriptor schema.Descriptor
	count      int64
	bytes      int64
}

func (s *Store) descriptorProposal(ctx context.Context, organizationID string, signal model.Signal, field string) (StoredProposal, error) {
	if err := model.ValidateSourceID(organizationID); err != nil {
		return StoredProposal{}, errors.New("invalid organization identifier")
	}
	var descriptorJSON, examplesJSON, firstSeen, lastSeen string
	var proposal StoredProposal
	err := s.control.QueryRowContext(ctx, `SELECT descriptor_json,observed_values,estimated_bytes,example_queries_json,status,first_seen_at,last_seen_at FROM descriptor_proposals WHERE organization_id=? AND signal=? AND field=?`, organizationID, signal, query.CanonicalField(field)).Scan(&descriptorJSON, &proposal.Proposal.ObservedValues, &proposal.Proposal.EstimatedBytes, &examplesJSON, &proposal.Status, &firstSeen, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredProposal{}, errors.New("descriptor proposal not found")
	}
	if err != nil {
		return StoredProposal{}, errors.New("load descriptor proposal")
	}
	if err = json.Unmarshal([]byte(descriptorJSON), &proposal.Proposal.Descriptor); err != nil {
		return StoredProposal{}, errors.New("decode descriptor proposal")
	}
	if err = json.Unmarshal([]byte(examplesJSON), &proposal.Proposal.ExampleQueries); err != nil {
		return StoredProposal{}, errors.New("decode descriptor examples")
	}
	proposal.FirstSeenAt, err = time.Parse(time.RFC3339Nano, firstSeen)
	if err != nil {
		return StoredProposal{}, errors.New("descriptor proposal first-seen time is invalid")
	}
	proposal.LastSeenAt, err = time.Parse(time.RFC3339Nano, lastSeen)
	if err != nil || proposal.Proposal.Validate() != nil || proposal.Status != "pending" && proposal.Status != "activated" && proposal.Status != "rejected" {
		return StoredProposal{}, errors.New("stored descriptor proposal is invalid")
	}
	return proposal, nil
}

func (s *Store) markProposalActivated(ctx context.Context, organizationID string, descriptor schema.Descriptor) error {
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		return errors.New("encode activated descriptor")
	}
	result, err := s.control.ExecContext(ctx, `UPDATE descriptor_proposals SET descriptor_json=?,status='activated' WHERE organization_id=? AND signal=? AND field=? AND status='pending'`, string(encoded), organizationID, descriptor.Signal, descriptor.Field)
	if err != nil {
		return errors.New("acknowledge activated descriptor")
	}
	if changed, _ := result.RowsAffected(); changed == 1 {
		return nil
	}
	proposal, err := s.descriptorProposal(ctx, organizationID, descriptor.Signal, descriptor.Field)
	if err != nil || proposal.Status != "activated" || !sameDescriptorIgnoringProjection(proposal.Proposal.Descriptor, descriptor) || proposal.Proposal.Descriptor.ProjectionVersion != descriptor.ProjectionVersion {
		return errors.New("activated descriptor acknowledgement is inconsistent")
	}
	return nil
}

func (s *Store) RejectDescriptorProposal(ctx context.Context, organizationID string, signal model.Signal, field string) error {
	if err := model.ValidateSourceID(organizationID); err != nil {
		return errors.New("invalid organization identifier")
	}
	lock := s.namedLock("organization:" + organizationID)
	lock.Lock()
	defer lock.Unlock()
	registry, _, err := s.ActiveDescriptors(ctx, organizationID)
	if err != nil {
		return err
	}
	if _, active := registry.Lookup(signal, field); active {
		return errors.New("active descriptor proposal cannot be rejected")
	}
	result, err := s.control.ExecContext(ctx, `UPDATE descriptor_proposals SET status='rejected' WHERE organization_id=? AND signal=? AND field=? AND status='pending'`, organizationID, signal, query.CanonicalField(field))
	if err != nil {
		return errors.New("reject descriptor proposal")
	}
	if changed, _ := result.RowsAffected(); changed == 1 {
		return nil
	}
	proposal, err := s.descriptorProposal(ctx, organizationID, signal, field)
	if err == nil && proposal.Status == "rejected" {
		return nil
	}
	return errors.New("pending descriptor proposal not found")
}

func (s *Store) recordDescriptorProposals(ctx context.Context, organizationID string, batch model.Batch, segmentDigest string, now time.Time) error {
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = recordDescriptorProposalsTx(ctx, tx, organizationID, batch, segmentDigest, now); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return errors.New("commit descriptor proposals")
	}
	return nil
}

func recordDescriptorProposalsTx(ctx context.Context, tx *sql.Tx, organizationID string, batch model.Batch, segmentDigest string, now time.Time) error {
	if err := model.ValidateSourceID(organizationID); err != nil || !validDigest(segmentDigest) || now.IsZero() {
		return errors.New("descriptor proposal identity is invalid")
	}
	evidence := map[string]fieldEvidence{}
	for _, observation := range batch.Records {
		for field, value := range observation.Attributes {
			canonical := query.CanonicalField(field)
			if _, known := query.BuiltinDescriptor(batch.Signal, canonical); known {
				continue
			}
			current, exists := evidence[canonical]
			if !exists && len(evidence) >= model.MaxDistinctFields {
				return errors.New("descriptor proposal field limit exceeded")
			}
			descriptor := proposedDescriptor(batch.Signal, canonical, inferType(value))
			if err := descriptor.Validate(); err != nil {
				continue
			}
			if current.count > 0 {
				descriptor.Type = mergeType(current.descriptor.Type, descriptor.Type)
			}
			current.descriptor = descriptor
			current.count++
			current.bytes += int64(len(canonical) + len(value))
			evidence[canonical] = current
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	fields := make([]string, 0, len(evidence))
	for field := range evidence {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		observed := evidence[field]
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO descriptor_proposal_segments(segment_digest,organization_id,signal,field,observed_values,estimated_bytes) VALUES(?,?,?,?,?,?)`, segmentDigest, organizationID, batch.Signal, field, observed.count, observed.bytes)
		if err != nil {
			return errors.New("record descriptor proposal segment")
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return errors.New("inspect descriptor proposal segment")
		}
		if inserted == 0 {
			continue
		}
		if err = upsertProposal(ctx, tx, organizationID, batch.Signal, observed, now); err != nil {
			return err
		}
	}
	return nil
}

func upsertProposal(ctx context.Context, tx *sql.Tx, organizationID string, signal model.Signal, observed fieldEvidence, now time.Time) error {
	field := observed.descriptor.Field
	var descriptorJSON, examplesJSON, status string
	var count, estimated int64
	err := tx.QueryRowContext(ctx, `SELECT descriptor_json,observed_values,estimated_bytes,example_queries_json,status FROM descriptor_proposals WHERE organization_id=? AND signal=? AND field=?`, organizationID, signal, field).Scan(&descriptorJSON, &count, &estimated, &examplesJSON, &status)
	if errors.Is(err, sql.ErrNoRows) {
		descriptorBody, marshalErr := json.Marshal(observed.descriptor)
		if marshalErr != nil {
			return errors.New("encode descriptor proposal")
		}
		examples := []string{fmt.Sprintf(`%s | where %s == "value" | limit 50`, signal, field)}
		exampleBody, marshalErr := json.Marshal(examples)
		if marshalErr != nil {
			return errors.New("encode descriptor examples")
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO descriptor_proposals(organization_id,signal,field,descriptor_json,observed_values,estimated_bytes,example_queries_json,status,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,'pending',?,?)`, organizationID, signal, field, string(descriptorBody), observed.count, observed.bytes, string(exampleBody), now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return errors.New("create descriptor proposal")
		}
		return nil
	}
	if err != nil {
		return errors.New("load descriptor proposal")
	}
	if status != "pending" {
		return nil
	}
	var descriptor schema.Descriptor
	if err = json.Unmarshal([]byte(descriptorJSON), &descriptor); err != nil || descriptor.Validate() != nil {
		return errors.New("stored descriptor proposal is invalid")
	}
	descriptor.Type = mergeType(descriptor.Type, observed.descriptor.Type)
	if count > math.MaxInt64-observed.count || estimated > math.MaxInt64-observed.bytes {
		return errors.New("descriptor proposal evidence overflow")
	}
	descriptorBody, err := json.Marshal(descriptor)
	if err != nil {
		return errors.New("encode descriptor proposal")
	}
	_, err = tx.ExecContext(ctx, `UPDATE descriptor_proposals SET descriptor_json=?,observed_values=?,estimated_bytes=?,last_seen_at=? WHERE organization_id=? AND signal=? AND field=? AND status='pending'`, string(descriptorBody), count+observed.count, estimated+observed.bytes, now.UTC().Format(time.RFC3339Nano), organizationID, signal, field)
	if err != nil {
		return errors.New("update descriptor proposal")
	}
	return nil
}

func (s *Store) DescriptorProposals(ctx context.Context, organizationID string) ([]StoredProposal, error) {
	if err := model.ValidateSourceID(organizationID); err != nil {
		return nil, errors.New("invalid organization identifier")
	}
	rows, err := s.control.QueryContext(ctx, `SELECT descriptor_json,observed_values,estimated_bytes,example_queries_json,status,first_seen_at,last_seen_at FROM descriptor_proposals WHERE organization_id=? ORDER BY signal,field`, organizationID)
	if err != nil {
		return nil, errors.New("list descriptor proposals")
	}
	defer rows.Close()
	var proposals []StoredProposal
	for rows.Next() {
		var descriptorJSON, examplesJSON, firstSeen, lastSeen string
		var proposal StoredProposal
		if err = rows.Scan(&descriptorJSON, &proposal.Proposal.ObservedValues, &proposal.Proposal.EstimatedBytes, &examplesJSON, &proposal.Status, &firstSeen, &lastSeen); err != nil {
			return nil, errors.New("read descriptor proposal")
		}
		if err = json.Unmarshal([]byte(descriptorJSON), &proposal.Proposal.Descriptor); err != nil {
			return nil, errors.New("decode descriptor proposal")
		}
		if err = json.Unmarshal([]byte(examplesJSON), &proposal.Proposal.ExampleQueries); err != nil {
			return nil, errors.New("decode descriptor examples")
		}
		proposal.FirstSeenAt, err = time.Parse(time.RFC3339Nano, firstSeen)
		if err != nil {
			return nil, errors.New("descriptor proposal first-seen time is invalid")
		}
		proposal.LastSeenAt, err = time.Parse(time.RFC3339Nano, lastSeen)
		if err != nil || proposal.Proposal.Validate() != nil || proposal.Status != "pending" && proposal.Status != "activated" && proposal.Status != "rejected" {
			return nil, errors.New("stored descriptor proposal is invalid")
		}
		proposals = append(proposals, proposal)
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New("list descriptor proposals")
	}
	return proposals, nil
}

func proposedDescriptor(signal model.Signal, field string, valueType schema.Type) schema.Descriptor {
	return schema.Descriptor{
		Version: schema.DescriptorVersion, Signal: signal, Field: field,
		Type: valueType, Meaning: "Observed unreviewed field awaiting administrator classification.",
		Sensitivity: schema.SensitivitySensitive, Cardinality: schema.CardinalityHigh,
		Index: schema.IndexNone, Retention: schema.RetentionRaw, ProjectionVersion: 1,
	}
}

func inferType(value string) schema.Type {
	if _, err := strconv.ParseInt(value, 10, 64); err == nil {
		return schema.TypeInteger
	}
	if number, err := strconv.ParseFloat(value, 64); err == nil && !math.IsNaN(number) && !math.IsInf(number, 0) {
		return schema.TypeFloat
	}
	if value == "true" || value == "false" {
		return schema.TypeBoolean
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return schema.TypeTime
	}
	return schema.TypeString
}

func mergeType(left, right schema.Type) schema.Type {
	if left == right {
		return left
	}
	if left == schema.TypeInteger && right == schema.TypeFloat || left == schema.TypeFloat && right == schema.TypeInteger {
		return schema.TypeFloat
	}
	return schema.TypeString
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}
