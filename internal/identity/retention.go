// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"time"
)

type EvidencePruneReport struct {
	AuthenticationEvents int64 `json:"authentication_events"`
	OrganizationEvents   int64 `json:"organization_events"`
	ExpiredSessions      int64 `json:"expired_sessions"`
	ExpiredInvitations   int64 `json:"expired_invitations"`
	ExpiredBreakGlass    int64 `json:"expired_break_glass"`
}

// PruneEvidence applies the server default to platform authentication audit
// events and each organization's approved retention override to its visible
// access audit. Operational credentials are removed only after expiration.
func (services *Services) PruneEvidence(ctx context.Context, defaultDays int, now time.Time) (EvidencePruneReport, error) {
	if services == nil || services.control == nil || defaultDays < 1 || defaultDays > 3650 || now.IsZero() {
		return EvidencePruneReport{}, errors.New("identity: evidence retention input is invalid")
	}
	tx, err := services.control.BeginTx(ctx, nil)
	if err != nil {
		return EvidencePruneReport{}, errors.New("identity: begin evidence retention")
	}
	defer tx.Rollback()
	report := EvidencePruneReport{}
	cutoff := now.UTC().Add(-time.Duration(defaultDays) * 24 * time.Hour).Unix()
	result, err := tx.ExecContext(ctx, `DELETE FROM gwf_audit_events WHERE created_at<?`, cutoff)
	if err != nil {
		return report, errors.New("identity: prune authentication audit")
	}
	report.AuthenticationEvents, _ = result.RowsAffected()
	var policyTable int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='organization_retention_policies'`).Scan(&policyTable); err != nil {
		return report, errors.New("identity: inspect organization retention policy")
	}
	organizationQuery := `SELECT DISTINCT organization_id,? FROM gwf_access_audit_events ORDER BY organization_id`
	if policyTable == 1 {
		organizationQuery = `SELECT DISTINCT audit.organization_id,COALESCE(policy.evidence_days,?) FROM gwf_access_audit_events audit LEFT JOIN organization_retention_policies policy ON policy.organization_id=audit.organization_id ORDER BY audit.organization_id`
	}
	rows, err := tx.QueryContext(ctx, organizationQuery, defaultDays)
	if err != nil {
		return report, errors.New("identity: list organization audit retention")
	}
	type organizationCutoff struct {
		id   string
		days int
	}
	var organizations []organizationCutoff
	for rows.Next() {
		var organization organizationCutoff
		if err = rows.Scan(&organization.id, &organization.days); err != nil || organization.days < 1 || organization.days > 3650 {
			_ = rows.Close()
			return report, errors.New("identity: organization audit retention is invalid")
		}
		organizations = append(organizations, organization)
	}
	if err = rows.Close(); err != nil {
		return report, errors.New("identity: close organization audit retention")
	}
	for _, organization := range organizations {
		organizationCutoff := now.UTC().Add(-time.Duration(organization.days) * 24 * time.Hour).Unix()
		result, err = tx.ExecContext(ctx, `DELETE FROM gwf_access_audit_events WHERE organization_id=? AND created_at<?`, organization.id, organizationCutoff)
		if err != nil {
			return report, errors.New("identity: prune organization access audit")
		}
		removed, _ := result.RowsAffected()
		report.OrganizationEvents += removed
	}
	for _, cleanup := range []struct {
		statement   string
		destination *int64
	}{
		{`DELETE FROM gwf_auth_sessions WHERE expires_at<=?`, &report.ExpiredSessions},
		{`DELETE FROM gwf_organization_invitations WHERE expires_at<=?`, &report.ExpiredInvitations},
		{`DELETE FROM gwf_break_glass WHERE expires_at<=?`, &report.ExpiredBreakGlass},
	} {
		result, err = tx.ExecContext(ctx, cleanup.statement, now.UTC().Unix())
		if err != nil {
			return report, errors.New("identity: prune expired security state")
		}
		*cleanup.destination, _ = result.RowsAffected()
	}
	if err = tx.Commit(); err != nil {
		return report, errors.New("identity: commit evidence retention")
	}
	return report, nil
}
