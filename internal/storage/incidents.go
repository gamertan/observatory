// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

const (
	AlertRuleVersion = 1
	IncidentVersion  = 1
	MaxDueRules      = 64
)

type AlertRule struct {
	Version             int           `json:"version"`
	Revision            int           `json:"revision"`
	OrganizationID      string        `json:"organization_id"`
	ID                  string        `json:"id"`
	Name                string        `json:"name"`
	Description         string        `json:"description"`
	SavedQueryID        string        `json:"saved_query_id"`
	Severity            string        `json:"severity"`
	MinimumMatches      int           `json:"minimum_matches"`
	RequiredConsecutive int           `json:"required_consecutive"`
	EvaluationInterval  time.Duration `json:"evaluation_interval"`
	Enabled             bool          `json:"enabled"`
	LastEvaluatedAt     *time.Time    `json:"last_evaluated_at,omitempty"`
	NextEvaluationAt    time.Time     `json:"next_evaluation_at"`
	LastResult          *int          `json:"last_result,omitempty"`
	LastError           string        `json:"last_error,omitempty"`
	CreatedBy           string        `json:"created_by"`
	UpdatedBy           string        `json:"updated_by"`
	CreatedAt           time.Time     `json:"created_at"`
	UpdatedAt           time.Time     `json:"updated_at"`
}

type AlertRuleInput struct {
	ID                  string
	ExpectedRevision    int
	OrganizationID      string
	Name                string
	Description         string
	SavedQueryID        string
	Severity            string
	MinimumMatches      int
	RequiredConsecutive int
	EvaluationInterval  time.Duration
	Enabled             bool
	ActorUserID         string
}

type Incident struct {
	Version            int        `json:"version"`
	OrganizationID     string     `json:"organization_id"`
	ID                 string     `json:"id"`
	RuleID             string     `json:"rule_id"`
	State              string     `json:"state"`
	Severity           string     `json:"severity"`
	Title              string     `json:"title"`
	ConsecutiveMatches int        `json:"consecutive_matches"`
	StartedAt          time.Time  `json:"started_at"`
	LastObservedAt     time.Time  `json:"last_observed_at"`
	AcknowledgedBy     string     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt     *time.Time `json:"acknowledged_at,omitempty"`
	SilencedBy         string     `json:"silenced_by,omitempty"`
	SilencedUntil      *time.Time `json:"silenced_until,omitempty"`
	ResolvedAt         *time.Time `json:"resolved_at,omitempty"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type IncidentEvent struct {
	Sequence  int       `json:"sequence"`
	Event     string    `json:"event"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
}

type AlertEvaluation struct {
	RuleID          string `json:"rule_id"`
	OrganizationID  string `json:"organization_id"`
	Matched         bool   `json:"matched"`
	Rows            int    `json:"rows"`
	IncidentID      string `json:"incident_id,omitempty"`
	IncidentState   string `json:"incident_state,omitempty"`
	IncidentChanged bool   `json:"incident_changed"`
	Error           string `json:"error,omitempty"`
}

func (s *Store) SaveAlertRule(ctx context.Context, input AlertRuleInput, now time.Time) (AlertRule, error) {
	if err := validateAlertRuleInput(input, now); err != nil {
		return AlertRule{}, err
	}
	if _, err := s.SavedQuery(ctx, input.OrganizationID, input.SavedQueryID); err != nil {
		return AlertRule{}, errors.New("alert rule saved query is unavailable")
	}
	var err error
	if input.ID == "" {
		input.ID, err = storageID("rule")
		if err != nil {
			return AlertRule{}, err
		}
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if input.ExpectedRevision == 0 {
		_, err = s.control.ExecContext(ctx, `INSERT INTO alert_rules(organization_id,id,version,revision,name,description,saved_query_id,severity,minimum_matches,required_consecutive,evaluation_interval_seconds,enabled,next_evaluation_at,created_by,updated_by,created_at,updated_at) VALUES(?,?,1,1,?,?,?,?,?,?,?,?,?,?,?,?,?)`, input.OrganizationID, input.ID, input.Name, input.Description, input.SavedQueryID, input.Severity, input.MinimumMatches, input.RequiredConsecutive, int(input.EvaluationInterval/time.Second), boolInt(input.Enabled), timestamp, input.ActorUserID, input.ActorUserID, timestamp, timestamp)
	} else {
		if model.ValidateSourceID(input.ID) != nil || input.ExpectedRevision < 1 {
			return AlertRule{}, errors.New("alert rule revision input is invalid")
		}
		var result sql.Result
		result, err = s.control.ExecContext(ctx, `UPDATE alert_rules SET revision=revision+1,name=?,description=?,saved_query_id=?,severity=?,minimum_matches=?,required_consecutive=?,evaluation_interval_seconds=?,enabled=?,next_evaluation_at=?,updated_by=?,updated_at=? WHERE organization_id=? AND id=? AND revision=?`, input.Name, input.Description, input.SavedQueryID, input.Severity, input.MinimumMatches, input.RequiredConsecutive, int(input.EvaluationInterval/time.Second), boolInt(input.Enabled), timestamp, input.ActorUserID, timestamp, input.OrganizationID, input.ID, input.ExpectedRevision)
		if err == nil {
			if changed, _ := result.RowsAffected(); changed != 1 {
				return AlertRule{}, errors.New("alert rule revision conflict")
			}
		}
	}
	if err != nil {
		return AlertRule{}, errors.New("save alert rule")
	}
	return s.AlertRule(ctx, input.OrganizationID, input.ID)
}

func (s *Store) AlertRule(ctx context.Context, organizationID, id string) (AlertRule, error) {
	if model.ValidateSourceID(organizationID) != nil || model.ValidateSourceID(id) != nil {
		return AlertRule{}, errors.New("alert rule identity is invalid")
	}
	row := s.control.QueryRowContext(ctx, `SELECT version,revision,name,description,saved_query_id,severity,minimum_matches,required_consecutive,evaluation_interval_seconds,enabled,last_evaluated_at,next_evaluation_at,last_result,last_error,created_by,updated_by,created_at,updated_at FROM alert_rules WHERE organization_id=? AND id=?`, organizationID, id)
	return scanAlertRule(row, organizationID, id)
}

func (s *Store) AlertRules(ctx context.Context, organizationID string) ([]AlertRule, error) {
	if model.ValidateSourceID(organizationID) != nil {
		return nil, errors.New("invalid organization identifier")
	}
	rows, err := s.control.QueryContext(ctx, `SELECT id FROM alert_rules WHERE organization_id=? ORDER BY name,id`, organizationID)
	if err != nil {
		return nil, errors.New("list alert rules")
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, errors.New("list alert rules")
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New("list alert rules")
	}
	result := make([]AlertRule, 0, len(ids))
	for _, id := range ids {
		value, loadErr := s.AlertRule(ctx, organizationID, id)
		if loadErr != nil {
			return nil, loadErr
		}
		result = append(result, value)
	}
	return result, nil
}

func (s *Store) EvaluateDueAlertRules(ctx context.Context, budget query.Budget, now time.Time) ([]AlertEvaluation, error) {
	if now.IsZero() {
		return nil, errors.New("alert evaluation time is required")
	}
	rows, err := s.control.QueryContext(ctx, `SELECT organization_id,id FROM alert_rules WHERE enabled=1 AND next_evaluation_at<=? ORDER BY next_evaluation_at,organization_id,id LIMIT ?`, now.UTC().Format(time.RFC3339Nano), MaxDueRules)
	if err != nil {
		return nil, errors.New("list due alert rules")
	}
	type identity struct{ organizationID, ruleID string }
	var identities []identity
	for rows.Next() {
		var item identity
		if err = rows.Scan(&item.organizationID, &item.ruleID); err != nil {
			_ = rows.Close()
			return nil, errors.New("list due alert rules")
		}
		identities = append(identities, item)
	}
	if err = rows.Close(); err != nil || rows.Err() != nil {
		return nil, errors.New("list due alert rules")
	}
	result := make([]AlertEvaluation, 0, len(identities))
	for _, item := range identities {
		evaluation, evaluated, evaluationErr := s.evaluateAlertRule(ctx, item.organizationID, item.ruleID, budget, now.UTC())
		if evaluationErr != nil {
			return result, evaluationErr
		}
		if evaluated {
			result = append(result, evaluation)
		}
	}
	return result, nil
}

func (s *Store) evaluateAlertRule(ctx context.Context, organizationID, ruleID string, budget query.Budget, now time.Time) (AlertEvaluation, bool, error) {
	rule, err := s.AlertRule(ctx, organizationID, ruleID)
	if err != nil {
		return AlertEvaluation{}, false, err
	}
	claim, err := s.control.ExecContext(ctx, `UPDATE alert_rules SET next_evaluation_at=? WHERE organization_id=? AND id=? AND enabled=1 AND next_evaluation_at<=?`, now.Add(rule.EvaluationInterval).Format(time.RFC3339Nano), organizationID, ruleID, now.Format(time.RFC3339Nano))
	if err != nil {
		return AlertEvaluation{}, false, errors.New("claim alert rule evaluation")
	}
	if changed, _ := claim.RowsAffected(); changed != 1 {
		return AlertEvaluation{}, false, nil
	}
	saved, err := s.SavedQuery(ctx, organizationID, rule.SavedQueryID)
	if err != nil {
		return AlertEvaluation{RuleID: rule.ID, OrganizationID: organizationID, Error: "query_unavailable"}, true, s.recordRuleError(ctx, rule, now)
	}
	result, err := s.Query(ctx, saved.AST, query.Scope{OrganizationID: organizationID, ProjectID: saved.Scope.ProjectID, EnvironmentID: saved.Scope.EnvironmentID, ServiceID: saved.Scope.ServiceID}, budget, now)
	if err != nil {
		return AlertEvaluation{RuleID: rule.ID, OrganizationID: organizationID, Error: "query_unavailable"}, true, s.recordRuleError(ctx, rule, now)
	}
	matched := len(result.Rows) >= rule.MinimumMatches
	incident, changed, err := s.recordAlertResult(ctx, rule, len(result.Rows), matched, now)
	if err != nil {
		return AlertEvaluation{}, true, err
	}
	evaluation := AlertEvaluation{RuleID: rule.ID, OrganizationID: organizationID, Matched: matched, Rows: len(result.Rows)}
	if incident.ID != "" {
		evaluation.IncidentID, evaluation.IncidentState = incident.ID, incident.State
	}
	evaluation.IncidentChanged = changed
	return evaluation, true, nil
}

func (s *Store) recordRuleError(ctx context.Context, rule AlertRule, now time.Time) error {
	_, err := s.control.ExecContext(ctx, `UPDATE alert_rules SET last_evaluated_at=?,last_result=NULL,last_error='query_unavailable' WHERE organization_id=? AND id=?`, now.Format(time.RFC3339Nano), rule.OrganizationID, rule.ID)
	if err != nil {
		return errors.New("record alert rule failure")
	}
	return nil
}

func (s *Store) recordAlertResult(ctx context.Context, rule AlertRule, rows int, matched bool, now time.Time) (Incident, bool, error) {
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return Incident{}, false, errors.New("begin alert evaluation")
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE alert_rules SET last_evaluated_at=?,last_result=?,last_error='' WHERE organization_id=? AND id=?`, now.Format(time.RFC3339Nano), rows, rule.OrganizationID, rule.ID); err != nil {
		return Incident{}, false, errors.New("record alert evaluation")
	}
	incident, found, err := openIncidentTx(ctx, tx, rule.OrganizationID, rule.ID)
	if err != nil {
		return Incident{}, false, err
	}
	changed := false
	if !matched {
		if !found {
			if err = tx.Commit(); err != nil {
				return Incident{}, false, errors.New("commit alert evaluation")
			}
			return Incident{}, false, nil
		}
		if err = resolveIncidentTx(ctx, tx, &incident, "system", now); err != nil {
			return Incident{}, false, err
		}
		changed = true
	} else if !found {
		incidentID, idErr := storageID("incident")
		if idErr != nil {
			return Incident{}, false, idErr
		}
		state := "pending"
		if rule.RequiredConsecutive == 1 {
			state = "firing"
		}
		stamp := now.Format(time.RFC3339Nano)
		_, err = tx.ExecContext(ctx, `INSERT INTO incidents(organization_id,id,version,rule_id,state,severity,title,consecutive_matches,started_at,last_observed_at,updated_at) VALUES(?,?,1,?,?,?,?,1,?,?,?)`, rule.OrganizationID, incidentID, rule.ID, state, rule.Severity, rule.Name, stamp, stamp, stamp)
		if err != nil {
			return Incident{}, false, errors.New("open incident")
		}
		incident = Incident{Version: IncidentVersion, OrganizationID: rule.OrganizationID, ID: incidentID, RuleID: rule.ID, State: state, Severity: rule.Severity, Title: rule.Name, ConsecutiveMatches: 1, StartedAt: now, LastObservedAt: now, UpdatedAt: now}
		if err = appendIncidentEventTx(ctx, tx, incident, "opened", "system", now); err != nil {
			return Incident{}, false, err
		}
		changed = true
	} else {
		incident.ConsecutiveMatches++
		incident.LastObservedAt, incident.UpdatedAt = now, now
		event := ""
		if incident.State == "pending" && incident.ConsecutiveMatches >= rule.RequiredConsecutive {
			incident.State, event = "firing", "promoted"
		} else if incident.State == "silenced" && incident.SilencedUntil != nil && !now.Before(*incident.SilencedUntil) {
			incident.State, incident.SilencedBy, incident.SilencedUntil, event = "firing", "", nil, "unsilenced"
		}
		_, err = tx.ExecContext(ctx, `UPDATE incidents SET state=?,consecutive_matches=?,last_observed_at=?,silenced_by=?,silenced_until=?,updated_at=? WHERE organization_id=? AND id=?`, incident.State, incident.ConsecutiveMatches, now.Format(time.RFC3339Nano), nullableText(incident.SilencedBy), nullableTime(incident.SilencedUntil), now.Format(time.RFC3339Nano), incident.OrganizationID, incident.ID)
		if err != nil {
			return Incident{}, false, errors.New("update incident observation")
		}
		if event != "" {
			if err = appendIncidentEventTx(ctx, tx, incident, event, "system", now); err != nil {
				return Incident{}, false, err
			}
			changed = true
		}
	}
	if err = tx.Commit(); err != nil {
		return Incident{}, false, errors.New("commit alert evaluation")
	}
	return incident, changed, nil
}

func (s *Store) Incidents(ctx context.Context, organizationID string, includeResolved bool, limit int) ([]Incident, error) {
	if model.ValidateSourceID(organizationID) != nil || limit < 1 || limit > 1000 {
		return nil, errors.New("incident list input is invalid")
	}
	statement := `SELECT id,version,rule_id,state,severity,title,consecutive_matches,started_at,last_observed_at,acknowledged_by,acknowledged_at,silenced_by,silenced_until,resolved_at,updated_at FROM incidents WHERE organization_id=?`
	if !includeResolved {
		statement += ` AND state!='resolved'`
	}
	statement += ` ORDER BY CASE state WHEN 'firing' THEN 0 WHEN 'pending' THEN 1 WHEN 'acknowledged' THEN 2 WHEN 'silenced' THEN 3 ELSE 4 END,updated_at DESC,id LIMIT ?`
	rows, err := s.control.QueryContext(ctx, statement, organizationID, limit)
	if err != nil {
		return nil, errors.New("list incidents")
	}
	defer rows.Close()
	var result []Incident
	for rows.Next() {
		value, scanErr := scanIncident(rows, organizationID)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, value)
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New("list incidents")
	}
	return result, nil
}

func (s *Store) TransitionIncident(ctx context.Context, organizationID, incidentID, action, actor string, silenceUntil *time.Time, now time.Time) (Incident, error) {
	if model.ValidateSourceID(organizationID) != nil || model.ValidateSourceID(incidentID) != nil || model.ValidateSourceID(actor) != nil || now.IsZero() {
		return Incident{}, errors.New("incident transition input is invalid")
	}
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return Incident{}, errors.New("begin incident transition")
	}
	defer tx.Rollback()
	incident, err := incidentByIDTx(ctx, tx, organizationID, incidentID)
	if err != nil {
		return Incident{}, err
	}
	if incident.State == "resolved" {
		return Incident{}, errors.New("resolved incident cannot transition")
	}
	switch action {
	case "acknowledge":
		incident.State, incident.AcknowledgedBy = "acknowledged", actor
		incident.SilencedBy, incident.SilencedUntil = "", nil
		stamp := now.UTC()
		incident.AcknowledgedAt = &stamp
		if err = appendIncidentEventTx(ctx, tx, incident, "acknowledged", actor, stamp); err != nil {
			return Incident{}, err
		}
	case "silence":
		if silenceUntil == nil || !silenceUntil.After(now) || silenceUntil.After(now.Add(30*24*time.Hour)) {
			return Incident{}, errors.New("incident silence expiry is invalid")
		}
		stamp := silenceUntil.UTC()
		incident.State, incident.SilencedBy, incident.SilencedUntil = "silenced", actor, &stamp
		if err = appendIncidentEventTx(ctx, tx, incident, "silenced", actor, now.UTC()); err != nil {
			return Incident{}, err
		}
	case "resolve":
		if err = resolveIncidentTx(ctx, tx, &incident, actor, now.UTC()); err != nil {
			return Incident{}, err
		}
	default:
		return Incident{}, errors.New("incident action is invalid")
	}
	incident.UpdatedAt = now.UTC()
	if action != "resolve" {
		_, err = tx.ExecContext(ctx, `UPDATE incidents SET state=?,acknowledged_by=?,acknowledged_at=?,silenced_by=?,silenced_until=?,updated_at=? WHERE organization_id=? AND id=?`, incident.State, nullableText(incident.AcknowledgedBy), nullableTime(incident.AcknowledgedAt), nullableText(incident.SilencedBy), nullableTime(incident.SilencedUntil), incident.UpdatedAt.Format(time.RFC3339Nano), organizationID, incidentID)
		if err != nil {
			return Incident{}, errors.New("update incident")
		}
	}
	if err = tx.Commit(); err != nil {
		return Incident{}, errors.New("commit incident transition")
	}
	return incident, nil
}

func (s *Store) IncidentEvents(ctx context.Context, organizationID, incidentID string) ([]IncidentEvent, error) {
	if model.ValidateSourceID(organizationID) != nil || model.ValidateSourceID(incidentID) != nil {
		return nil, errors.New("incident event identity is invalid")
	}
	rows, err := s.control.QueryContext(ctx, `SELECT sequence,event,actor,created_at FROM incident_events WHERE organization_id=? AND incident_id=? ORDER BY sequence`, organizationID, incidentID)
	if err != nil {
		return nil, errors.New("list incident events")
	}
	defer rows.Close()
	var result []IncidentEvent
	for rows.Next() {
		var value IncidentEvent
		var created string
		if err = rows.Scan(&value.Sequence, &value.Event, &value.Actor, &created); err != nil {
			return nil, errors.New("read incident event")
		}
		value.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, errors.New("stored incident event is invalid")
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

type alertRuleScanner interface{ Scan(...any) error }

func scanAlertRule(row alertRuleScanner, organizationID, id string) (AlertRule, error) {
	value := AlertRule{OrganizationID: organizationID, ID: id}
	var enabled int
	var interval int64
	var lastEvaluated, nextEvaluation, created, updated sql.NullString
	var lastResult sql.NullInt64
	if err := row.Scan(&value.Version, &value.Revision, &value.Name, &value.Description, &value.SavedQueryID, &value.Severity, &value.MinimumMatches, &value.RequiredConsecutive, &interval, &enabled, &lastEvaluated, &nextEvaluation, &lastResult, &value.LastError, &value.CreatedBy, &value.UpdatedBy, &created, &updated); errors.Is(err, sql.ErrNoRows) {
		return AlertRule{}, errors.New("alert rule not found")
	} else if err != nil {
		return AlertRule{}, errors.New("read alert rule")
	}
	value.Enabled = enabled == 1
	value.EvaluationInterval = time.Duration(interval) * time.Second
	if lastResult.Valid {
		result := int(lastResult.Int64)
		value.LastResult = &result
	}
	var err error
	if lastEvaluated.Valid {
		parsed, parseErr := time.Parse(time.RFC3339Nano, lastEvaluated.String)
		if parseErr != nil {
			return AlertRule{}, errors.New("stored alert rule evaluation time is invalid")
		}
		value.LastEvaluatedAt = &parsed
	}
	value.NextEvaluationAt, err = time.Parse(time.RFC3339Nano, nextEvaluation.String)
	if err == nil {
		value.CreatedAt, err = time.Parse(time.RFC3339Nano, created.String)
	}
	if err == nil {
		value.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated.String)
	}
	if err != nil || validateAlertRule(value) != nil {
		return AlertRule{}, errors.New("stored alert rule is invalid")
	}
	return value, nil
}

type incidentScanner interface{ Scan(...any) error }

func scanIncident(row incidentScanner, organizationID string) (Incident, error) {
	value := Incident{OrganizationID: organizationID}
	var started, observed, updated string
	var acknowledgedBy, acknowledgedAt, silencedBy, silencedUntil, resolvedAt sql.NullString
	if err := row.Scan(&value.ID, &value.Version, &value.RuleID, &value.State, &value.Severity, &value.Title, &value.ConsecutiveMatches, &started, &observed, &acknowledgedBy, &acknowledgedAt, &silencedBy, &silencedUntil, &resolvedAt, &updated); errors.Is(err, sql.ErrNoRows) {
		return Incident{}, sql.ErrNoRows
	} else if err != nil {
		return Incident{}, errors.New("read incident")
	}
	value.AcknowledgedBy, value.SilencedBy = acknowledgedBy.String, silencedBy.String
	var err error
	value.StartedAt, err = time.Parse(time.RFC3339Nano, started)
	if err == nil {
		value.LastObservedAt, err = time.Parse(time.RFC3339Nano, observed)
	}
	if err == nil {
		value.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	}
	if err == nil {
		value.AcknowledgedAt, err = parseOptionalTime(acknowledgedAt)
	}
	if err == nil {
		value.SilencedUntil, err = parseOptionalTime(silencedUntil)
	}
	if err == nil {
		value.ResolvedAt, err = parseOptionalTime(resolvedAt)
	}
	if err != nil || validateIncident(value) != nil {
		return Incident{}, errors.New("stored incident is invalid")
	}
	return value, nil
}

func openIncidentTx(ctx context.Context, tx *sql.Tx, organizationID, ruleID string) (Incident, bool, error) {
	row := tx.QueryRowContext(ctx, `SELECT id,version,rule_id,state,severity,title,consecutive_matches,started_at,last_observed_at,acknowledged_by,acknowledged_at,silenced_by,silenced_until,resolved_at,updated_at FROM incidents WHERE organization_id=? AND rule_id=? AND state!='resolved'`, organizationID, ruleID)
	value, err := scanIncident(row, organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return Incident{}, false, nil
	}
	if err != nil {
		return Incident{}, false, err
	}
	return value, true, nil
}

func incidentByIDTx(ctx context.Context, tx *sql.Tx, organizationID, incidentID string) (Incident, error) {
	row := tx.QueryRowContext(ctx, `SELECT id,version,rule_id,state,severity,title,consecutive_matches,started_at,last_observed_at,acknowledged_by,acknowledged_at,silenced_by,silenced_until,resolved_at,updated_at FROM incidents WHERE organization_id=? AND id=?`, organizationID, incidentID)
	value, err := scanIncident(row, organizationID)
	if err != nil {
		return Incident{}, errors.New("incident not found")
	}
	return value, nil
}

func resolveIncidentTx(ctx context.Context, tx *sql.Tx, incident *Incident, actor string, now time.Time) error {
	incident.State, incident.ResolvedAt, incident.UpdatedAt = "resolved", &now, now
	_, err := tx.ExecContext(ctx, `UPDATE incidents SET state='resolved',resolved_at=?,updated_at=? WHERE organization_id=? AND id=?`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), incident.OrganizationID, incident.ID)
	if err != nil {
		return errors.New("resolve incident")
	}
	return appendIncidentEventTx(ctx, tx, *incident, "resolved", actor, now)
}

func appendIncidentEventTx(ctx context.Context, tx *sql.Tx, incident Incident, event, actor string, now time.Time) error {
	var sequence int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM incident_events WHERE organization_id=? AND incident_id=?`, incident.OrganizationID, incident.ID).Scan(&sequence); err != nil {
		return errors.New("sequence incident event")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO incident_events(organization_id,incident_id,sequence,event,actor,created_at) VALUES(?,?,?,?,?,?)`, incident.OrganizationID, incident.ID, sequence, event, actor, now.UTC().Format(time.RFC3339Nano)); err != nil {
		return errors.New("append incident event")
	}
	return nil
}

func validateAlertRuleInput(input AlertRuleInput, now time.Time) error {
	if model.ValidateSourceID(input.OrganizationID) != nil || model.ValidateSourceID(input.ActorUserID) != nil || model.ValidateSourceID(input.SavedQueryID) != nil || !boundedText(input.Name, 128, false) || !boundedText(input.Description, 1024, true) || input.MinimumMatches < 1 || input.MinimumMatches > 100_000 || input.RequiredConsecutive < 1 || input.RequiredConsecutive > 10 || input.EvaluationInterval < 15*time.Second || input.EvaluationInterval > 24*time.Hour || input.EvaluationInterval%time.Second != 0 || now.IsZero() {
		return errors.New("alert rule input is invalid")
	}
	if !validSeverity(input.Severity) || input.ExpectedRevision == 0 && input.ID != "" {
		return errors.New("alert rule input is invalid")
	}
	return nil
}

func validateAlertRule(value AlertRule) error {
	if value.Version != AlertRuleVersion || value.Revision < 1 || model.ValidateSourceID(value.OrganizationID) != nil || model.ValidateSourceID(value.ID) != nil || model.ValidateSourceID(value.SavedQueryID) != nil || model.ValidateSourceID(value.CreatedBy) != nil || model.ValidateSourceID(value.UpdatedBy) != nil || !boundedText(value.Name, 128, false) || !boundedText(value.Description, 1024, true) || !validSeverity(value.Severity) || value.MinimumMatches < 1 || value.MinimumMatches > 100_000 || value.RequiredConsecutive < 1 || value.RequiredConsecutive > 10 || value.EvaluationInterval < 15*time.Second || value.EvaluationInterval > 24*time.Hour || value.NextEvaluationAt.IsZero() || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) || value.LastError != "" && value.LastError != "query_unavailable" {
		return errors.New("alert rule is invalid")
	}
	return nil
}

func validateIncident(value Incident) error {
	states := map[string]bool{"pending": true, "firing": true, "acknowledged": true, "silenced": true, "resolved": true}
	if value.Version != IncidentVersion || model.ValidateSourceID(value.OrganizationID) != nil || model.ValidateSourceID(value.ID) != nil || model.ValidateSourceID(value.RuleID) != nil || !states[value.State] || !validSeverity(value.Severity) || !boundedText(value.Title, 128, false) || value.ConsecutiveMatches < 0 || value.StartedAt.IsZero() || value.LastObservedAt.Before(value.StartedAt) || value.UpdatedAt.Before(value.StartedAt) {
		return errors.New("incident is invalid")
	}
	if value.State == "acknowledged" && (value.AcknowledgedBy == "" || value.AcknowledgedAt == nil) || value.State == "silenced" && (value.SilencedBy == "" || value.SilencedUntil == nil) || value.State == "resolved" && value.ResolvedAt == nil {
		return errors.New("incident state metadata is invalid")
	}
	if value.AcknowledgedBy != "" && (model.ValidateSourceID(value.AcknowledgedBy) != nil || value.AcknowledgedAt == nil) || value.AcknowledgedAt != nil && (value.AcknowledgedBy == "" || value.AcknowledgedAt.Before(value.StartedAt)) || value.SilencedBy != "" && (model.ValidateSourceID(value.SilencedBy) != nil || value.SilencedUntil == nil) || value.SilencedUntil != nil && (value.SilencedBy == "" || value.SilencedUntil.Before(value.StartedAt)) || value.ResolvedAt != nil && value.ResolvedAt.Before(value.StartedAt) {
		return errors.New("incident actor metadata is invalid")
	}
	return nil
}

func parseOptionalTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func validSeverity(value string) bool {
	return value == "information" || value == "warning" || value == "critical"
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}
