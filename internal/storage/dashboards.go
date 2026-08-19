// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

const (
	SavedQueryVersion  = 1
	DashboardVersion   = 1
	MaxDashboardPanels = 16
)

var ErrDashboardRevisionConflict = errors.New("dashboard revision conflict")

type ResourceScope struct {
	ProjectID     string `json:"project_id,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
	ServiceID     string `json:"service_id,omitempty"`
}

type SavedQuery struct {
	Version        int           `json:"version"`
	Revision       int           `json:"revision"`
	OrganizationID string        `json:"organization_id"`
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	Query          string        `json:"query"`
	AST            query.AST     `json:"ast"`
	Scope          ResourceScope `json:"scope"`
	CreatedBy      string        `json:"created_by"`
	UpdatedBy      string        `json:"updated_by"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

type SavedQueryInput struct {
	ID               string
	ExpectedRevision int
	OrganizationID   string
	Name             string
	Description      string
	Query            string
	Scope            ResourceScope
	ActorUserID      string
	MaxRows          int
}

type DashboardPanel struct {
	ID            string `json:"id"`
	Position      int    `json:"position"`
	Title         string `json:"title"`
	Visualization string `json:"visualization"`
	SavedQueryID  string `json:"saved_query_id"`
}

type Dashboard struct {
	Version        int              `json:"version"`
	Revision       int              `json:"revision"`
	OrganizationID string           `json:"organization_id"`
	ID             string           `json:"id"`
	Slug           string           `json:"slug"`
	Name           string           `json:"name"`
	Description    string           `json:"description"`
	Panels         []DashboardPanel `json:"panels"`
	CreatedBy      string           `json:"created_by"`
	UpdatedBy      string           `json:"updated_by"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

type DashboardInput struct {
	ID               string
	ExpectedRevision int
	OrganizationID   string
	Slug             string
	Name             string
	Description      string
	Panels           []DashboardPanel
	ActorUserID      string
}

type DashboardExport struct {
	Version      int                    `json:"version"`
	Dashboard    DashboardDefinition    `json:"dashboard"`
	SavedQueries []SavedQueryDefinition `json:"saved_queries"`
}

type DashboardDefinition struct {
	Slug        string           `json:"slug"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Panels      []DashboardPanel `json:"panels"`
}

type SavedQueryDefinition struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Query       string        `json:"query"`
	Scope       ResourceScope `json:"scope"`
}

type DashboardImportInput struct {
	OrganizationID string
	ActorUserID    string
	MaxRows        int
	Bundle         DashboardExport
}

func (s *Store) SaveQuery(ctx context.Context, input SavedQueryInput, now time.Time) (SavedQuery, error) {
	ast, err := validateSavedQueryInput(input, now)
	if err != nil {
		return SavedQuery{}, err
	}
	astJSON, err := json.Marshal(ast)
	if err != nil {
		return SavedQuery{}, errors.New("encode saved query AST")
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if input.ID == "" {
		input.ID, err = storageID("query")
		if err != nil {
			return SavedQuery{}, err
		}
		_, err = s.control.ExecContext(ctx, `INSERT INTO saved_queries(organization_id,id,version,revision,name,description,query_text,ast_json,project_id,environment_id,service_id,created_by,updated_by,created_at,updated_at) VALUES(?,?,1,1,?,?,?,?,?,?,?,?,?,?,?)`, input.OrganizationID, input.ID, input.Name, input.Description, input.Query, string(astJSON), input.Scope.ProjectID, input.Scope.EnvironmentID, input.Scope.ServiceID, input.ActorUserID, input.ActorUserID, timestamp, timestamp)
		if err != nil {
			return SavedQuery{}, errors.New("create saved query")
		}
	} else {
		if input.ExpectedRevision < 1 || model.ValidateSourceID(input.ID) != nil {
			return SavedQuery{}, errors.New("saved query revision input is invalid")
		}
		result, updateErr := s.control.ExecContext(ctx, `UPDATE saved_queries SET revision=revision+1,name=?,description=?,query_text=?,ast_json=?,project_id=?,environment_id=?,service_id=?,updated_by=?,updated_at=? WHERE organization_id=? AND id=? AND revision=?`, input.Name, input.Description, input.Query, string(astJSON), input.Scope.ProjectID, input.Scope.EnvironmentID, input.Scope.ServiceID, input.ActorUserID, timestamp, input.OrganizationID, input.ID, input.ExpectedRevision)
		if updateErr != nil {
			return SavedQuery{}, errors.New("update saved query")
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return SavedQuery{}, errors.New("saved query revision conflict")
		}
	}
	return s.SavedQuery(ctx, input.OrganizationID, input.ID)
}

func (s *Store) SavedQuery(ctx context.Context, organizationID, id string) (SavedQuery, error) {
	if model.ValidateSourceID(organizationID) != nil || model.ValidateSourceID(id) != nil {
		return SavedQuery{}, errors.New("saved query identity is invalid")
	}
	row := s.control.QueryRowContext(ctx, `SELECT version,revision,name,description,query_text,ast_json,project_id,environment_id,service_id,created_by,updated_by,created_at,updated_at FROM saved_queries WHERE organization_id=? AND id=?`, organizationID, id)
	return scanSavedQuery(row, organizationID, id)
}

func (s *Store) SavedQueries(ctx context.Context, organizationID string) ([]SavedQuery, error) {
	if model.ValidateSourceID(organizationID) != nil {
		return nil, errors.New("invalid organization identifier")
	}
	rows, err := s.control.QueryContext(ctx, `SELECT id,version,revision,name,description,query_text,ast_json,project_id,environment_id,service_id,created_by,updated_by,created_at,updated_at FROM saved_queries WHERE organization_id=? ORDER BY name,id`, organizationID)
	if err != nil {
		return nil, errors.New("list saved queries")
	}
	defer rows.Close()
	var result []SavedQuery
	for rows.Next() {
		var id string
		var value SavedQuery
		var astJSON, createdAt, updatedAt string
		value.OrganizationID = organizationID
		if err = rows.Scan(&id, &value.Version, &value.Revision, &value.Name, &value.Description, &value.Query, &astJSON, &value.Scope.ProjectID, &value.Scope.EnvironmentID, &value.Scope.ServiceID, &value.CreatedBy, &value.UpdatedBy, &createdAt, &updatedAt); err != nil {
			return nil, errors.New("read saved query")
		}
		value.ID = id
		if err = decodeSavedQuery(&value, astJSON, createdAt, updatedAt); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New("list saved queries")
	}
	return result, nil
}

type rowScanner interface{ Scan(...any) error }

func scanSavedQuery(row rowScanner, organizationID, id string) (SavedQuery, error) {
	value := SavedQuery{OrganizationID: organizationID, ID: id}
	var astJSON, createdAt, updatedAt string
	if err := row.Scan(&value.Version, &value.Revision, &value.Name, &value.Description, &value.Query, &astJSON, &value.Scope.ProjectID, &value.Scope.EnvironmentID, &value.Scope.ServiceID, &value.CreatedBy, &value.UpdatedBy, &createdAt, &updatedAt); errors.Is(err, sql.ErrNoRows) {
		return SavedQuery{}, errors.New("saved query not found")
	} else if err != nil {
		return SavedQuery{}, errors.New("read saved query")
	}
	if err := decodeSavedQuery(&value, astJSON, createdAt, updatedAt); err != nil {
		return SavedQuery{}, err
	}
	return value, nil
}

func decodeSavedQuery(value *SavedQuery, astJSON, createdAt, updatedAt string) error {
	if value.Version != SavedQueryVersion || value.Revision < 1 || model.ValidateSourceID(value.OrganizationID) != nil || model.ValidateSourceID(value.ID) != nil || model.ValidateSourceID(value.CreatedBy) != nil || model.ValidateSourceID(value.UpdatedBy) != nil || !validResourceScope(value.Scope) || !boundedText(value.Name, 128, false) || !boundedText(value.Description, 1024, true) {
		return errors.New("stored saved query is invalid")
	}
	parsed, err := query.Parse(value.Query, 100_000)
	if err != nil || json.Unmarshal([]byte(astJSON), &value.AST) != nil || hydrateSavedAST(&value.AST) != nil || query.Validate(value.AST, 100_000) != nil {
		return errors.New("stored saved query AST is invalid")
	}
	parsedJSON, _ := json.Marshal(parsed)
	storedJSON, _ := json.Marshal(value.AST)
	if string(parsedJSON) != string(storedJSON) {
		return errors.New("stored saved query AST does not match query text")
	}
	value.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return errors.New("stored saved query created time is invalid")
	}
	value.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil || value.UpdatedAt.Before(value.CreatedAt) {
		return errors.New("stored saved query updated time is invalid")
	}
	return nil
}

func hydrateSavedAST(ast *query.AST) error {
	var err error
	if ast.WindowText != "" {
		ast.Window, err = time.ParseDuration(ast.WindowText)
	}
	if err == nil && ast.BucketText != "" {
		ast.Bucket, err = time.ParseDuration(ast.BucketText)
	}
	if err != nil {
		return errors.New("stored saved query duration is invalid")
	}
	return nil
}

func (s *Store) SaveDashboard(ctx context.Context, input DashboardInput, now time.Time) (Dashboard, error) {
	if err := validateDashboardInput(input, now); err != nil {
		return Dashboard{}, err
	}
	if input.ExpectedRevision == 0 && input.ID != "" {
		return Dashboard{}, errors.New("new dashboard identity is server-generated")
	}
	if input.ExpectedRevision > 0 && model.ValidateSourceID(input.ID) != nil {
		return Dashboard{}, errors.New("dashboard revision input is invalid")
	}
	var err error
	if input.ID == "" {
		input.ID, err = storageID("dashboard")
		if err != nil {
			return Dashboard{}, err
		}
	}
	panels := append([]DashboardPanel(nil), input.Panels...)
	for index := range panels {
		if panels[index].ID == "" {
			panels[index].ID, err = storageID("panel")
			if err != nil {
				return Dashboard{}, err
			}
		}
	}
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return Dashboard{}, errors.New("begin dashboard update")
	}
	defer tx.Rollback()
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if input.ExpectedRevision == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO dashboards(organization_id,id,version,revision,slug,name,description,created_by,updated_by,created_at,updated_at) VALUES(?,?,1,1,?,?,?,?,?,?,?)`, input.OrganizationID, input.ID, input.Slug, input.Name, input.Description, input.ActorUserID, input.ActorUserID, timestamp, timestamp)
		if err != nil {
			return Dashboard{}, errors.New("create dashboard")
		}
	} else {
		if model.ValidateSourceID(input.ID) != nil || input.ExpectedRevision < 1 {
			return Dashboard{}, errors.New("dashboard revision input is invalid")
		}
		result, updateErr := tx.ExecContext(ctx, `UPDATE dashboards SET revision=revision+1,slug=?,name=?,description=?,updated_by=?,updated_at=? WHERE organization_id=? AND id=? AND revision=?`, input.Slug, input.Name, input.Description, input.ActorUserID, timestamp, input.OrganizationID, input.ID, input.ExpectedRevision)
		if updateErr != nil {
			return Dashboard{}, errors.New("update dashboard")
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return Dashboard{}, ErrDashboardRevisionConflict
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM dashboard_panels WHERE organization_id=? AND dashboard_id=?`, input.OrganizationID, input.ID); err != nil {
			return Dashboard{}, errors.New("replace dashboard panels")
		}
	}
	for _, panel := range panels {
		if _, err = tx.ExecContext(ctx, `INSERT INTO dashboard_panels(organization_id,dashboard_id,id,position,title,visualization,saved_query_id) VALUES(?,?,?,?,?,?,?)`, input.OrganizationID, input.ID, panel.ID, panel.Position, panel.Title, panel.Visualization, panel.SavedQueryID); err != nil {
			return Dashboard{}, errors.New("store dashboard panel")
		}
	}
	if err = tx.Commit(); err != nil {
		return Dashboard{}, errors.New("commit dashboard update")
	}
	return s.Dashboard(ctx, input.OrganizationID, input.Slug)
}

func (s *Store) Dashboard(ctx context.Context, organizationID, slug string) (Dashboard, error) {
	if model.ValidateSourceID(organizationID) != nil || !validSlug(slug) {
		return Dashboard{}, errors.New("dashboard identity is invalid")
	}
	value := Dashboard{OrganizationID: organizationID}
	var createdAt, updatedAt string
	err := s.control.QueryRowContext(ctx, `SELECT id,version,revision,name,description,created_by,updated_by,created_at,updated_at FROM dashboards WHERE organization_id=? AND slug=?`, organizationID, slug).Scan(&value.ID, &value.Version, &value.Revision, &value.Name, &value.Description, &value.CreatedBy, &value.UpdatedBy, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Dashboard{}, errors.New("dashboard not found")
	}
	if err != nil {
		return Dashboard{}, errors.New("read dashboard")
	}
	value.Slug = slug
	value.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Dashboard{}, errors.New("stored dashboard created time is invalid")
	}
	value.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil || value.UpdatedAt.Before(value.CreatedAt) {
		return Dashboard{}, errors.New("stored dashboard updated time is invalid")
	}
	rows, err := s.control.QueryContext(ctx, `SELECT id,position,title,visualization,saved_query_id FROM dashboard_panels WHERE organization_id=? AND dashboard_id=? ORDER BY position,id`, organizationID, value.ID)
	if err != nil {
		return Dashboard{}, errors.New("read dashboard panels")
	}
	defer rows.Close()
	for rows.Next() {
		var panel DashboardPanel
		if err = rows.Scan(&panel.ID, &panel.Position, &panel.Title, &panel.Visualization, &panel.SavedQueryID); err != nil || validatePanel(panel) != nil {
			return Dashboard{}, errors.New("stored dashboard panel is invalid")
		}
		value.Panels = append(value.Panels, panel)
	}
	if err = rows.Err(); err != nil || validateDashboard(value) != nil {
		return Dashboard{}, errors.New("stored dashboard is invalid")
	}
	return value, nil
}

func (s *Store) Dashboards(ctx context.Context, organizationID string) ([]Dashboard, error) {
	if model.ValidateSourceID(organizationID) != nil {
		return nil, errors.New("invalid organization identifier")
	}
	rows, err := s.control.QueryContext(ctx, `SELECT slug FROM dashboards WHERE organization_id=? ORDER BY name,slug`, organizationID)
	if err != nil {
		return nil, errors.New("list dashboards")
	}
	var slugs []string
	for rows.Next() {
		var slug string
		if err = rows.Scan(&slug); err != nil {
			_ = rows.Close()
			return nil, errors.New("list dashboards")
		}
		slugs = append(slugs, slug)
	}
	if err = rows.Close(); err != nil || rows.Err() != nil {
		return nil, errors.New("list dashboards")
	}
	result := make([]Dashboard, 0, len(slugs))
	for _, slug := range slugs {
		value, loadErr := s.Dashboard(ctx, organizationID, slug)
		if loadErr != nil {
			return nil, loadErr
		}
		result = append(result, value)
	}
	return result, nil
}

func (s *Store) ExportDashboard(ctx context.Context, organizationID, slug string) (DashboardExport, error) {
	dashboard, err := s.Dashboard(ctx, organizationID, slug)
	if err != nil {
		return DashboardExport{}, err
	}
	queries := make([]SavedQueryDefinition, 0, len(dashboard.Panels))
	seen := map[string]bool{}
	for _, panel := range dashboard.Panels {
		if seen[panel.SavedQueryID] {
			continue
		}
		value, loadErr := s.SavedQuery(ctx, organizationID, panel.SavedQueryID)
		if loadErr != nil {
			return DashboardExport{}, loadErr
		}
		seen[value.ID] = true
		queries = append(queries, SavedQueryDefinition{ID: value.ID, Name: value.Name, Description: value.Description, Query: value.Query, Scope: value.Scope})
	}
	sort.Slice(queries, func(i, j int) bool { return queries[i].ID < queries[j].ID })
	definition := DashboardDefinition{Slug: dashboard.Slug, Name: dashboard.Name, Description: dashboard.Description, Panels: dashboard.Panels}
	return DashboardExport{Version: DashboardVersion, Dashboard: definition, SavedQueries: queries}, nil
}

// ImportDashboard validates one source-control-safe export and creates its
// queries, dashboard, and panels atomically with new server-owned identities.
// Tenant and actor metadata are supplied independently of the bundle.
func (s *Store) ImportDashboard(ctx context.Context, input DashboardImportInput, now time.Time) (Dashboard, error) {
	if input.Bundle.Version != DashboardVersion || model.ValidateSourceID(input.OrganizationID) != nil || model.ValidateSourceID(input.ActorUserID) != nil || input.MaxRows < 1 || input.MaxRows > 100_000 || now.IsZero() || len(input.Bundle.SavedQueries) > MaxDashboardPanels {
		return Dashboard{}, errors.New("dashboard import is invalid")
	}
	queryIDs := make(map[string]string, len(input.Bundle.SavedQueries))
	type importedQuery struct {
		definition SavedQueryDefinition
		id         string
		astJSON    string
		ast        query.AST
	}
	queries := make([]importedQuery, 0, len(input.Bundle.SavedQueries))
	for _, definition := range input.Bundle.SavedQueries {
		if model.ValidateSourceID(definition.ID) != nil || queryIDs[definition.ID] != "" {
			return Dashboard{}, errors.New("dashboard import query identity is invalid or duplicated")
		}
		ast, err := validateSavedQueryInput(SavedQueryInput{OrganizationID: input.OrganizationID, ActorUserID: input.ActorUserID, MaxRows: input.MaxRows, Name: definition.Name, Description: definition.Description, Query: definition.Query, Scope: definition.Scope}, now)
		if err != nil {
			return Dashboard{}, err
		}
		encoded, err := json.Marshal(ast)
		if err != nil {
			return Dashboard{}, errors.New("encode imported saved query AST")
		}
		id, err := storageID("query")
		if err != nil {
			return Dashboard{}, err
		}
		queryIDs[definition.ID] = id
		queries = append(queries, importedQuery{definition: definition, id: id, astJSON: string(encoded), ast: ast})
	}
	queryASTs := make(map[string]query.AST, len(queries))
	for _, imported := range queries {
		queryASTs[imported.definition.ID] = imported.ast
	}
	panels := make([]DashboardPanel, len(input.Bundle.Dashboard.Panels))
	referenced := make(map[string]bool, len(queries))
	for index, panel := range input.Bundle.Dashboard.Panels {
		mapped := queryIDs[panel.SavedQueryID]
		if mapped == "" {
			return Dashboard{}, errors.New("dashboard import panel references an unknown saved query")
		}
		ast := queryASTs[panel.SavedQueryID]
		if panel.Visualization == "stat" && ast.Summary == nil || panel.Visualization == "timeseries" && (ast.Summary == nil || ast.Bucket <= 0) {
			return Dashboard{}, errors.New("dashboard import presentation does not match its saved query")
		}
		panelID, err := storageID("panel")
		if err != nil {
			return Dashboard{}, err
		}
		panel.ID, panel.SavedQueryID = panelID, mapped
		panels[index] = panel
		referenced[panel.SavedQueryID] = true
	}
	if len(referenced) != len(queries) {
		return Dashboard{}, errors.New("dashboard import contains an unreferenced saved query")
	}
	dashboardID, err := storageID("dashboard")
	if err != nil {
		return Dashboard{}, err
	}
	dashboardInput := DashboardInput{ID: dashboardID, ExpectedRevision: 1, OrganizationID: input.OrganizationID, ActorUserID: input.ActorUserID, Slug: input.Bundle.Dashboard.Slug, Name: input.Bundle.Dashboard.Name, Description: input.Bundle.Dashboard.Description, Panels: panels}
	if err = validateDashboardInput(dashboardInput, now); err != nil {
		return Dashboard{}, err
	}
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return Dashboard{}, errors.New("begin dashboard import")
	}
	defer tx.Rollback()
	timestamp := now.UTC().Format(time.RFC3339Nano)
	for _, imported := range queries {
		definition := imported.definition
		_, err = tx.ExecContext(ctx, `INSERT INTO saved_queries(organization_id,id,version,revision,name,description,query_text,ast_json,project_id,environment_id,service_id,created_by,updated_by,created_at,updated_at) VALUES(?,?,1,1,?,?,?,?,?,?,?,?,?,?,?)`, input.OrganizationID, imported.id, definition.Name, definition.Description, strings.TrimSpace(definition.Query), imported.astJSON, definition.Scope.ProjectID, definition.Scope.EnvironmentID, definition.Scope.ServiceID, input.ActorUserID, input.ActorUserID, timestamp, timestamp)
		if err != nil {
			return Dashboard{}, errors.New("import saved query")
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO dashboards(organization_id,id,version,revision,slug,name,description,created_by,updated_by,created_at,updated_at) VALUES(?,?,1,1,?,?,?,?,?,?,?)`, input.OrganizationID, dashboardID, input.Bundle.Dashboard.Slug, input.Bundle.Dashboard.Name, input.Bundle.Dashboard.Description, input.ActorUserID, input.ActorUserID, timestamp, timestamp)
	if err != nil {
		return Dashboard{}, errors.New("import dashboard")
	}
	for _, panel := range panels {
		if _, err = tx.ExecContext(ctx, `INSERT INTO dashboard_panels(organization_id,dashboard_id,id,position,title,visualization,saved_query_id) VALUES(?,?,?,?,?,?,?)`, input.OrganizationID, dashboardID, panel.ID, panel.Position, panel.Title, panel.Visualization, panel.SavedQueryID); err != nil {
			return Dashboard{}, errors.New("import dashboard panel")
		}
	}
	if err = tx.Commit(); err != nil {
		return Dashboard{}, errors.New("commit dashboard import")
	}
	return s.Dashboard(ctx, input.OrganizationID, input.Bundle.Dashboard.Slug)
}

func validateSavedQueryInput(input SavedQueryInput, now time.Time) (query.AST, error) {
	if model.ValidateSourceID(input.OrganizationID) != nil || model.ValidateSourceID(input.ActorUserID) != nil || !boundedText(input.Name, 128, false) || !boundedText(input.Description, 1024, true) || !validResourceScope(input.Scope) || input.MaxRows < 1 || input.MaxRows > 100_000 || now.IsZero() {
		return query.AST{}, errors.New("saved query input is invalid")
	}
	ast, err := query.Parse(strings.TrimSpace(input.Query), input.MaxRows)
	if err != nil {
		return query.AST{}, fmt.Errorf("saved query: %w", err)
	}
	return ast, nil
}

func validateDashboardInput(input DashboardInput, now time.Time) error {
	if model.ValidateSourceID(input.OrganizationID) != nil || model.ValidateSourceID(input.ActorUserID) != nil || !validSlug(input.Slug) || !boundedText(input.Name, 128, false) || !boundedText(input.Description, 1024, true) || len(input.Panels) > MaxDashboardPanels || now.IsZero() {
		return errors.New("dashboard input is invalid")
	}
	positions := map[int]bool{}
	ids := map[string]bool{}
	for _, panel := range input.Panels {
		if err := validatePanelInput(panel); err != nil || positions[panel.Position] || panel.ID != "" && ids[panel.ID] {
			return errors.New("dashboard panel input is invalid")
		}
		positions[panel.Position] = true
		if panel.ID != "" {
			ids[panel.ID] = true
		}
	}
	return nil
}

func validateDashboard(value Dashboard) error {
	if value.Version != DashboardVersion || value.Revision < 1 || model.ValidateSourceID(value.OrganizationID) != nil || model.ValidateSourceID(value.ID) != nil || model.ValidateSourceID(value.CreatedBy) != nil || model.ValidateSourceID(value.UpdatedBy) != nil || !validSlug(value.Slug) || !boundedText(value.Name, 128, false) || !boundedText(value.Description, 1024, true) || len(value.Panels) > MaxDashboardPanels {
		return errors.New("dashboard is invalid")
	}
	return nil
}

func validatePanel(panel DashboardPanel) error {
	if model.ValidateSourceID(panel.ID) != nil {
		return errors.New("dashboard panel is invalid")
	}
	return validatePanelInput(panel)
}

func validatePanelInput(panel DashboardPanel) error {
	if panel.ID != "" && model.ValidateSourceID(panel.ID) != nil || panel.Position < 0 || panel.Position >= 64 || !boundedText(panel.Title, 128, false) || model.ValidateSourceID(panel.SavedQueryID) != nil {
		return errors.New("dashboard panel is invalid")
	}
	switch panel.Visualization {
	case "table", "stat", "timeseries":
		return nil
	default:
		return errors.New("dashboard panel visualization is invalid")
	}
}

func validResourceScope(scope ResourceScope) bool {
	values := []string{scope.ProjectID, scope.EnvironmentID, scope.ServiceID}
	for _, value := range values {
		if value != "" && model.ValidateSourceID(value) != nil {
			return false
		}
	}
	if scope.EnvironmentID != "" && scope.ProjectID == "" {
		return false
	}
	if scope.ServiceID != "" && (scope.ProjectID == "" || scope.EnvironmentID == "") {
		return false
	}
	return true
}

func boundedText(value string, maximum int, empty bool) bool {
	return utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n") && len(value) <= maximum && (empty || value != "")
}

func validSlug(value string) bool {
	if len(value) < 2 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func storageID(prefix string) (string, error) {
	random := make([]byte, 18)
	if _, err := rand.Read(random); err != nil {
		return "", errors.New("cryptographic randomness unavailable")
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(random), nil
}
