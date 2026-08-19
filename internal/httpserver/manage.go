// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/site"
	"gamertan.com/observatory/internal/storage"
	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/authhttp"
)

func (s *Server) createSavedQuery(w http.ResponseWriter, r *http.Request) {
	values, principal, ok := s.authorizeManagementForm(w, r, "organization_id", "csrf_token", "name", "description", "query")
	if !ok {
		return
	}
	s.saveQuery(w, r, values, principal, values.Get("query"))
}

func (s *Server) createBuiltQuery(w http.ResponseWriter, r *http.Request) {
	required := []string{"organization_id", "csrf_token", "name", "description", "signal", "filter_operator", "window", "aggregate", "limit"}
	optional := []string{"filter_field", "filter_value", "aggregate_field", "group_by", "bucket"}
	values, principal, ok := s.authorizeManagementFormFields(w, r, required, optional)
	if !ok {
		return
	}
	text, err := buildAssistedQuery(values, s.options.MaxQueryRows)
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "assisted query rejected")
		return
	}
	s.saveQuery(w, r, values, principal, text)
}

func (s *Server) saveQuery(w http.ResponseWriter, r *http.Request, values url.Values, principal auth.Principal, text string) {
	_, err := s.store.SaveQuery(r.Context(), storage.SavedQueryInput{
		OrganizationID: values.Get("organization_id"), Name: values.Get("name"),
		Description: values.Get("description"), Query: text,
		ActorUserID: principal.User.ID, MaxRows: s.options.MaxQueryRows,
	}, s.now())
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "saved query rejected")
		return
	}
	http.Redirect(w, r, "/app/?organization="+url.QueryEscape(values.Get("organization_id"))+"#saved-work", http.StatusSeeOther)
}

func buildAssistedQuery(values url.Values, maxRows int) (string, error) {
	allowed := func(value string, candidates ...string) bool {
		for _, candidate := range candidates {
			if value == candidate {
				return true
			}
		}
		return false
	}
	signal := values.Get("signal")
	if !allowed(signal, "logs", "metrics", "traces", "deployments") {
		return "", fmt.Errorf("unsupported signal")
	}
	window := values.Get("window")
	if !allowed(window, "15m", "1h", "6h", "24h", "168h") {
		return "", fmt.Errorf("unsupported window")
	}
	limit, err := strconv.Atoi(values.Get("limit"))
	if err != nil || limit < 1 || limit > maxRows || !allowed(values.Get("limit"), "10", "20", "50", "100", "250") {
		return "", fmt.Errorf("unsupported limit")
	}
	stages := []string{signal}
	filterField := values.Get("filter_field")
	filterValue := values.Get("filter_value")
	filterOperator := values.Get("filter_operator")
	if !allowed(filterOperator, "==", "!=", ">=", "<=", ">", "<") {
		return "", fmt.Errorf("invalid filter comparison")
	}
	if filterField == "" {
		if filterValue != "" {
			return "", fmt.Errorf("filter value requires a field")
		}
	} else {
		if !allowed(filterField, "service", "project", "environment", "route", "status", "duration", "name", "severity", "value", "trace_id", "correlation_id") ||
			filterValue == "" || len(filterValue) > 256 || !utf8.ValidString(filterValue) || strings.IndexByte(filterValue, 0) >= 0 {
			return "", fmt.Errorf("invalid filter")
		}
		quoted := strconv.Quote(filterValue)
		quoted = strings.ReplaceAll(quoted, "|", `\u007c`)
		stages = append(stages, "where "+filterField+" "+filterOperator+" "+quoted)
	}
	stages = append(stages, "window "+window)

	aggregate := values.Get("aggregate")
	aggregateField := values.Get("aggregate_field")
	groupBy := values.Get("group_by")
	bucket := values.Get("bucket")
	if aggregate == "none" {
		if aggregateField != "" || groupBy != "" || bucket != "" {
			return "", fmt.Errorf("summary options require an aggregate")
		}
	} else {
		if !allowed(aggregate, "count", "min", "max", "sum", "avg", "p50", "p95", "p99") ||
			!allowed(groupBy, "", "service", "project", "environment", "route", "status", "name", "severity") ||
			!allowed(bucket, "", "1m", "5m", "15m", "1h") {
			return "", fmt.Errorf("invalid summary")
		}
		expression := "count()"
		if aggregate == "count" {
			if aggregateField != "" {
				return "", fmt.Errorf("count accepts no field")
			}
		} else {
			if !allowed(aggregateField, "value", "duration", "status") {
				return "", fmt.Errorf("numeric aggregate field required")
			}
			expression = aggregate + "(" + aggregateField + ")"
		}
		groups := make([]string, 0, 2)
		if groupBy != "" {
			groups = append(groups, groupBy)
		}
		if bucket != "" {
			groups = append(groups, "window("+bucket+")")
		}
		stage := "summarize " + expression
		if len(groups) > 0 {
			stage += " by " + strings.Join(groups, ", ")
		}
		stages = append(stages, stage)
	}
	stages = append(stages, "limit "+strconv.Itoa(limit))
	text := strings.Join(stages, " | ")
	if _, err = query.Parse(text, maxRows); err != nil {
		return "", err
	}
	return text, nil
}

func (s *Server) createDashboard(w http.ResponseWriter, r *http.Request) {
	values, principal, ok := s.authorizeManagementForm(w, r, "organization_id", "csrf_token", "slug", "name", "description", "panel_title", "saved_query_id", "visualization")
	if !ok {
		return
	}
	organizationID := values.Get("organization_id")
	queryValue, err := s.store.SavedQuery(r.Context(), organizationID, values.Get("saved_query_id"))
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "dashboard query rejected")
		return
	}
	visualization := values.Get("visualization")
	if !validDashboardPresentation(queryValue, visualization) {
		writeProblem(w, http.StatusUnprocessableEntity, "dashboard presentation does not match query")
		return
	}
	_, err = s.store.SaveDashboard(r.Context(), storage.DashboardInput{
		OrganizationID: organizationID, Slug: values.Get("slug"), Name: values.Get("name"),
		Description: values.Get("description"), ActorUserID: principal.User.ID,
		Panels: []storage.DashboardPanel{{Position: 0, Title: values.Get("panel_title"), Visualization: visualization, SavedQueryID: queryValue.ID}},
	}, s.now())
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "dashboard rejected")
		return
	}
	http.Redirect(w, r, "/app/dashboards/"+url.PathEscape(values.Get("slug"))+"/?organization="+url.QueryEscape(organizationID), http.StatusSeeOther)
}

func (s *Server) updateDashboard(w http.ResponseWriter, r *http.Request) {
	values, principal, ok := s.authorizeManagementForm(w, r, "organization_id", "csrf_token", "dashboard_id", "expected_revision", "slug", "name", "description")
	if !ok {
		return
	}
	current, ok := s.dashboardForRevision(w, r, values)
	if !ok {
		return
	}
	updated, err := s.store.SaveDashboard(r.Context(), storage.DashboardInput{
		ID: current.ID, ExpectedRevision: current.Revision, OrganizationID: current.OrganizationID,
		Slug: values.Get("slug"), Name: values.Get("name"), Description: values.Get("description"),
		Panels: current.Panels, ActorUserID: principal.User.ID,
	}, s.now())
	if !writeDashboardRevisionResult(w, err) {
		return
	}
	redirectDashboard(w, r, updated.Slug, current.OrganizationID)
}

func (s *Server) addDashboardPanel(w http.ResponseWriter, r *http.Request) {
	values, principal, ok := s.authorizeManagementForm(w, r, "organization_id", "csrf_token", "dashboard_id", "expected_revision", "panel_title", "saved_query_id", "visualization")
	if !ok {
		return
	}
	current, ok := s.dashboardForRevision(w, r, values)
	if !ok {
		return
	}
	queryValue, err := s.store.SavedQuery(r.Context(), current.OrganizationID, values.Get("saved_query_id"))
	if err != nil || !validDashboardPresentation(queryValue, values.Get("visualization")) {
		writeProblem(w, http.StatusUnprocessableEntity, "dashboard panel rejected")
		return
	}
	panels := append([]storage.DashboardPanel(nil), current.Panels...)
	panels = append(panels, storage.DashboardPanel{Position: len(panels), Title: values.Get("panel_title"), Visualization: values.Get("visualization"), SavedQueryID: queryValue.ID})
	updated, err := s.store.SaveDashboard(r.Context(), storage.DashboardInput{
		ID: current.ID, ExpectedRevision: current.Revision, OrganizationID: current.OrganizationID,
		Slug: current.Slug, Name: current.Name, Description: current.Description,
		Panels: panels, ActorUserID: principal.User.ID,
	}, s.now())
	if !writeDashboardRevisionResult(w, err) {
		return
	}
	redirectDashboard(w, r, updated.Slug, current.OrganizationID)
}

func (s *Server) updateDashboardPanel(w http.ResponseWriter, r *http.Request) {
	values, principal, ok := s.authorizeManagementForm(w, r, "organization_id", "csrf_token", "dashboard_id", "expected_revision", "panel_title", "saved_query_id", "visualization")
	if !ok {
		return
	}
	current, ok := s.dashboardForRevision(w, r, values)
	if !ok {
		return
	}
	queryValue, err := s.store.SavedQuery(r.Context(), current.OrganizationID, values.Get("saved_query_id"))
	if err != nil || !validDashboardPresentation(queryValue, values.Get("visualization")) {
		writeProblem(w, http.StatusUnprocessableEntity, "dashboard panel rejected")
		return
	}
	panelID := r.PathValue("panel")
	panels := append([]storage.DashboardPanel(nil), current.Panels...)
	found := false
	for index := range panels {
		if panels[index].ID != panelID {
			continue
		}
		panels[index].Title = values.Get("panel_title")
		panels[index].Visualization = values.Get("visualization")
		panels[index].SavedQueryID = queryValue.ID
		found = true
		break
	}
	if !found {
		writeProblem(w, http.StatusNotFound, "dashboard panel not found")
		return
	}
	updated, err := s.store.SaveDashboard(r.Context(), storage.DashboardInput{
		ID: current.ID, ExpectedRevision: current.Revision, OrganizationID: current.OrganizationID,
		Slug: current.Slug, Name: current.Name, Description: current.Description,
		Panels: panels, ActorUserID: principal.User.ID,
	}, s.now())
	if !writeDashboardRevisionResult(w, err) {
		return
	}
	redirectDashboard(w, r, updated.Slug, current.OrganizationID)
}

func (s *Server) removeDashboardPanel(w http.ResponseWriter, r *http.Request) {
	values, principal, ok := s.authorizeManagementForm(w, r, "organization_id", "csrf_token", "dashboard_id", "expected_revision")
	if !ok {
		return
	}
	current, ok := s.dashboardForRevision(w, r, values)
	if !ok {
		return
	}
	panelID := r.PathValue("panel")
	panels := make([]storage.DashboardPanel, 0, len(current.Panels))
	for _, panel := range current.Panels {
		if panel.ID != panelID {
			panel.Position = len(panels)
			panels = append(panels, panel)
		}
	}
	if len(panels) == len(current.Panels) {
		writeProblem(w, http.StatusNotFound, "dashboard panel not found")
		return
	}
	updated, err := s.store.SaveDashboard(r.Context(), storage.DashboardInput{
		ID: current.ID, ExpectedRevision: current.Revision, OrganizationID: current.OrganizationID,
		Slug: current.Slug, Name: current.Name, Description: current.Description,
		Panels: panels, ActorUserID: principal.User.ID,
	}, s.now())
	if !writeDashboardRevisionResult(w, err) {
		return
	}
	redirectDashboard(w, r, updated.Slug, current.OrganizationID)
}

func (s *Server) dashboardForRevision(w http.ResponseWriter, r *http.Request, values url.Values) (storage.Dashboard, bool) {
	current, err := s.store.Dashboard(r.Context(), values.Get("organization_id"), r.PathValue("slug"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "dashboard not found")
		return storage.Dashboard{}, false
	}
	revision, err := strconv.Atoi(values.Get("expected_revision"))
	if err != nil || revision < 1 || values.Get("dashboard_id") != current.ID {
		writeProblem(w, http.StatusBadRequest, "dashboard revision is invalid")
		return storage.Dashboard{}, false
	}
	if revision != current.Revision {
		writeProblem(w, http.StatusConflict, "dashboard changed; reload before editing")
		return storage.Dashboard{}, false
	}
	return current, true
}

func validDashboardPresentation(saved storage.SavedQuery, visualization string) bool {
	switch visualization {
	case "table":
		return true
	case "stat":
		return saved.AST.Summary != nil
	case "timeseries":
		return saved.AST.Summary != nil && saved.AST.Bucket > 0
	default:
		return false
	}
}

func writeDashboardRevisionResult(w http.ResponseWriter, err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, storage.ErrDashboardRevisionConflict) {
		writeProblem(w, http.StatusConflict, "dashboard changed; reload before editing")
	} else {
		writeProblem(w, http.StatusUnprocessableEntity, "dashboard revision rejected")
	}
	return false
}

func redirectDashboard(w http.ResponseWriter, r *http.Request, slug, organizationID string) {
	http.Redirect(w, r, "/app/dashboards/"+url.PathEscape(slug)+"/?organization="+url.QueryEscape(organizationID), http.StatusSeeOther)
}

func (s *Server) authorizeManagementForm(w http.ResponseWriter, r *http.Request, fields ...string) (url.Values, auth.Principal, bool) {
	return s.authorizeManagementFormFields(w, r, fields, nil)
}

func (s *Server) authorizeManagementFormFields(w http.ResponseWriter, r *http.Request, required, optional []string) (url.Values, auth.Principal, bool) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	values, err := readFormFields(w, r, 24<<10, required, optional)
	token, sessionOK := authhttp.SessionToken(r, s.cookie)
	csrfOK := err == nil && sessionOK && authhttp.VerifyCSRF(token, "dashboards:manage", values.Get("csrf_token"))
	if !tokenBoundFormRequest(r, s.options.PublicOrigin, csrfOK) {
		writeProblem(w, http.StatusForbidden, "valid dashboard form required")
		return nil, auth.Principal{}, false
	}
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "authentication required")
		return nil, auth.Principal{}, false
	}
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid dashboard management request")
		return nil, auth.Principal{}, false
	}
	organizationID := values.Get("organization_id")
	scope := access.Scope{OrganizationID: organizationID}
	if err = s.identity.ValidateResourceScope(r.Context(), scope); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid organization")
		return nil, auth.Principal{}, false
	}
	decision, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionDashboardsManage)
	if err != nil || !decision.Allowed {
		writeProblem(w, http.StatusForbidden, "dashboard management denied")
		return nil, auth.Principal{}, false
	}
	if !csrfOK {
		writeProblem(w, http.StatusForbidden, "valid dashboard CSRF token required")
		return nil, auth.Principal{}, false
	}
	return values, principal, true
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	organizationID, principal, ok := s.authorizeDashboardRead(w, r)
	if !ok {
		return
	}
	dashboard, err := s.store.Dashboard(r.Context(), organizationID, r.PathValue("slug"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "dashboard not found")
		return
	}
	organizations, err := s.identity.OrganizationsForUser(r.Context(), principal.User.ID)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "organization unavailable")
		return
	}
	organizationName := "Organization"
	for _, organization := range organizations {
		if organization.ID == organizationID {
			organizationName = organization.Name
			break
		}
	}
	view := site.DashboardView{
		Head:        s.head(dashboard.Name+" — Gamertan Observatory", dashboard.Description, "/app/dashboards/"+url.PathEscape(dashboard.Slug)+"/"),
		DisplayName: principal.User.DisplayName, Organization: site.OrganizationOption{ID: organizationID, Name: organizationName, Selected: true},
		ID: dashboard.ID, Slug: dashboard.Slug, Revision: dashboard.Revision,
		Name: dashboard.Name, Description: dashboard.Description,
		ExportURL: "/app/dashboards/" + url.PathEscape(dashboard.Slug) + "/export.json?organization=" + url.QueryEscape(organizationID),
	}
	manage, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, access.Scope{OrganizationID: organizationID}, identity.PermissionDashboardsManage)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "authorization unavailable")
		return
	}
	view.CanManage = manage.Allowed
	if view.CanManage {
		token, sessionOK := authhttp.SessionToken(r, s.cookie)
		if !sessionOK {
			writeProblem(w, http.StatusUnauthorized, "authentication required")
			return
		}
		view.ManageCSRF, err = authhttp.CSRFToken(token, "dashboards:manage")
		if err != nil {
			writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
			return
		}
		savedQueries, loadErr := s.store.SavedQueries(r.Context(), organizationID)
		if loadErr != nil {
			writeProblem(w, http.StatusServiceUnavailable, "saved queries unavailable")
			return
		}
		for _, saved := range savedQueries {
			view.SavedQueries = append(view.SavedQueries, site.SavedQuerySummary{ID: saved.ID, Name: saved.Name, Description: saved.Description, Query: saved.Query})
		}
	}
	for _, panel := range dashboard.Panels {
		view.Panels = append(view.Panels, s.dashboardPanel(r, principal.User.ID, organizationID, panel))
	}
	s.renderHTML(w, r, http.StatusOK, site.Dashboard(view))
}

func (s *Server) dashboardPanel(r *http.Request, userID, organizationID string, panel storage.DashboardPanel) site.PanelView {
	view := site.PanelView{ID: panel.ID, SavedQueryID: panel.SavedQueryID, Title: panel.Title, Visualization: panel.Visualization, Table: site.TableView{Caption: panel.Title, Columns: []site.TableColumn{{Label: "Status"}}, Empty: "Panel data is unavailable."}}
	saved, err := s.store.SavedQuery(r.Context(), organizationID, panel.SavedQueryID)
	if err != nil {
		return view
	}
	view.Query = saved.Query
	scope := access.Scope{OrganizationID: organizationID, ProjectID: saved.Scope.ProjectID, EnvironmentID: saved.Scope.EnvironmentID, ServiceID: saved.Scope.ServiceID}
	decision, err := s.identity.Access.Authorize(r.Context(), userID, scope, identity.PermissionTelemetryQuery)
	if err != nil || !decision.Allowed || s.identity.ValidateResourceScope(r.Context(), scope) != nil {
		return view
	}
	sensitive, err := s.identity.Access.Authorize(r.Context(), userID, scope, identity.PermissionTelemetryReadSensitive)
	if err != nil {
		return view
	}
	result, err := s.store.Query(r.Context(), saved.AST, query.Scope{OrganizationID: organizationID, ProjectID: saved.Scope.ProjectID, EnvironmentID: saved.Scope.EnvironmentID, ServiceID: saved.Scope.ServiceID, Sensitive: sensitive.Allowed}, s.options.QueryBudget, s.now())
	if err != nil {
		return view
	}
	view.Table = resultTable(panel.Title, result)
	if panel.Visualization == "timeseries" {
		view.Chart = resultChart(panel.Title, result)
	}
	if panel.Visualization == "stat" {
		for _, row := range result.Rows {
			for _, value := range row.Values {
				if value != nil {
					view.Stat = boundedCell(*value)
					return view
				}
			}
		}
	}
	return view
}

func resultChart(title string, result query.Result) site.ChartView {
	if len(result.Columns) < 2 || len(result.Rows) == 0 {
		return site.ChartView{}
	}
	valueIndex := len(result.Columns) - 1
	valueType := result.Columns[valueIndex].Type
	if valueType != "integer" && valueType != "float" && valueType != "duration" {
		return site.ChartView{}
	}
	const maxPoints = 48
	points := make([]struct {
		label, display string
		value          float64
	}, 0, min(len(result.Rows), maxPoints))
	maximum := float64(0)
	for index, row := range result.Rows {
		if index >= maxPoints || valueIndex >= len(row.Values) || row.Values[valueIndex] == nil {
			continue
		}
		value, err := strconv.ParseFloat(*row.Values[valueIndex], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return site.ChartView{}
		}
		labels := make([]string, 0, valueIndex)
		for column := 0; column < valueIndex && column < len(row.Values); column++ {
			if row.Values[column] != nil {
				labels = append(labels, boundedCell(*row.Values[column]))
			}
		}
		label := boundedCell(strings.Join(labels, " · "))
		if label == "" {
			label = fmt.Sprintf("Point %d", index+1)
		}
		display := boundedCell(*row.Values[valueIndex])
		if unit := result.Columns[valueIndex].Unit; unit != "" {
			display += " " + boundedCell(unit)
		}
		points = append(points, struct {
			label, display string
			value          float64
		}{label: label, display: display, value: value})
		maximum = math.Max(maximum, value)
	}
	if len(points) == 0 {
		return site.ChartView{}
	}
	if maximum == 0 {
		maximum = 1
	}
	view := site.ChartView{Label: title + " visual summary"}
	for _, point := range points {
		view.Points = append(view.Points, site.ChartPoint{
			Label: point.label, Value: strconv.FormatFloat(point.value, 'g', -1, 64),
			Maximum: strconv.FormatFloat(maximum, 'g', -1, 64), Display: point.display,
		})
	}
	return view
}

func (s *Server) exportDashboard(w http.ResponseWriter, r *http.Request) {
	organizationID, _, ok := s.authorizeDashboardRead(w, r)
	if !ok {
		return
	}
	exported, err := s.store.ExportDashboard(r.Context(), organizationID, r.PathValue("slug"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "dashboard not found")
		return
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(exported); err != nil {
		writeProblem(w, http.StatusInternalServerError, "dashboard export unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "observatory-dashboard-"+r.PathValue("slug")+".json"))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", body.Len()))
	if r.Method != http.MethodHead {
		_, _ = w.Write(body.Bytes())
	}
}

func (s *Server) authorizeDashboardRead(w http.ResponseWriter, r *http.Request) (string, auth.Principal, bool) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "authentication required")
		return "", auth.Principal{}, false
	}
	values := r.URL.Query()
	organizationID := values.Get("organization")
	if len(values) != 1 || len(values["organization"]) != 1 || organizationID == "" {
		writeProblem(w, http.StatusBadRequest, "organization is required")
		return "", auth.Principal{}, false
	}
	scope := access.Scope{OrganizationID: organizationID}
	if err := s.identity.ValidateResourceScope(r.Context(), scope); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid organization")
		return "", auth.Principal{}, false
	}
	decision, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionDashboardsRead)
	if err != nil || !decision.Allowed {
		writeProblem(w, http.StatusForbidden, "dashboard access denied")
		return "", auth.Principal{}, false
	}
	return organizationID, principal, true
}
