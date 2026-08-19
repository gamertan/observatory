// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/site"
	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/authhttp"
)

const defaultExploreQuery = "logs | window 1h | limit 50"

func (s *Server) explorePage(w http.ResponseWriter, r *http.Request) {
	view, _, ok := s.exploreView(w, r, defaultExploreQuery)
	if !ok {
		return
	}
	s.renderHTML(w, r, http.StatusOK, site.Explore(view))
}

func (s *Server) exploreForm(w http.ResponseWriter, r *http.Request) {
	values, err := readForm(w, r, 20<<10, "csrf_token", "query")
	queryText := defaultExploreQuery
	if err == nil {
		queryText = values.Get("query")
	}
	view, token, ok := s.exploreView(w, r, queryText)
	if !ok {
		return
	}
	csrfOK := err == nil && authhttp.VerifyCSRF(token, "query:execute", values.Get("csrf_token"))
	if !tokenBoundFormRequest(r, s.options.PublicOrigin, csrfOK) {
		view.ErrorMessage = "This query form expired or could not be verified. Please try again."
		s.renderHTML(w, r, http.StatusForbidden, site.Explore(view))
		return
	}
	if err != nil {
		view.ErrorMessage = "The query form was not accepted."
		s.renderHTML(w, r, http.StatusBadRequest, site.Explore(view))
		return
	}
	ast, err := query.Parse(queryText, s.options.MaxQueryRows)
	if err != nil {
		view.ErrorMessage = "The query could not be parsed. Check its stages, values, window, and limit."
		s.renderHTML(w, r, http.StatusUnprocessableEntity, site.Explore(view))
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	scope := access.Scope{OrganizationID: view.Organization.ID}
	sensitive, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionTelemetryReadSensitive)
	if err != nil {
		view.ErrorMessage = "Authorization is temporarily unavailable."
		s.renderHTML(w, r, http.StatusServiceUnavailable, site.Explore(view))
		return
	}
	result, err := s.store.Query(r.Context(), ast, query.Scope{OrganizationID: view.Organization.ID, Sensitive: sensitive.Allowed}, s.options.QueryBudget, s.now())
	switch {
	case errors.Is(err, query.ErrSensitivePermissionRequired):
		view.ErrorMessage = "This query requires permission to read sensitive fields."
		s.renderHTML(w, r, http.StatusForbidden, site.Explore(view))
		return
	case errors.Is(err, query.ErrBudgetExceeded):
		view.ErrorMessage = "This query exceeded its execution budget. Narrow the time window, fields, or result limit."
		s.renderHTML(w, r, http.StatusUnprocessableEntity, site.Explore(view))
		return
	case errors.Is(err, query.ErrTypeMismatch):
		view.ErrorMessage = "A query value did not match the selected field type."
		s.renderHTML(w, r, http.StatusUnprocessableEntity, site.Explore(view))
		return
	case err != nil:
		view.ErrorMessage = "The bounded query is temporarily unavailable. Your query text remains here to retry."
		s.renderHTML(w, r, http.StatusServiceUnavailable, site.Explore(view))
		return
	}
	view.Executed = true
	view.Table = resultTable("Authorized query results", result)
	view.Table.Empty = "No observations matched this query."
	view.Stats = site.QueryStatsView{
		ScannedRows: result.Stats.ScannedRows, MatchedRows: result.Stats.MatchedRows,
		ScannedBytes: formatQueryBytes(result.Stats.ScannedBytes),
		Duration:     formatQueryDuration(result.Stats.DurationNS),
		Truncated:    result.Stats.Truncated, Approximate: result.Stats.Approximate,
	}
	s.renderHTML(w, r, http.StatusOK, site.Explore(view))
}

func (s *Server) exploreView(w http.ResponseWriter, r *http.Request, queryText string) (site.ExploreView, string, bool) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login/", http.StatusSeeOther)
		return site.ExploreView{}, "", false
	}
	values := r.URL.Query()
	organizationID := values.Get("organization")
	if len(values) != 1 || len(values["organization"]) != 1 || organizationID == "" {
		writeProblem(w, http.StatusBadRequest, "organization is required")
		return site.ExploreView{}, "", false
	}
	organizations, err := s.identity.OrganizationsForUser(r.Context(), principal.User.ID)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "organization list unavailable")
		return site.ExploreView{}, "", false
	}
	organizationName := ""
	for _, organization := range organizations {
		if organization.ID == organizationID {
			organizationName = organization.Name
			break
		}
	}
	if organizationName == "" {
		writeProblem(w, http.StatusForbidden, "organization access denied")
		return site.ExploreView{}, "", false
	}
	scope := access.Scope{OrganizationID: organizationID}
	decision, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionTelemetryQuery)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "authorization unavailable")
		return site.ExploreView{}, "", false
	}
	if !decision.Allowed {
		writeProblem(w, http.StatusForbidden, "telemetry query access denied")
		return site.ExploreView{}, "", false
	}
	if err = s.identity.ValidateResourceScope(r.Context(), scope); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid organization")
		return site.ExploreView{}, "", false
	}
	token, ok := authhttp.SessionToken(r, s.cookie)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "authentication required")
		return site.ExploreView{}, "", false
	}
	csrf, err := authhttp.CSRFToken(token, "query:execute")
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return site.ExploreView{}, "", false
	}
	view := site.ExploreView{
		Head:         s.head("Explore — Gamertan Observatory", "Run an authorized, bounded query against organization evidence.", "/app/explore/"),
		DisplayName:  principal.User.DisplayName,
		Organization: site.OrganizationOption{ID: organizationID, Name: organizationName, Selected: true},
		Query:        queryText, CSRFToken: csrf,
		EventsURL: "/app/events?organization=" + url.QueryEscape(organizationID),
	}
	return view, token, true
}

func formatQueryBytes(value int64) string {
	if value < 1024 {
		return fmt.Sprintf("%d B", value)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	amount := float64(value)
	for _, unit := range units {
		amount /= 1024
		if amount < 1024 || unit == units[len(units)-1] {
			return fmt.Sprintf("%.1f %s", amount, unit)
		}
	}
	return fmt.Sprintf("%d B", value)
}

func formatQueryDuration(nanoseconds int64) string {
	duration := time.Duration(nanoseconds)
	if duration < time.Microsecond {
		return duration.String()
	}
	if duration < time.Millisecond {
		return duration.Round(time.Microsecond).String()
	}
	return duration.Round(time.Millisecond).String()
}
