// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/site"
	"gamertan.com/observatory/internal/storage"
	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/authhttp"
)

// EvaluateAlerts performs one bounded due-rule pass. It publishes only a
// generic organization invalidation signal when an incident changed;
// telemetry and incident details never enter the SSE stream.
func (s *Server) EvaluateAlerts(ctx context.Context) (int, error) {
	evaluations, err := s.store.EvaluateDueAlertRules(ctx, s.options.QueryBudget, s.now())
	if err != nil {
		return 0, err
	}
	organizations := map[string]struct{}{}
	for _, evaluation := range evaluations {
		if evaluation.IncidentChanged {
			organizations[evaluation.OrganizationID] = struct{}{}
		}
		if evaluation.IncidentChanged && evaluation.IncidentState == "firing" && s.options.PushDispatcher != nil {
			s.options.PushDispatcher.Enqueue(evaluation.OrganizationID)
		}
	}
	for organizationID := range organizations {
		s.refresh.publish(organizationID)
	}
	return len(evaluations), nil
}

func (s *Server) incidentInbox(w http.ResponseWriter, r *http.Request) {
	principal, organizationID, organizationName, ok := s.authorizeIncidentRead(w, r)
	if !ok {
		return
	}
	scope := access.Scope{OrganizationID: organizationID}
	incidents, err := s.store.Incidents(r.Context(), organizationID, true, 100)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "incidents unavailable")
		return
	}
	rules, err := s.store.AlertRules(r.Context(), organizationID)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "alert rules unavailable")
		return
	}
	saved, err := s.store.SavedQueries(r.Context(), organizationID)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "saved queries unavailable")
		return
	}
	view := site.IncidentInboxView{
		Head:         s.head("Incident inbox — Gamertan Observatory", "Authorized incident response and bounded alert rules.", "/app/incidents/"),
		DisplayName:  principal.User.DisplayName,
		Organization: site.OrganizationOption{ID: organizationID, Name: organizationName, Selected: true},
		EventsURL:    "/app/events?organization=" + url.QueryEscape(organizationID),
		OfflineURL:   "/app/incidents/offline/?organization=" + url.QueryEscape(organizationID),
		CacheKey:     "/app/incidents/?organization=" + url.QueryEscape(organizationID),
	}
	if s.options.PushDispatcher != nil {
		token, sessionOK := authhttp.SessionToken(r, s.cookie)
		if !sessionOK {
			writeProblem(w, http.StatusUnauthorized, "authentication required")
			return
		}
		view.PushPublicKey = s.options.PushPublicKey
		view.PushCSRF, err = authhttp.CSRFToken(token, "push:manage")
		if err != nil {
			writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
			return
		}
	}
	for _, incident := range incidents {
		item := site.IncidentSummary{ID: incident.ID, Title: incident.Title, State: incident.State, Severity: incident.Severity, StartedAt: incident.StartedAt.Format("2006-01-02 15:04:05 UTC"), UpdatedAt: incident.UpdatedAt.Format("2006-01-02 15:04:05 UTC")}
		if incident.SilencedUntil != nil {
			item.SilencedUntil = incident.SilencedUntil.Format("2006-01-02 15:04:05 UTC")
		}
		view.Incidents = append(view.Incidents, item)
		if incident.State != "resolved" {
			view.OpenCount++
		}
	}
	for _, rule := range rules {
		item := site.AlertRuleSummary{Name: rule.Name, Description: rule.Description, Severity: rule.Severity, Enabled: rule.Enabled, Interval: rule.EvaluationInterval.String(), LastError: rule.LastError}
		if rule.LastEvaluatedAt != nil {
			item.LastEvaluatedAt = rule.LastEvaluatedAt.Format("2006-01-02 15:04:05 UTC")
		}
		view.Rules = append(view.Rules, item)
	}
	for _, savedQuery := range saved {
		view.SavedQueries = append(view.SavedQueries, site.SavedQuerySummary{ID: savedQuery.ID, Name: savedQuery.Name, Description: savedQuery.Description, Query: savedQuery.Query})
	}
	manage, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionIncidentsManage)
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
		view.ManageCSRF, err = authhttp.CSRFToken(token, "incidents:manage")
		if err != nil {
			writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
			return
		}
	}
	s.renderHTML(w, r, http.StatusOK, site.IncidentInbox(view))
}

func (s *Server) offlineIncidentInbox(w http.ResponseWriter, r *http.Request) {
	_, organizationID, organizationName, ok := s.authorizeIncidentRead(w, r)
	if !ok {
		return
	}
	incidents, err := s.store.Incidents(r.Context(), organizationID, false, 100)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "incidents unavailable")
		return
	}
	view := site.OfflineIncidentView{
		Head:         s.head("Saved incident inbox — Gamertan Observatory", "A deliberately saved read-only incident snapshot.", "/app/incidents/"),
		Organization: site.OrganizationOption{ID: organizationID, Name: organizationName, Selected: true},
		CapturedAt:   s.now().Format("2006-01-02 15:04:05 UTC"),
	}
	for _, incident := range incidents {
		item := site.IncidentSummary{Title: incident.Title, State: incident.State, Severity: incident.Severity, StartedAt: incident.StartedAt.Format("2006-01-02 15:04:05 UTC"), UpdatedAt: incident.UpdatedAt.Format("2006-01-02 15:04:05 UTC")}
		if incident.SilencedUntil != nil {
			item.SilencedUntil = incident.SilencedUntil.Format("2006-01-02 15:04:05 UTC")
		}
		view.Incidents = append(view.Incidents, item)
	}
	s.renderHTML(w, r, http.StatusOK, site.OfflineIncidentInbox(view))
}

func (s *Server) authorizeIncidentRead(w http.ResponseWriter, r *http.Request) (auth.Principal, string, string, bool) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login/", http.StatusSeeOther)
		return auth.Principal{}, "", "", false
	}
	values := r.URL.Query()
	organizationValues, exists := values["organization"]
	if !exists || len(values) != 1 || len(organizationValues) != 1 || organizationValues[0] == "" {
		writeProblem(w, http.StatusBadRequest, "incident organization is required")
		return auth.Principal{}, "", "", false
	}
	organizationID := organizationValues[0]
	scope := access.Scope{OrganizationID: organizationID}
	decision, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionIncidentsRead)
	if err != nil || !decision.Allowed {
		writeProblem(w, http.StatusForbidden, "incident access denied")
		return auth.Principal{}, "", "", false
	}
	if err = s.identity.ValidateResourceScope(r.Context(), scope); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid organization")
		return auth.Principal{}, "", "", false
	}
	organizations, err := s.identity.OrganizationsForUser(r.Context(), principal.User.ID)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "organization unavailable")
		return auth.Principal{}, "", "", false
	}
	for _, organization := range organizations {
		if organization.ID == organizationID {
			return principal, organizationID, organization.Name, true
		}
	}
	writeProblem(w, http.StatusForbidden, "incident access denied")
	return auth.Principal{}, "", "", false
}

func (s *Server) createAlertRule(w http.ResponseWriter, r *http.Request) {
	values, principal, ok := s.authorizeIncidentForm(w, r, []string{"organization_id", "csrf_token", "name", "description", "saved_query_id", "severity", "minimum_matches", "required_consecutive", "evaluation_interval"}, nil)
	if !ok {
		return
	}
	minimumMatches, err := strconv.Atoi(values.Get("minimum_matches"))
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "alert rule rejected")
		return
	}
	requiredConsecutive, err := strconv.Atoi(values.Get("required_consecutive"))
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "alert rule rejected")
		return
	}
	intervals := map[string]time.Duration{"15s": 15 * time.Second, "30s": 30 * time.Second, "1m": time.Minute, "5m": 5 * time.Minute, "15m": 15 * time.Minute}
	interval, exists := intervals[values.Get("evaluation_interval")]
	if !exists {
		writeProblem(w, http.StatusUnprocessableEntity, "alert rule rejected")
		return
	}
	_, err = s.store.SaveAlertRule(r.Context(), storage.AlertRuleInput{
		OrganizationID: values.Get("organization_id"), Name: values.Get("name"), Description: values.Get("description"),
		SavedQueryID: values.Get("saved_query_id"), Severity: values.Get("severity"), MinimumMatches: minimumMatches,
		RequiredConsecutive: requiredConsecutive, EvaluationInterval: interval, Enabled: true, ActorUserID: principal.User.ID,
	}, s.now())
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "alert rule rejected")
		return
	}
	http.Redirect(w, r, "/app/incidents/?organization="+url.QueryEscape(values.Get("organization_id")), http.StatusSeeOther)
}

func (s *Server) transitionIncident(w http.ResponseWriter, r *http.Request) {
	values, principal, ok := s.authorizeIncidentForm(w, r, []string{"organization_id", "csrf_token", "action"}, []string{"silence_duration"})
	if !ok {
		return
	}
	var silenceUntil *time.Time
	if values.Get("action") == "silence" {
		durations := map[string]time.Duration{"15m": 15 * time.Minute, "1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "168h": 7 * 24 * time.Hour}
		duration, exists := durations[values.Get("silence_duration")]
		if !exists {
			writeProblem(w, http.StatusUnprocessableEntity, "incident transition rejected")
			return
		}
		until := s.now().Add(duration)
		silenceUntil = &until
	} else if values.Get("silence_duration") != "" {
		writeProblem(w, http.StatusUnprocessableEntity, "incident transition rejected")
		return
	}
	_, err := s.store.TransitionIncident(r.Context(), values.Get("organization_id"), r.PathValue("id"), values.Get("action"), principal.User.ID, silenceUntil, s.now())
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "incident transition rejected")
		return
	}
	s.refresh.publish(values.Get("organization_id"))
	http.Redirect(w, r, "/app/incidents/?organization="+url.QueryEscape(values.Get("organization_id")), http.StatusSeeOther)
}

func (s *Server) authorizeIncidentForm(w http.ResponseWriter, r *http.Request, required, optional []string) (url.Values, auth.Principal, bool) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	values, err := readFormFields(w, r, 24<<10, required, optional)
	token, sessionOK := authhttp.SessionToken(r, s.cookie)
	csrfOK := err == nil && sessionOK && authhttp.VerifyCSRF(token, "incidents:manage", values.Get("csrf_token"))
	if !tokenBoundFormRequest(r, s.options.PublicOrigin, csrfOK) {
		writeProblem(w, http.StatusForbidden, "valid incident form required")
		return nil, auth.Principal{}, false
	}
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "authentication required")
		return nil, auth.Principal{}, false
	}
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid incident management request")
		return nil, auth.Principal{}, false
	}
	scope := access.Scope{OrganizationID: values.Get("organization_id")}
	decision, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionIncidentsManage)
	if err != nil || !decision.Allowed {
		writeProblem(w, http.StatusForbidden, "incident management denied")
		return nil, auth.Principal{}, false
	}
	if err = s.identity.ValidateResourceScope(r.Context(), scope); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid organization")
		return nil, auth.Principal{}, false
	}
	if !csrfOK {
		writeProblem(w, http.StatusForbidden, "valid incident CSRF token required")
		return nil, auth.Principal{}, false
	}
	return values, principal, true
}
