// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/site"
	"gamertan.com/sandwich-hime/sando"
	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/authhttp"
	"gamertan.com/web/websec"
)

const loginCSRFCookieName = "__Host-observatory_login_csrf"

const (
	loginFormFailure       = "This sign-in form expired or could not be verified. Please try again."
	loginCredentialFailure = "The username or password was not accepted."
	passwordFormFailure    = "This password form expired or could not be verified. Please try again."
	passwordMatchFailure   = "The new passwords did not match. Please enter them again."
	passwordChangeFailure  = "The password could not be changed. Check the temporary password and choose a different password of at least 12 characters."
)

func (s *Server) landing(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.PrincipalFromContext(r.Context()); ok {
		http.Redirect(w, r, "/app/", http.StatusSeeOther)
		return
	}
	view := site.LandingView{Head: s.head("Gamertan Observatory", "A self-hosted observability platform in development for carefully operated Linux systems.", "/")}
	s.renderHTML(w, r, http.StatusOK, site.Landing(view))
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if principal, ok := auth.PrincipalFromContext(r.Context()); ok {
		if principal.User.PasswordChangeRequired {
			http.Redirect(w, r, "/account/password/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/app/", http.StatusSeeOther)
		return
	}
	s.renderLogin(w, r, http.StatusOK, "")
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	values, err := readFormFields(w, r, 16<<10, []string{"identifier", "password"}, []string{"csrf_token"})
	csrfOK := err == nil && validLoginCSRF(r, values.Get("csrf_token"))
	if !tokenBoundFormRequest(r, s.options.PublicOrigin, csrfOK) {
		s.renderLogin(w, r, http.StatusForbidden, loginFormFailure)
		return
	}
	if err != nil {
		s.renderLogin(w, r, http.StatusBadRequest, loginFormFailure)
		return
	}
	token, principal, err := s.identity.Auth.Authenticate(r.Context(), values.Get("identifier"), values.Get("password"), s.options.SessionLifetime)
	if err != nil {
		s.renderLogin(w, r, http.StatusUnauthorized, loginCredentialFailure)
		return
	}
	if err = authhttp.SetSession(w, s.cookie, token, s.now()); err != nil {
		_ = s.identity.Auth.RevokeSession(r.Context(), token)
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	if _, cookieErr := r.Cookie(loginCSRFCookieName); cookieErr == nil {
		clearLoginCSRF(w)
	}
	location := "/app/"
	if principal.User.PasswordChangeRequired {
		location = "/account/password/"
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

// tokenBoundFormRequest makes the purpose-bound form token the primary CSRF
// proof. Browser origin metadata is defense in depth: an explicit cross-site
// or contradictory origin still fails closed, while absent or opaque metadata
// does not break an otherwise valid ordinary HTML form submission.
func tokenBoundFormRequest(r *http.Request, publicOrigin string, validToken bool) bool {
	if !validToken {
		return false
	}
	fetchSite := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	if fetchSite != "" && fetchSite != "same-origin" && fetchSite != "none" {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" || origin == "null" {
		return true
	}
	return websec.SameOrigin(r, publicOrigin)
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, message string) {
	csrf, err := s.issueLoginCSRF(w)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "login unavailable")
		return
	}
	view := site.LoginView{Head: s.head("Sign in — Gamertan Observatory", "Sign in to the local Gamertan Observatory workshop.", "/login/"), CSRFToken: csrf, ErrorMessage: message}
	s.renderHTML(w, r, status, site.Login(view))
}

func (s *Server) issueLoginCSRF(w http.ResponseWriter) (string, error) {
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return "", errors.New("generate login CSRF token")
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookieName, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: s.now().Add(10 * time.Minute), MaxAge: 600})
	return token, nil
}

func validLoginCSRF(r *http.Request, candidate string) bool {
	cookie, err := r.Cookie(loginCSRFCookieName)
	if err != nil {
		return false
	}
	want, wantErr := base64.RawURLEncoding.DecodeString(cookie.Value)
	got, gotErr := base64.RawURLEncoding.DecodeString(candidate)
	return wantErr == nil && gotErr == nil && len(want) == 32 && len(got) == len(want) && subtle.ConstantTimeCompare(want, got) == 1
}

func clearLoginCSRF(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func (s *Server) passwordPage(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login/", http.StatusSeeOther)
		return
	}
	if !principal.User.PasswordChangeRequired {
		http.Redirect(w, r, "/app/", http.StatusSeeOther)
		return
	}
	s.renderPassword(w, r, http.StatusOK, "")
}

func (s *Server) passwordForm(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	token, tokenOK := authhttp.SessionToken(r, s.cookie)
	values, err := readForm(w, r, 8<<10, "csrf_token", "current_password", "new_password", "confirm_password")
	csrfOK := err == nil && tokenOK && authhttp.VerifyCSRF(token, "account:password:change", values.Get("csrf_token"))
	if !tokenBoundFormRequest(r, s.options.PublicOrigin, csrfOK) {
		if ok && tokenOK && principal.User.PasswordChangeRequired {
			s.renderPassword(w, r, http.StatusForbidden, passwordFormFailure)
		} else {
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
		}
		return
	}
	if !ok || !tokenOK || !principal.User.PasswordChangeRequired {
		writeProblem(w, http.StatusForbidden, "password change authorization required")
		return
	}
	if err != nil || !csrfOK {
		s.renderPassword(w, r, http.StatusBadRequest, passwordFormFailure)
		return
	}
	if values.Get("new_password") != values.Get("confirm_password") {
		s.renderPassword(w, r, http.StatusUnprocessableEntity, passwordMatchFailure)
		return
	}
	if err = s.identity.Auth.ChangePassword(r.Context(), principal.User.ID, values.Get("current_password"), values.Get("new_password")); err != nil {
		s.renderPassword(w, r, http.StatusUnprocessableEntity, passwordChangeFailure)
		return
	}
	if err = authhttp.ClearSession(w, s.cookie); err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	http.Redirect(w, r, "/login/?password=changed", http.StatusSeeOther)
}

func (s *Server) renderPassword(w http.ResponseWriter, r *http.Request, status int, message string) {
	token, ok := authhttp.SessionToken(r, s.cookie)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "authentication required")
		return
	}
	csrf, err := authhttp.CSRFToken(token, "account:password:change")
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	view := site.PasswordView{Head: s.head("Choose your password — Gamertan Observatory", "Replace the one-time Observatory credential before continuing.", "/account/password/"), CSRFToken: csrf, ErrorMessage: message}
	s.renderHTML(w, r, status, site.Password(view))
}

func (s *Server) logoutForm(w http.ResponseWriter, r *http.Request) {
	values, err := readForm(w, r, 4<<10, "csrf_token")
	token, ok := authhttp.SessionToken(r, s.cookie)
	csrfOK := err == nil && ok && authhttp.VerifyCSRF(token, "session:delete", values.Get("csrf_token"))
	if !tokenBoundFormRequest(r, s.options.PublicOrigin, csrfOK) {
		writeProblem(w, http.StatusForbidden, "valid sign-out form required")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid sign-out request")
		return
	}
	if !csrfOK {
		writeProblem(w, http.StatusForbidden, "valid session CSRF token required")
		return
	}
	if err = s.identity.Auth.RevokeSession(r.Context(), token); err != nil && !errors.Is(err, auth.ErrSessionNotFound) {
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	if err = authhttp.ClearSession(w, s.cookie); err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	http.Redirect(w, r, "/login/", http.StatusSeeOther)
}

func (s *Server) app(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login/", http.StatusSeeOther)
		return
	}
	organizations, err := s.identity.OrganizationsForUser(r.Context(), principal.User.ID)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "organization list unavailable")
		return
	}
	if len(organizations) == 0 {
		writeProblem(w, http.StatusForbidden, "organization access required")
		return
	}
	queryValues := r.URL.Query()
	requested := queryValues.Get("organization")
	if len(queryValues) > 0 {
		selectedValues, exists := queryValues["organization"]
		if !exists || len(queryValues) != 1 || len(selectedValues) != 1 || selectedValues[0] == "" {
			writeProblem(w, http.StatusBadRequest, "invalid organization selection")
			return
		}
	}
	selected := organizations[0]
	if requested != "" {
		found := false
		for _, organization := range organizations {
			if organization.ID == requested {
				selected, found = organization, true
				break
			}
		}
		if !found {
			writeProblem(w, http.StatusForbidden, "organization access denied")
			return
		}
	}
	scope := access.Scope{OrganizationID: selected.ID}
	decision, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionDashboardsRead)
	if err != nil || !decision.Allowed {
		writeProblem(w, http.StatusForbidden, "dashboard access denied")
		return
	}
	token, ok := authhttp.SessionToken(r, s.cookie)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "authentication required")
		return
	}
	csrf, err := authhttp.CSRFToken(token, "session:delete")
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	view := site.AppView{
		Head:        s.head("Overview — Gamertan Observatory", "Recent authorized telemetry and saved Observatory work.", "/app/"),
		DisplayName: principal.User.DisplayName, CSRFToken: csrf,
		EventsURL:    "/app/events?organization=" + url.QueryEscape(selected.ID),
		RefreshedAt:  s.now().Format("2006-01-02 15:04:05 UTC"),
		Organization: site.OrganizationOption{ID: selected.ID, Name: selected.Name, Selected: true},
		IncidentsURL: "/app/incidents/?organization=" + url.QueryEscape(selected.ID),
	}
	projectionStatus, projectionErr := s.store.OrganizationProjectionStatus(r.Context(), selected.ID, s.now())
	if projectionErr == nil && projectionStatus.PendingSegments > 0 {
		view.PendingBatches = projectionStatus.PendingSegments
		view.ProjectionLag = formatProjectionLag(projectionStatus.OldestPendingLag)
	}
	incidentDecision, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionIncidentsRead)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "authorization unavailable")
		return
	}
	if incidentDecision.Allowed {
		incidents, incidentErr := s.store.Incidents(r.Context(), selected.ID, false, 100)
		if incidentErr != nil {
			writeProblem(w, http.StatusServiceUnavailable, "incidents unavailable")
			return
		}
		view.OpenIncidents = len(incidents)
	}
	manage, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionDashboardsManage)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "authorization unavailable")
		return
	}
	view.CanManage = manage.Allowed
	if view.CanManage {
		view.ManageCSRF, err = authhttp.CSRFToken(token, "dashboards:manage")
		if err != nil {
			writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
			return
		}
	}
	for _, organization := range organizations {
		view.Organizations = append(view.Organizations, site.OrganizationOption{ID: organization.ID, Name: organization.Name, Selected: organization.ID == selected.ID})
	}
	view.Signals = s.overviewSignals(r, selected.ID)
	saved, err := s.store.SavedQueries(r.Context(), selected.ID)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "saved queries unavailable")
		return
	}
	for _, item := range saved {
		view.SavedQueries = append(view.SavedQueries, site.SavedQuerySummary{ID: item.ID, Name: item.Name, Description: item.Description, Query: item.Query})
	}
	dashboards, err := s.store.Dashboards(r.Context(), selected.ID)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "dashboards unavailable")
		return
	}
	for _, item := range dashboards {
		view.Dashboards = append(view.Dashboards, site.DashboardSummary{Slug: item.Slug, Name: item.Name, Description: item.Description, PanelCount: len(item.Panels)})
	}
	s.renderHTML(w, r, http.StatusOK, site.App(view))
}

func formatProjectionLag(lag time.Duration) string {
	if lag < time.Second {
		return "less than one second"
	}
	return lag.Round(time.Second).String()
}

func (s *Server) overviewSignals(r *http.Request, organizationID string) []site.SignalView {
	definitions := []struct {
		signal      model.Signal
		id, name    string
		description string
	}{
		{model.SignalLogs, "logs", "logs", "Recent structured events accepted for this organization."},
		{model.SignalMetrics, "metrics", "metrics", "Recent numeric observations with a table alternative."},
		{model.SignalTraces, "traces", "traces", "Recent spans and their correlation identities."},
		{model.SignalDeployments, "deployments", "deployments", "Recent bounded deployment evidence."},
	}
	views := make([]site.SignalView, 0, len(definitions))
	for _, definition := range definitions {
		text := string(definition.signal) + " | window 1h | limit 20"
		ast, err := query.Parse(text, s.options.MaxQueryRows)
		var result query.Result
		if err == nil {
			result, err = s.store.Query(r.Context(), ast, query.Scope{OrganizationID: organizationID}, s.options.QueryBudget, s.now())
		}
		table := site.TableView{Caption: "Recent " + definition.name, Columns: []site.TableColumn{{Label: "Status"}}, Empty: "No observations are available in the last hour."}
		if err != nil {
			table.Empty = "This bounded query is temporarily unavailable."
		} else {
			table = resultTable("Recent "+definition.name, result)
		}
		views = append(views, site.SignalView{ID: definition.id, Name: definition.name, Description: definition.description, Query: text, Table: table})
	}
	return views
}

func resultTable(caption string, result query.Result) site.TableView {
	table := site.TableView{Caption: caption, Empty: "No observations are available in the last hour."}
	for _, column := range result.Columns {
		table.Columns = append(table.Columns, site.TableColumn{Label: column.Field, Unit: column.Unit})
	}
	for _, row := range result.Rows {
		view := site.TableRow{Values: make([]string, len(result.Columns))}
		for index := range view.Values {
			view.Values[index] = "—"
			if index < len(row.Values) && row.Values[index] != nil {
				view.Values[index] = boundedCell(*row.Values[index])
			}
		}
		table.Rows = append(table.Rows, view)
	}
	return table
}

func boundedCell(value string) string {
	const maxRunes = 256
	if utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:maxRunes]) + "…"
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "authentication required")
		return
	}
	organizationID := r.URL.Query().Get("organization")
	if len(r.URL.Query()) != 1 || len(r.URL.Query()["organization"]) != 1 {
		writeProblem(w, http.StatusBadRequest, "organization is required")
		return
	}
	scope := access.Scope{OrganizationID: organizationID}
	if err := s.identity.ValidateResourceScope(r.Context(), scope); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid organization")
		return
	}
	decision, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionDashboardsRead)
	if err != nil || !decision.Allowed {
		writeProblem(w, http.StatusForbidden, "dashboard access denied")
		return
	}
	updates, remove, err := s.refresh.subscribe(organizationID)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "live refresh capacity reached")
		return
	}
	defer remove()
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeProblem(w, http.StatusNotImplemented, "streaming unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	_, _ = io.WriteString(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-updates:
			_, _ = io.WriteString(w, "event: refresh\ndata: {}\n\n")
			flusher.Flush()
		case <-heartbeat.C:
			_, _ = io.WriteString(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request) {
	body, contentType, ok := site.Asset(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (s *Server) head(title, description, path string) site.HeadView {
	return site.HeadView{Title: title, Description: description, CanonicalURL: s.options.PublicOrigin + path, Assets: site.AssetPaths()}
}

func (s *Server) renderHTML(w http.ResponseWriter, r *http.Request, status int, component sando.Component) {
	var body bytes.Buffer
	if err := sando.Render(r.Context(), &body, component); err != nil {
		writeProblem(w, http.StatusInternalServerError, "interface render unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", body.Len()))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body.Bytes())
	}
}

func readForm(w http.ResponseWriter, r *http.Request, limit int64, fields ...string) (url.Values, error) {
	return readFormFields(w, r, limit, fields, nil)
}

func readFormFields(w http.ResponseWriter, r *http.Request, limit int64, required, optional []string) (url.Values, error) {
	mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || len(parameters) > 1 || len(parameters) == 1 && !strings.EqualFold(parameters["charset"], "utf-8") {
		return nil, errors.New("URL-encoded form required")
	}
	body := http.MaxBytesReader(w, r.Body, limit)
	defer body.Close()
	encoded, err := io.ReadAll(body)
	if err != nil || !utf8.Valid(encoded) {
		return nil, errors.New("invalid form body")
	}
	values, err := url.ParseQuery(string(encoded))
	if err != nil || len(values) != len(required)+len(optional) {
		return nil, errors.New("invalid form fields")
	}
	for _, field := range required {
		if len(values[field]) != 1 || values.Get(field) == "" {
			return nil, errors.New("invalid form field")
		}
	}
	for _, field := range optional {
		if len(values[field]) != 1 {
			return nil, errors.New("invalid form field")
		}
	}
	return values, nil
}
