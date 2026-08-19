// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/nativeprotocol"
	"gamertan.com/observatory/internal/otlp"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/storage"
	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/authhttp"
	"gamertan.com/web/requestmeta"
	"gamertan.com/web/websec"
)

type Options struct {
	PublicOrigin        string
	MaxBodyBytes        int64
	MaxConcurrentIngest int
	MaxQueryRows        int
	QueryBudget         query.Budget
	SessionLifetime     time.Duration
	PushPublicKey       string
	PushDispatcher      PushDispatcher
}

type PushDispatcher interface {
	Enqueue(organizationID string) bool
}

type Server struct {
	store       *storage.Store
	identity    *identity.Services
	options     Options
	cookie      authhttp.CookieConfig
	now         func() time.Time
	refresh     *refreshHub
	requests    *requestmeta.Resolver
	ingestSlots chan struct{}
}

func New(store *storage.Store, identities *identity.Services, options Options) (*Server, error) {
	if store == nil || identities == nil || identities.Auth == nil || identities.Access == nil {
		return nil, errors.New("server storage and identity services are required")
	}
	origin, err := url.Parse(options.PublicOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" && origin.Path != "/" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("server public origin must be an absolute HTTPS origin")
	}
	options.PublicOrigin = strings.TrimSuffix(options.PublicOrigin, "/")
	if options.MaxConcurrentIngest == 0 {
		options.MaxConcurrentIngest = 8
	}
	if options.MaxBodyBytes < 1024 || options.MaxConcurrentIngest < 1 || options.MaxConcurrentIngest > 64 || options.MaxQueryRows < 1 || options.SessionLifetime < 5*time.Minute || options.SessionLifetime > 30*24*time.Hour {
		return nil, errors.New("server limits are invalid")
	}
	if options.QueryBudget.MaxRows != options.MaxQueryRows || options.QueryBudget.MaxDuration < time.Millisecond || options.QueryBudget.MaxScannedBytes < 1 || options.QueryBudget.MaxMemoryBytes < 1 {
		return nil, errors.New("server query budget is invalid")
	}
	if (options.PushPublicKey == "") != (options.PushDispatcher == nil) {
		return nil, errors.New("server Web Push key and dispatcher must be configured together")
	}
	if options.PushPublicKey != "" {
		publicKey, decodeErr := base64.RawURLEncoding.DecodeString(options.PushPublicKey)
		if decodeErr != nil || len(publicKey) != 65 {
			return nil, errors.New("server Web Push public key is invalid")
		}
		if _, decodeErr = ecdh.P256().NewPublicKey(publicKey); decodeErr != nil {
			return nil, errors.New("server Web Push public key is invalid")
		}
	}
	cookie := authhttp.CookieConfig{Name: "__Host-observatory_session", Lifetime: options.SessionLifetime, SameSite: http.SameSiteStrictMode}
	if err = cookie.Validate(); err != nil {
		return nil, err
	}
	requests, err := requestmeta.New(requestmeta.Config{})
	if err != nil {
		return nil, fmt.Errorf("server request metadata: %w", err)
	}
	return &Server{store: store, identity: identities, options: options, cookie: cookie, now: func() time.Time { return time.Now().UTC() }, refresh: newRefreshHub(256, 8), requests: requests, ingestSlots: make(chan struct{}, options.MaxConcurrentIngest)}, nil
}

func (s *Server) enterIngest(w http.ResponseWriter) (func(), bool) {
	select {
	case s.ingestSlots <- struct{}{}:
		return func() { <-s.ingestSlots }, true
	default:
		w.Header().Set("Retry-After", "1")
		writeProblem(w, http.StatusServiceUnavailable, "ingestion capacity temporarily unavailable")
		return nil, false
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", textOK("ok\n"))
	mux.HandleFunc("HEAD /healthz", textOK("ok\n"))
	mux.HandleFunc("GET /readyz", textOK("ready\n"))
	mux.HandleFunc("HEAD /readyz", textOK("ready\n"))
	mux.HandleFunc("GET /{$}", s.landing)
	mux.HandleFunc("HEAD /{$}", s.landing)
	mux.HandleFunc("GET /manifest.webmanifest", s.webManifest)
	mux.HandleFunc("HEAD /manifest.webmanifest", s.webManifest)
	mux.HandleFunc("GET /service-worker.js", s.serviceWorker)
	mux.HandleFunc("HEAD /service-worker.js", s.serviceWorker)
	mux.HandleFunc("GET /offline/{$}", s.offlineShell)
	mux.HandleFunc("HEAD /offline/{$}", s.offlineShell)
	mux.HandleFunc("GET /login/{$}", s.loginPage)
	mux.HandleFunc("HEAD /login/{$}", s.loginPage)
	mux.HandleFunc("POST /login/{$}", s.loginForm)
	mux.HandleFunc("POST /logout/{$}", s.logoutForm)
	mux.HandleFunc("GET /account/password/{$}", s.passwordPage)
	mux.HandleFunc("HEAD /account/password/{$}", s.passwordPage)
	mux.HandleFunc("POST /account/password/{$}", s.passwordForm)
	mux.HandleFunc("GET /app/{$}", s.app)
	mux.HandleFunc("HEAD /app/{$}", s.app)
	mux.HandleFunc("GET /app/explore/{$}", s.explorePage)
	mux.HandleFunc("HEAD /app/explore/{$}", s.explorePage)
	mux.HandleFunc("POST /app/explore/{$}", s.exploreForm)
	mux.HandleFunc("GET /app/events", s.events)
	mux.HandleFunc("POST /app/queries/{$}", s.createSavedQuery)
	mux.HandleFunc("POST /app/queries/builder/{$}", s.createBuiltQuery)
	mux.HandleFunc("POST /app/dashboards/{$}", s.createDashboard)
	mux.HandleFunc("GET /app/dashboards/{slug}/{$}", s.dashboard)
	mux.HandleFunc("HEAD /app/dashboards/{slug}/{$}", s.dashboard)
	mux.HandleFunc("POST /app/dashboards/{slug}/{$}", s.updateDashboard)
	mux.HandleFunc("POST /app/dashboards/{slug}/panels/{$}", s.addDashboardPanel)
	mux.HandleFunc("POST /app/dashboards/{slug}/panels/{panel}/{$}", s.updateDashboardPanel)
	mux.HandleFunc("POST /app/dashboards/{slug}/panels/{panel}/remove/{$}", s.removeDashboardPanel)
	mux.HandleFunc("GET /app/dashboards/{slug}/export.json", s.exportDashboard)
	mux.HandleFunc("HEAD /app/dashboards/{slug}/export.json", s.exportDashboard)
	mux.HandleFunc("GET /app/incidents/{$}", s.incidentInbox)
	mux.HandleFunc("HEAD /app/incidents/{$}", s.incidentInbox)
	mux.HandleFunc("GET /app/incidents/offline/{$}", s.offlineIncidentInbox)
	mux.HandleFunc("HEAD /app/incidents/offline/{$}", s.offlineIncidentInbox)
	mux.HandleFunc("POST /app/alert-rules/{$}", s.createAlertRule)
	mux.HandleFunc("POST /app/incidents/{id}/{$}", s.transitionIncident)
	mux.HandleFunc("GET /assets/", s.serveAsset)
	mux.HandleFunc("HEAD /assets/", s.serveAsset)
	mux.HandleFunc("POST /api/v1/ingest/native", s.ingest)
	mux.HandleFunc("POST /api/v2/ingest/native", s.ingestFramed)
	mux.HandleFunc("POST /v1/logs", s.ingestOTLP(otlp.Logs))
	mux.HandleFunc("POST /v1/metrics", s.ingestOTLP(otlp.Metrics))
	mux.HandleFunc("POST /v1/traces", s.ingestOTLP(otlp.Traces))
	mux.HandleFunc("POST /api/v1/agent/enroll", s.enrollAgent)
	mux.HandleFunc("POST /api/v1/agent/alert-transition", s.recordAgentAlertTransition)
	mux.HandleFunc("DELETE /api/v1/agent/source", s.revokeAgentSource)
	mux.HandleFunc("POST /api/v1/session", s.login)
	mux.HandleFunc("DELETE /api/v1/session", s.logout)
	mux.HandleFunc("POST /api/v1/account/password", s.changePassword)
	mux.HandleFunc("POST /api/v1/query/parse", s.parseQuery)
	mux.HandleFunc("POST /api/v1/query/explain", s.explainQuery)
	mux.HandleFunc("POST /api/v1/query", s.executeQuery)
	mux.HandleFunc("POST /api/v1/push/subscription", s.savePushSubscription)
	mux.HandleFunc("POST /api/v1/push/subscription/status", s.pushSubscriptionStatus)
	mux.HandleFunc("DELETE /api/v1/push/subscription", s.deletePushSubscription)
	return securityHeaders(s.requests.Middleware(authhttp.Optional(s.identity.Auth, s.cookie)(s.requirePasswordChange(mux))))
}

func (s *Server) recordAgentAlertTransition(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r.Header.Get("Authorization"))
	if !ok || !strings.HasPrefix(token, "obs1.") {
		writeProblem(w, http.StatusUnauthorized, "source authentication required")
		return
	}
	// Authenticate before decoding. RecordSourceAlertTransition authenticates
	// again while binding scope and raw evidence to the credential.
	if _, err := s.store.Authenticate(r.Context(), token); err != nil {
		writeProblem(w, http.StatusUnauthorized, "source authentication required")
		return
	}
	leave, ok := s.enterIngest(w)
	if !ok {
		return
	}
	defer leave()
	body := http.MaxBytesReader(w, r.Body, 64<<10)
	defer body.Close()
	var transition model.AlertTransition
	if err := decodeOne(body, &transition); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid source alert transition")
		return
	}
	ack, err := s.store.RecordSourceAlertTransition(r.Context(), token, transition, s.now())
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "source alert transition rejected")
		return
	}
	writeJSON(w, http.StatusAccepted, ack)
}

func (s *Server) requirePasswordChange(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok || !principal.User.PasswordChangeRequired || passwordChangeAllowed(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			http.Redirect(w, r, "/account/password/", http.StatusSeeOther)
			return
		}
		writeProblem(w, http.StatusForbidden, "password change required")
	})
}

func passwordChangeAllowed(r *http.Request) bool {
	switch r.URL.Path {
	case "/healthz", "/readyz", "/manifest.webmanifest", "/service-worker.js", "/offline/", "/account/password/", "/logout/", "/api/v1/account/password", "/api/v1/session":
		return true
	}
	return strings.HasPrefix(r.URL.Path, "/assets/")
}

func (s *Server) revokeAgentSource(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r.Header.Get("Authorization"))
	if !ok || !strings.HasPrefix(token, "obs1.") {
		writeProblem(w, http.StatusUnauthorized, "source authentication required")
		return
	}
	source, err := s.store.Authenticate(r.Context(), token)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "source authentication required")
		return
	}
	if err = s.store.RevokeSource(r.Context(), source.ID); err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "source revocation unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) enrollAgent(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r.Header.Get("Authorization"))
	if !ok || !strings.HasPrefix(token, "obse1.") {
		writeProblem(w, http.StatusUnauthorized, "valid enrollment required")
		return
	}
	body := http.MaxBytesReader(w, r.Body, 1)
	defer body.Close()
	payload, bodyErr := io.ReadAll(body)
	if bodyErr != nil || len(payload) != 0 {
		writeProblem(w, http.StatusBadRequest, "enrollment request body must be empty")
		return
	}
	enrollment, credential, err := s.store.RedeemEnrollment(r.Context(), token, s.now())
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "valid enrollment required")
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		SourceID   string `json:"source_id"`
		Credential string `json:"credential"`
	}{enrollment.SourceID, credential})
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "source authentication required")
		return
	}
	source, err := s.store.Authenticate(r.Context(), token)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "source authentication required")
		return
	}
	leave, ok := s.enterIngest(w)
	if !ok {
		return
	}
	defer leave()
	body := http.MaxBytesReader(w, r.Body, s.options.MaxBodyBytes)
	defer body.Close()
	var batch model.Batch
	if err := decodeOne(body, &batch); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid native batch")
		return
	}
	ack, err := s.store.Ingest(r.Context(), token, batch, s.now())
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "batch rejected")
		return
	}
	s.refresh.publish(source.Scope.OrganizationID)
	writeJSON(w, http.StatusAccepted, ack)
}

func (s *Server) ingestFramed(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "source authentication required")
		return
	}
	source, err := s.store.Authenticate(r.Context(), token)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "source authentication required")
		return
	}
	leave, ok := s.enterIngest(w)
	if !ok {
		return
	}
	defer leave()
	mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		writeProblem(w, http.StatusUnsupportedMediaType, "native JSON content type required")
		return
	}
	envelope, err := nativeprotocol.ParseHeaders(r.Header, s.options.MaxBodyBytes)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid native batch envelope")
		return
	}
	body := http.MaxBytesReader(w, r.Body, s.options.MaxBodyBytes)
	defer body.Close()
	if _, exact, checkErr := s.store.CheckNativeReplay(r.Context(), token, envelope); checkErr != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "batch rejected")
		return
	} else if exact {
		if err = verifyNativeReplayBody(body, envelope); err != nil {
			writeProblem(w, http.StatusBadRequest, "native batch body does not match envelope")
			return
		}
		ack, confirmErr := s.store.ConfirmNativeReplay(r.Context(), token, envelope)
		if confirmErr != nil {
			writeProblem(w, http.StatusUnprocessableEntity, "batch rejected")
			return
		}
		writeJSON(w, http.StatusAccepted, ack)
		return
	}
	encoded, err := io.ReadAll(body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid native batch")
		return
	}
	var batch model.Batch
	if err = decodeOne(bytes.NewReader(encoded), &batch); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid native batch")
		return
	}
	ack, err := s.store.IngestNative(r.Context(), token, batch, envelope, encoded, s.now())
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "batch rejected")
		return
	}
	if !ack.Duplicate {
		s.refresh.publish(source.Scope.OrganizationID)
	}
	writeJSON(w, http.StatusAccepted, ack)
}

func verifyNativeReplayBody(body io.Reader, envelope model.BatchEnvelope) error {
	digest := sha256.New()
	written, err := io.Copy(digest, body)
	if err != nil || written != envelope.EncodedBytes || hex.EncodeToString(digest.Sum(nil)) != envelope.WireDigest {
		return errors.New("native batch body does not match envelope")
	}
	return nil
}

func (s *Server) ingestOTLP(signal otlp.Signal) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r.Header.Get("Authorization"))
		if !ok || !strings.HasPrefix(token, "obs1.") {
			writeProblem(w, http.StatusUnauthorized, "source authentication required")
			return
		}
		// Authenticate before parsing attacker-controlled protobuf. IngestAuto
		// authenticates again while assigning the next sequence under its source
		// lock so revocation cannot race into an acknowledged write.
		source, err := s.store.Authenticate(r.Context(), token)
		if err != nil {
			writeProblem(w, http.StatusUnauthorized, "source authentication required")
			return
		}
		leave, ok := s.enterIngest(w)
		if !ok {
			return
		}
		defer leave()
		mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-protobuf" || len(parameters) != 0 {
			writeProblem(w, http.StatusUnsupportedMediaType, "OTLP protobuf content type required")
			return
		}
		body, status, err := readOTLPBody(w, r, s.options.MaxBodyBytes)
		if err != nil {
			title := "invalid OTLP request body"
			if status == http.StatusRequestEntityTooLarge {
				title = "OTLP request body exceeds limit"
			} else if status == http.StatusUnsupportedMediaType {
				title = "unsupported OTLP content encoding"
			}
			writeProblem(w, status, title)
			return
		}
		now := s.now()
		records, err := otlp.Decode(signal, body, now)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid OTLP protobuf payload")
			return
		}
		if _, err = s.store.IngestAuto(r.Context(), token, signal.StreamID(), signal.ModelSignal(), records, now); err != nil {
			writeProblem(w, http.StatusUnprocessableEntity, "OTLP batch rejected")
			return
		}
		s.refresh.publish(source.Scope.OrganizationID)
		response, err := otlp.SuccessResponse(signal)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "OTLP response unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(response)))
		w.WriteHeader(http.StatusOK)
		if len(response) > 0 {
			_, _ = w.Write(response)
		}
	}
}

func readOTLPBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, int, error) {
	compressed := http.MaxBytesReader(w, r.Body, limit)
	defer compressed.Close()
	encoding := strings.TrimSpace(strings.ToLower(r.Header.Get("Content-Encoding")))
	var reader io.Reader = compressed
	var zipped *gzip.Reader
	switch encoding {
	case "", "identity":
	case "gzip":
		var err error
		zipped, err = gzip.NewReader(compressed)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}
		defer zipped.Close()
		reader = io.LimitReader(zipped, limit+1)
	default:
		return nil, http.StatusUnsupportedMediaType, errors.New("unsupported content encoding")
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, http.StatusRequestEntityTooLarge, err
		}
		return nil, http.StatusBadRequest, err
	}
	if int64(len(body)) > limit {
		return nil, http.StatusRequestEntityTooLarge, errors.New("decoded body exceeds limit")
	}
	return body, http.StatusOK, nil
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !websec.SameOrigin(r, s.options.PublicOrigin) {
		writeProblem(w, http.StatusForbidden, "same-origin request required")
		return
	}
	body := http.MaxBytesReader(w, r.Body, 16<<10)
	defer body.Close()
	var input struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}
	if err := decodeOne(body, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid session request")
		return
	}
	token, principal, err := s.identity.Auth.Authenticate(r.Context(), input.Identifier, input.Password, s.options.SessionLifetime)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err = authhttp.SetSession(w, s.cookie, token, s.now()); err != nil {
		_ = s.identity.Auth.RevokeSession(r.Context(), token)
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	csrf, err := authhttp.CSRFToken(token, "session:delete")
	if err != nil {
		_ = s.identity.Auth.RevokeSession(r.Context(), token)
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	passwordCSRF := ""
	if principal.User.PasswordChangeRequired {
		passwordCSRF, err = authhttp.CSRFToken(token, "account:password:change")
		if err != nil {
			_ = s.identity.Auth.RevokeSession(r.Context(), token)
			writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
			return
		}
	}
	writeJSON(w, http.StatusOK, struct {
		UserID                 string `json:"user_id"`
		Username               string `json:"username"`
		DisplayName            string `json:"display_name"`
		CSRFToken              string `json:"csrf_token"`
		PasswordChangeCSRF     string `json:"password_change_csrf,omitempty"`
		PasswordChangeRequired bool   `json:"password_change_required"`
	}{principal.User.ID, principal.User.Username, principal.User.DisplayName, csrf, passwordCSRF, principal.User.PasswordChangeRequired})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	if !websec.SameOrigin(r, s.options.PublicOrigin) {
		writeProblem(w, http.StatusForbidden, "same-origin request required")
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	token, tokenOK := authhttp.SessionToken(r, s.cookie)
	if !ok || !tokenOK || !principal.User.PasswordChangeRequired || !authhttp.VerifyCSRF(token, "account:password:change", r.Header.Get("X-CSRF-Token")) {
		writeProblem(w, http.StatusForbidden, "password change authorization required")
		return
	}
	body := http.MaxBytesReader(w, r.Body, 8<<10)
	defer body.Close()
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeOne(body, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid password change request")
		return
	}
	if err := s.identity.Auth.ChangePassword(r.Context(), principal.User.ID, input.CurrentPassword, input.NewPassword); err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "password change rejected")
		return
	}
	if err := authhttp.ClearSession(w, s.cookie); err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !websec.SameOrigin(r, s.options.PublicOrigin) {
		writeProblem(w, http.StatusForbidden, "same-origin request required")
		return
	}
	token, ok := authhttp.SessionToken(r, s.cookie)
	if !ok || !authhttp.VerifyCSRF(token, "session:delete", r.Header.Get("X-CSRF-Token")) {
		writeProblem(w, http.StatusForbidden, "valid session CSRF token required")
		return
	}
	if err := s.identity.Auth.RevokeSession(r.Context(), token); err != nil && !errors.Is(err, auth.ErrSessionNotFound) {
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	if err := authhttp.ClearSession(w, s.cookie); err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type queryRequest struct {
	Query          string     `json:"query,omitempty"`
	AST            *query.AST `json:"ast,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	ProjectID      string     `json:"project_id,omitempty"`
	EnvironmentID  string     `json:"environment_id,omitempty"`
	ServiceID      string     `json:"service_id,omitempty"`
}

func (s *Server) parseQuery(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, 16<<10)
	defer body.Close()
	var input queryRequest
	if err := decodeOne(body, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid query request")
		return
	}
	ast, err := parseAST(input, s.options.MaxQueryRows)
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "query rejected")
		return
	}
	writeJSON(w, http.StatusOK, ast)
}

func (s *Server) explainQuery(w http.ResponseWriter, r *http.Request) {
	if !websec.SameOrigin(r, s.options.PublicOrigin) {
		writeProblem(w, http.StatusForbidden, "same-origin request required")
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "authentication required")
		return
	}
	body := http.MaxBytesReader(w, r.Body, 16<<10)
	defer body.Close()
	var input queryRequest
	if err := decodeOne(body, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid query request")
		return
	}
	ast, err := parseAST(input, s.options.MaxQueryRows)
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "query rejected")
		return
	}
	requested := access.Scope{OrganizationID: input.OrganizationID, ProjectID: input.ProjectID, EnvironmentID: input.EnvironmentID, ServiceID: input.ServiceID}
	decision, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, requested, identity.PermissionTelemetryQuery)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid resource scope")
		return
	}
	if !decision.Allowed {
		writeProblem(w, http.StatusForbidden, "resource access denied")
		return
	}
	if err := s.identity.ValidateResourceScope(r.Context(), requested); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid resource scope")
		return
	}
	sensitive, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, requested, identity.PermissionTelemetryReadSensitive)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "authorization unavailable")
		return
	}
	estimated, err := s.store.EstimateOrganizationBytes(input.OrganizationID)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "query planning unavailable")
		return
	}
	registry, _, err := s.store.ActiveDescriptors(r.Context(), input.OrganizationID)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "query planning unavailable")
		return
	}
	explain, err := query.Plan(ast, query.Scope{
		OrganizationID: input.OrganizationID, ProjectID: input.ProjectID,
		EnvironmentID: input.EnvironmentID, ServiceID: input.ServiceID,
		Sensitive: sensitive.Allowed,
	}, registry, estimated, s.options.QueryBudget)
	if errors.Is(err, query.ErrSensitivePermissionRequired) {
		writeProblem(w, http.StatusForbidden, "sensitive-field permission required")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "query plan rejected")
		return
	}
	writeJSON(w, http.StatusOK, explain)
}

func (s *Server) executeQuery(w http.ResponseWriter, r *http.Request) {
	if !websec.SameOrigin(r, s.options.PublicOrigin) {
		writeProblem(w, http.StatusForbidden, "same-origin request required")
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "authentication required")
		return
	}
	body := http.MaxBytesReader(w, r.Body, 16<<10)
	defer body.Close()
	var input queryRequest
	if err := decodeOne(body, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid query request")
		return
	}
	ast, err := parseAST(input, s.options.MaxQueryRows)
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "query rejected")
		return
	}
	requested := access.Scope{OrganizationID: input.OrganizationID, ProjectID: input.ProjectID, EnvironmentID: input.EnvironmentID, ServiceID: input.ServiceID}
	decision, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, requested, identity.PermissionTelemetryQuery)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid resource scope")
		return
	}
	if !decision.Allowed {
		writeProblem(w, http.StatusForbidden, "resource access denied")
		return
	}
	if err = s.identity.ValidateResourceScope(r.Context(), requested); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid resource scope")
		return
	}
	sensitive, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, requested, identity.PermissionTelemetryReadSensitive)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "authorization unavailable")
		return
	}
	result, err := s.store.Query(r.Context(), ast, query.Scope{
		OrganizationID: input.OrganizationID, ProjectID: input.ProjectID,
		EnvironmentID: input.EnvironmentID, ServiceID: input.ServiceID,
		Sensitive: sensitive.Allowed,
	}, s.options.QueryBudget, s.now())
	switch {
	case errors.Is(err, query.ErrSensitivePermissionRequired):
		writeProblem(w, http.StatusForbidden, "sensitive-field permission required")
		return
	case errors.Is(err, query.ErrBudgetExceeded):
		writeProblem(w, http.StatusUnprocessableEntity, "query execution budget exceeded")
		return
	case errors.Is(err, query.ErrTypeMismatch):
		writeProblem(w, http.StatusUnprocessableEntity, "query field type mismatch")
		return
	case err != nil:
		writeProblem(w, http.StatusServiceUnavailable, "query execution unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func parseAST(input queryRequest, maxRows int) (query.AST, error) {
	if (input.Query == "") == (input.AST == nil) {
		return query.AST{}, errors.New("provide exactly one query or AST")
	}
	if input.AST == nil {
		return query.Parse(input.Query, maxRows)
	}
	ast := *input.AST
	var err error
	if ast.WindowText != "" {
		ast.Window, err = time.ParseDuration(ast.WindowText)
	}
	if err == nil && ast.BucketText != "" {
		ast.Bucket, err = time.ParseDuration(ast.BucketText)
	}
	if err == nil {
		err = query.Validate(ast, maxRows)
	}
	return ast, err
}

func decodeOne(reader io.Reader, value any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON value")
	}
	return nil
}

func bearer(value string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) || strings.ContainsAny(value[len(prefix):], " \t\r\n") {
		return "", false
	}
	return value[len(prefix):], value[len(prefix):] != ""
}

func textOK(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, body)
		}
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; manifest-src 'self'; script-src 'self'; style-src 'self'; worker-src 'self'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeProblem(w http.ResponseWriter, status int, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
	}{Title: title, Status: status})
}
