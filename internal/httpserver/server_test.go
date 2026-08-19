// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/nativeprotocol"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
	"gamertan.com/observatory/internal/storage"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"
)

func TestIngestionConcurrencyIsBoundedAndReusable(t *testing.T) {
	server, store, identities, _ := newUITestServer(t)
	defer store.Close()
	defer identities.Close()
	server.ingestSlots = make(chan struct{}, 1)

	first := httptest.NewRecorder()
	leave, ok := server.enterIngest(first)
	if !ok || leave == nil {
		t.Fatal("first ingestion slot was unavailable")
	}
	second := httptest.NewRecorder()
	if secondLeave, admitted := server.enterIngest(second); admitted || secondLeave != nil || second.Code != http.StatusServiceUnavailable || second.Header().Get("Retry-After") != "1" || !strings.Contains(second.Body.String(), "ingestion capacity temporarily unavailable") {
		t.Fatalf("second admission admitted=%t status=%d retry=%q body=%s", admitted, second.Code, second.Header().Get("Retry-After"), second.Body.String())
	}
	leave()
	third := httptest.NewRecorder()
	thirdLeave, admitted := server.enterIngest(third)
	if !admitted || thirdLeave == nil {
		t.Fatal("released ingestion capacity was not reusable")
	}
	thirdLeave()
}

func TestServerWebPushConfigurationIsAllOrNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identities, err := identity.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer identities.Close()
	dispatcher := &recordingPushDispatcher{}
	options := testOptions()
	options.PushDispatcher = dispatcher
	if _, err = New(store, identities, options); err == nil {
		t.Fatal("dispatcher without public key accepted")
	}
	options.PushPublicKey = "invalid"
	if _, err = New(store, identities, options); err == nil {
		t.Fatal("invalid public key accepted")
	}
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	options.PushPublicKey = base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	if _, err = New(store, identities, options); err != nil {
		t.Fatalf("valid Web Push configuration: %v", err)
	}
}

func TestIngestDoesNotExposeValuesInErrors(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	token, err := store.CreateSource(context.Background(), "source", model.Scope{OrganizationID: "org", ProjectID: "p", EnvironmentID: "prod", ServiceID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	identities, err := identity.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer identities.Close()
	server, err := New(store, identities, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	batch := model.Batch{Version: 1, SourceID: "source", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request", Body: "credential=do-not-echo"}}}
	body, _ := json.Marshal(batch)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/native", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/ingest/native", bytes.NewBufferString(`{"secret":"do-not-echo"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || bytes.Contains(rec.Body.Bytes(), []byte("do-not-echo")) {
		t.Fatalf("unsafe error response %d: %s", rec.Code, rec.Body.String())
	}
}

func TestFramedNativeIngestAcknowledgesExactReplayAndOverlappingTime(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	token, err := store.CreateSource(context.Background(), "source", model.Scope{OrganizationID: "org", ProjectID: "p", EnvironmentID: "prod", ServiceID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer identities.Close()
	now := time.Date(2026, 8, 18, 20, 0, 0, 0, time.UTC)
	server, err := New(store, identities, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	handler := server.Handler()
	send := func(batch model.Batch, body []byte, envelope model.BatchEnvelope) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "https://observatory.example/api/v2/ingest/native", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		nativeprotocol.SetHeaders(request.Header, envelope)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "first"}}}
	body, _ := json.Marshal(batch)
	envelope, _ := batch.Envelope(body)
	first := send(batch, body, envelope)
	if first.Code != http.StatusAccepted || strings.Contains(first.Body.String(), `"duplicate":true`) {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	replay := send(batch, body, envelope)
	if replay.Code != http.StatusAccepted || !strings.Contains(replay.Body.String(), `"duplicate":true`) {
		t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	tampered := append(append([]byte(nil), body...), ' ')
	bad := send(batch, tampered, envelope)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("tampered status=%d body=%s", bad.Code, bad.Body.String())
	}
	batch.Sequence = 2
	batch.ObservedAt = now.Add(time.Second)
	// The second batch intentionally overlaps the first batch's observed time.
	body, _ = json.Marshal(batch)
	envelope, _ = batch.Envelope(body)
	overlap := send(batch, body, envelope)
	if overlap.Code != http.StatusAccepted {
		t.Fatalf("overlap status=%d body=%s", overlap.Code, overlap.Body.String())
	}
}

func TestOTLPHTTPIngestionIsAuthenticatedBoundedAndCompressed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	scope := model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}
	token, err := store.CreateSource(context.Background(), "otlp-source", scope)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer identities.Close()
	now := time.Date(2026, 8, 17, 3, 0, 0, 0, time.UTC)
	server, err := New(store, identities, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	handler := server.Handler()
	payload, err := proto.Marshal(&logspb.LogsData{ResourceLogs: []*logspb.ResourceLogs{{ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
		TimeUnixNano: uint64(now.UnixNano()), EventName: "http.request", Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "accepted"}},
	}}}}}}})
	if err != nil {
		t.Fatal(err)
	}

	send := func(body []byte, encoding string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "https://observatory.example/v1/logs", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/x-protobuf")
		if encoding != "" {
			request.Header.Set("Content-Encoding", encoding)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	plain := send(payload, "")
	if plain.Code != http.StatusOK || plain.Header().Get("Content-Type") != "application/x-protobuf" || plain.Header().Get("Content-Length") != "0" || plain.Body.Len() != 0 {
		t.Fatalf("plain status=%d headers=%v body=%q", plain.Code, plain.Header(), plain.Body.String())
	}
	var compressed bytes.Buffer
	zipper := gzip.NewWriter(&compressed)
	if _, err = zipper.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = zipper.Close(); err != nil {
		t.Fatal(err)
	}
	if response := send(compressed.Bytes(), "gzip"); response.Code != http.StatusOK {
		t.Fatalf("gzip status=%d body=%s", response.Code, response.Body.String())
	}
	if err = store.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if bytes, err := store.EstimateOrganizationBytes(scope.OrganizationID); err != nil || bytes == 0 {
		t.Fatalf("projection bytes=%d err=%v", bytes, err)
	}

	unauthorized := httptest.NewRequest(http.MethodPost, "https://observatory.example/v1/logs", bytes.NewReader(payload))
	unauthorized.Header.Set("Content-Type", "application/x-protobuf")
	unauthorizedResult := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResult, unauthorized)
	if unauthorizedResult.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorizedResult.Code)
	}
	wrongMedia := httptest.NewRequest(http.MethodPost, "https://observatory.example/v1/logs", bytes.NewReader(payload))
	wrongMedia.Header.Set("Authorization", "Bearer "+token)
	wrongMedia.Header.Set("Content-Type", "application/json")
	wrongMediaResult := httptest.NewRecorder()
	handler.ServeHTTP(wrongMediaResult, wrongMedia)
	if wrongMediaResult.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("media status=%d", wrongMediaResult.Code)
	}

	compressed.Reset()
	zipper = gzip.NewWriter(&compressed)
	if _, err = zipper.Write(bytes.Repeat([]byte{'x'}, int(testOptions().MaxBodyBytes)+1)); err != nil {
		t.Fatal(err)
	}
	if err = zipper.Close(); err != nil {
		t.Fatal(err)
	}
	tooLarge := send(compressed.Bytes(), "gzip")
	if tooLarge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status=%d body=%s", tooLarge.Code, tooLarge.Body.String())
	}
}

func TestSessionAndScopedExplain(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identities, err := identity.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer identities.Close()
	bootstrap, err := identities.Bootstrap(context.Background(), identity.BootstrapInput{Username: "operator", Email: "operator@example.test", DisplayName: "Operator", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(store, identities, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	login := httptest.NewRequest(http.MethodPost, "https://observatory.example/api/v1/session", strings.NewReader(`{"identifier":"operator","password":"correct horse battery staple"}`))
	login.Header.Set("Origin", "https://observatory.example")
	loginResult := httptest.NewRecorder()
	handler.ServeHTTP(loginResult, login)
	if loginResult.Code != http.StatusOK || strings.Contains(loginResult.Body.String(), "correct horse") {
		t.Fatalf("login status=%d body=%s", loginResult.Code, loginResult.Body.String())
	}
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err = json.Unmarshal(loginResult.Body.Bytes(), &session); err != nil || session.CSRFToken == "" {
		t.Fatalf("session=%+v err=%v", session, err)
	}
	cookies := loginResult.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-observatory_session" || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("cookies=%+v", cookies)
	}

	explainBody := fmt.Sprintf(`{"organization_id":%q,"query":"logs | where status >= 500 | limit 10"}`, bootstrap.Organization.ID)
	explain := httptest.NewRequest(http.MethodPost, "https://observatory.example/api/v1/query/explain", strings.NewReader(explainBody))
	explain.Header.Set("Origin", "https://observatory.example")
	explain.AddCookie(cookies[0])
	explainResult := httptest.NewRecorder()
	handler.ServeHTTP(explainResult, explain)
	if explainResult.Code != http.StatusOK || !strings.Contains(explainResult.Body.String(), `"projected_sources"`) {
		t.Fatalf("explain status=%d body=%s", explainResult.Code, explainResult.Body.String())
	}
	now := time.Now().UTC()
	sourceToken, err := store.CreateSource(context.Background(), "query-source", model.Scope{OrganizationID: bootstrap.Organization.ID, ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "query-source", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "application.http.request", Attributes: map[string]string{"http.status_code": "503", "http.route": "/failed", "workshop.queue_depth": "12"}}}}
	if _, err = store.Ingest(context.Background(), sourceToken, batch, now); err != nil {
		t.Fatal(err)
	}
	if err = store.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	execute := httptest.NewRequest(http.MethodPost, "https://observatory.example/api/v1/query", strings.NewReader(explainBody))
	execute.Header.Set("Origin", "https://observatory.example")
	execute.AddCookie(cookies[0])
	executeResult := httptest.NewRecorder()
	handler.ServeHTTP(executeResult, execute)
	if executeResult.Code != http.StatusOK || !strings.Contains(executeResult.Body.String(), `"http.status_code"`) || !strings.Contains(executeResult.Body.String(), `"503"`) {
		t.Fatalf("execute status=%d body=%s", executeResult.Code, executeResult.Body.String())
	}
	reviewed := schema.Descriptor{Version: schema.DescriptorVersion, Signal: model.SignalLogs, Field: "workshop.queue_depth", Type: schema.TypeInteger, Meaning: "Reviewed queue depth for one application service.", Sensitivity: schema.SensitivityInternal, Cardinality: schema.CardinalityLow, Index: schema.IndexRange, Retention: schema.RetentionRaw, ProjectionVersion: 1}
	if _, err = store.ActivateDescriptor(context.Background(), bootstrap.Organization.ID, reviewed, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	customBody := fmt.Sprintf(`{"organization_id":%q,"query":"logs | where workshop.queue_depth >= 10 | limit 10"}`, bootstrap.Organization.ID)
	for _, path := range []string{"/api/v1/query/explain", "/api/v1/query"} {
		request := httptest.NewRequest(http.MethodPost, "https://observatory.example"+path, strings.NewReader(customBody))
		request.Header.Set("Origin", "https://observatory.example")
		request.AddCookie(cookies[0])
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"workshop.queue_depth"`) || !strings.Contains(response.Body.String(), `"indexed":true`) {
			t.Fatalf("path=%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}

	for _, path := range []string{"/api/v1/query/explain", "/api/v1/query"} {
		denied := httptest.NewRequest(http.MethodPost, "https://observatory.example"+path, strings.NewReader(`{"organization_id":"unowned1","query":"logs | limit 10"}`))
		denied.Header.Set("Origin", "https://observatory.example")
		denied.AddCookie(cookies[0])
		deniedResult := httptest.NewRecorder()
		handler.ServeHTTP(deniedResult, denied)
		if deniedResult.Code != http.StatusForbidden {
			t.Fatalf("path=%s cross-organization status=%d body=%s", path, deniedResult.Code, deniedResult.Body.String())
		}
	}

	logout := httptest.NewRequest(http.MethodDelete, "https://observatory.example/api/v1/session", nil)
	logout.Header.Set("Origin", "https://observatory.example")
	logout.Header.Set("X-CSRF-Token", session.CSRFToken)
	logout.AddCookie(cookies[0])
	logoutResult := httptest.NewRecorder()
	handler.ServeHTTP(logoutResult, logout)
	if logoutResult.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d body=%s", logoutResult.Code, logoutResult.Body.String())
	}
}

func TestCrossOriginLoginIsRejected(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identities, err := identity.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer identities.Close()
	server, err := New(store, identities, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://observatory.example/api/v1/session", strings.NewReader(`{"identifier":"operator","password":"secret"}`))
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAgentEnrollmentIsSingleUseAndCredentialCanSelfRevoke(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identities, err := identity.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer identities.Close()
	now := time.Date(2026, 8, 17, 2, 0, 0, 0, time.UTC)
	enrollmentToken, _, err := store.CreateEnrollment(context.Background(), "source-a", model.Scope{OrganizationID: "organization-a", ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"}, "operator-a", 15*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(store, identities, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now.Add(time.Minute) }
	enroll := httptest.NewRequest(http.MethodPost, "https://observatory.example/api/v1/agent/enroll", nil)
	enroll.Header.Set("Authorization", "Bearer "+enrollmentToken)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, enroll)
	if response.Code != http.StatusCreated || strings.Contains(response.Body.String(), enrollmentToken) {
		t.Fatalf("enroll status=%d body=%s", response.Code, response.Body.String())
	}
	var enrolled struct {
		SourceID   string `json:"source_id"`
		Credential string `json:"credential"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &enrolled); err != nil || enrolled.SourceID != "source-a" || enrolled.Credential == "" {
		t.Fatalf("enrolled=%+v err=%v", enrolled, err)
	}
	replay := httptest.NewRequest(http.MethodPost, "https://observatory.example/api/v1/agent/enroll", nil)
	replay.Header.Set("Authorization", "Bearer "+enrollmentToken)
	replayResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusUnauthorized {
		t.Fatalf("replay status=%d", replayResponse.Code)
	}
	revoke := httptest.NewRequest(http.MethodDelete, "https://observatory.example/api/v1/agent/source", nil)
	revoke.Header.Set("Authorization", "Bearer "+enrolled.Credential)
	revokeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(revokeResponse, revoke)
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("revoke status=%d body=%s", revokeResponse.Code, revokeResponse.Body.String())
	}
	if _, err = store.Authenticate(context.Background(), enrolled.Credential); err == nil {
		t.Fatal("revoked source credential remained active")
	}
}

func testOptions() Options {
	return Options{PublicOrigin: "https://observatory.example", MaxBodyBytes: 1 << 20, MaxQueryRows: 1000, SessionLifetime: time.Hour, QueryBudget: query.Budget{MaxDuration: 2 * time.Second, MaxRows: 1000, MaxScannedBytes: 10 << 20, MaxMemoryBytes: 8 << 20}}
}
