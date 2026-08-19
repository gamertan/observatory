// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
	"gamertan.com/observatory/internal/site"
	"gamertan.com/observatory/internal/storage"
	"gamertan.com/web/authhttp"
)

func TestHandlerAssignsFreshBoundedRequestIDs(t *testing.T) {
	server, store, identities, _ := newUITestServer(t)
	defer store.Close()
	defer identities.Close()
	handler := server.Handler()

	var previous string
	for _, test := range []struct {
		method string
		target string
	}{
		{http.MethodGet, "https://observatory.example/healthz"},
		{http.MethodHead, "https://observatory.example/readyz"},
		{http.MethodGet, "https://observatory.example/"},
		{http.MethodGet, "https://observatory.example/not-found"},
	} {
		header := http.Header{"X-Request-ID": []string{"attacker-selected"}}
		response := perform(handler, test.method, test.target, nil, nil, header)
		requestID := response.Header().Get("X-Request-ID")
		decoded, err := hex.DecodeString(requestID)
		if err != nil || len(decoded) != 16 || requestID == "attacker-selected" || requestID == previous {
			t.Fatalf("%s %s request_id=%q decoded=%d err=%v previous=%q", test.method, test.target, requestID, len(decoded), err, previous)
		}
		previous = requestID
	}
}

func TestHTMLInterfaceAuthenticationAssetsAndOverview(t *testing.T) {
	server, store, identities, bootstrap := newUITestServer(t)
	defer store.Close()
	defer identities.Close()
	handler := server.Handler()

	landing := perform(handler, http.MethodGet, "https://observatory.example/", nil, nil)
	if landing.Code != http.StatusOK || landing.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(landing.Body.String(), "Keep the evidence close.") {
		t.Fatalf("landing status=%d body=%s", landing.Code, landing.Body.String())
	}
	csp := landing.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "style-src 'self'") || !strings.Contains(csp, "manifest-src 'self'") || !strings.Contains(csp, "worker-src 'self'") || strings.Contains(landing.Body.String(), "<style") {
		t.Fatalf("CSP=%q body=%s", csp, landing.Body.String())
	}
	if !strings.Contains(landing.Body.String(), `<link rel="manifest" href="/manifest.webmanifest">`) {
		t.Fatalf("landing omitted manifest discovery: %s", landing.Body.String())
	}
	head := perform(handler, http.MethodHead, "https://observatory.example/", nil, nil)
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != landing.Header().Get("Content-Length") {
		t.Fatalf("HEAD status=%d length=%q body=%d", head.Code, head.Header().Get("Content-Length"), head.Body.Len())
	}
	for _, path := range []string{site.AssetPaths().StylePath, site.AssetPaths().ScriptPath, site.AssetPaths().IconPath} {
		asset := perform(handler, http.MethodGet, "https://observatory.example"+path, nil, nil)
		if asset.Code != http.StatusOK || asset.Body.Len() == 0 || asset.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("asset %s status=%d cache=%q", path, asset.Code, asset.Header().Get("Cache-Control"))
		}
		assetHead := perform(handler, http.MethodHead, "https://observatory.example"+path, nil, nil)
		if assetHead.Code != http.StatusOK || assetHead.Body.Len() != 0 || assetHead.Header().Get("Content-Length") != asset.Header().Get("Content-Length") {
			t.Fatalf("asset HEAD %s status=%d", path, assetHead.Code)
		}
	}
	manifest := perform(handler, http.MethodGet, "https://observatory.example/manifest.webmanifest", nil, nil)
	if manifest.Code != http.StatusOK || manifest.Header().Get("Content-Type") != "application/manifest+json" || !strings.Contains(manifest.Body.String(), site.AssetPaths().IconPath) {
		t.Fatalf("manifest status=%d headers=%v body=%s", manifest.Code, manifest.Header(), manifest.Body.String())
	}
	manifestHead := perform(handler, http.MethodHead, "https://observatory.example/manifest.webmanifest", nil, nil)
	if manifestHead.Code != http.StatusOK || manifestHead.Body.Len() != 0 || manifestHead.Header().Get("Content-Length") != manifest.Header().Get("Content-Length") {
		t.Fatalf("manifest HEAD status=%d body=%d", manifestHead.Code, manifestHead.Body.Len())
	}
	worker := perform(handler, http.MethodGet, "https://observatory.example/service-worker.js", nil, nil)
	if worker.Code != http.StatusOK || worker.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || worker.Header().Get("Cache-Control") != "no-cache" || worker.Header().Get("Service-Worker-Allowed") != "/" || !strings.Contains(worker.Body.String(), "cache-inbox") {
		t.Fatalf("worker status=%d headers=%v", worker.Code, worker.Header())
	}
	offline := perform(handler, http.MethodGet, "https://observatory.example/offline/", nil, nil)
	if offline.Code != http.StatusOK || !strings.Contains(offline.Body.String(), "The evidence is still safe.") {
		t.Fatalf("offline status=%d body=%s", offline.Code, offline.Body.String())
	}
	disabledPush := perform(handler, http.MethodPost, "https://observatory.example/api/v1/push/subscription", strings.NewReader(`{}`), nil)
	if disabledPush.Code != http.StatusNotFound {
		t.Fatalf("disabled push status=%d body=%s", disabledPush.Code, disabledPush.Body.String())
	}

	unauthenticated := perform(handler, http.MethodGet, "https://observatory.example/app/", nil, nil)
	if unauthenticated.Code != http.StatusSeeOther || unauthenticated.Header().Get("Location") != "/login/" {
		t.Fatalf("unauthenticated status=%d location=%q", unauthenticated.Code, unauthenticated.Header().Get("Location"))
	}
	extraQuery := perform(handler, http.MethodGet, "https://observatory.example/app/?unexpected=true", nil, []*http.Cookie{loginHTML(t, handler)})
	if extraQuery.Code != http.StatusBadRequest {
		t.Fatalf("unexpected query status=%d", extraQuery.Code)
	}

	loginCookie := loginHTML(t, handler)
	now := server.now()
	token, err := store.CreateSource(context.Background(), "ui-source", model.Scope{OrganizationID: bootstrap.Organization.ID, ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "ui-source", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "application.http.request", Attributes: map[string]string{"http.status_code": "200", "http.route": "/"}}}}
	body, _ := json.Marshal(batch)
	updates, remove, err := server.refresh.subscribe(bootstrap.Organization.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	ingestHeaders := http.Header{"Authorization": []string{"Bearer " + token}, "Content-Type": []string{"application/json"}}
	ingest := perform(handler, http.MethodPost, "https://observatory.example/api/v1/ingest/native", bytes.NewReader(body), nil, ingestHeaders)
	if ingest.Code != http.StatusAccepted {
		t.Fatalf("ingest status=%d body=%s", ingest.Code, ingest.Body.String())
	}
	pending := perform(handler, http.MethodGet, "https://observatory.example/app/", nil, []*http.Cookie{loginCookie})
	if pending.Code != http.StatusOK || !strings.Contains(pending.Body.String(), "Durable evidence is still being indexed.") || !strings.Contains(pending.Body.String(), "Accepted batches safely stored: 1.") || !strings.Contains(pending.Body.String(), `role="status"`) {
		t.Fatalf("pending app status=%d body=%s", pending.Code, pending.Body.String())
	}
	if err = store.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-updates:
	default:
		t.Fatal("successful ingest did not publish organization refresh")
	}

	app := perform(handler, http.MethodGet, "https://observatory.example/app/", nil, []*http.Cookie{loginCookie})
	if app.Code != http.StatusOK || !strings.Contains(app.Body.String(), bootstrap.Organization.Name) || !strings.Contains(app.Body.String(), "application.http.request") || !strings.Contains(app.Body.String(), "Recent metrics") || !strings.Contains(app.Body.String(), "Recent traces") || !strings.Contains(app.Body.String(), "Recent deployments") || !strings.Contains(app.Body.String(), `action="/app/queries/builder/"`) || !strings.Contains(app.Body.String(), "Build a query") {
		t.Fatalf("app status=%d body=%s", app.Code, app.Body.String())
	}
	if strings.Contains(app.Body.String(), "Durable evidence is still being indexed.") {
		t.Fatalf("app retained indexing status after projection completed: %s", app.Body.String())
	}
	for _, forbidden := range []string{"Render #", "request number", "position:sticky", "unsafe-inline"} {
		if strings.Contains(app.Body.String(), forbidden) {
			t.Fatalf("app exposed forbidden marker %q", forbidden)
		}
	}
	appHead := perform(handler, http.MethodHead, "https://observatory.example/app/", nil, []*http.Cookie{loginCookie})
	if appHead.Code != http.StatusOK || appHead.Body.Len() != 0 || appHead.Header().Get("Content-Length") != app.Header().Get("Content-Length") {
		t.Fatalf("app HEAD status=%d body=%d", appHead.Code, appHead.Body.Len())
	}

	sessionToken := loginCookie.Value
	csrf, err := authhttp.CSRFToken(sessionToken, "session:delete")
	if err != nil {
		t.Fatal(err)
	}
	logout := url.Values{"csrf_token": []string{csrf}}.Encode()
	logoutHeaders := http.Header{"Origin": []string{"null"}, "Content-Type": []string{"application/x-www-form-urlencoded"}}
	loggedOut := perform(handler, http.MethodPost, "https://observatory.example/logout/", strings.NewReader(logout), []*http.Cookie{loginCookie}, logoutHeaders)
	if loggedOut.Code != http.StatusSeeOther || loggedOut.Header().Get("Location") != "/login/" {
		t.Fatalf("logout status=%d location=%q", loggedOut.Code, loggedOut.Header().Get("Location"))
	}
}

func TestExploreWorkbenchUsesBoundedServerRenderedQueries(t *testing.T) {
	server, store, identities, bootstrap := newUITestServer(t)
	defer store.Close()
	defer identities.Close()
	handler := server.Handler()

	unauthenticated := perform(handler, http.MethodGet, "https://observatory.example/app/explore/?organization="+url.QueryEscape(bootstrap.Organization.ID), nil, nil)
	if unauthenticated.Code != http.StatusSeeOther || unauthenticated.Header().Get("Location") != "/login/" {
		t.Fatalf("unauthenticated status=%d location=%q", unauthenticated.Code, unauthenticated.Header().Get("Location"))
	}
	cookie := loginHTML(t, handler)
	missingOrganization := perform(handler, http.MethodGet, "https://observatory.example/app/explore/", nil, []*http.Cookie{cookie})
	if missingOrganization.Code != http.StatusBadRequest {
		t.Fatalf("missing organization status=%d body=%s", missingOrganization.Code, missingOrganization.Body.String())
	}
	target := "https://observatory.example/app/explore/?organization=" + url.QueryEscape(bootstrap.Organization.ID)
	page := perform(handler, http.MethodGet, target, nil, []*http.Cookie{cookie})
	pageBody := page.Body.String()
	currentLink := `<a aria-current="page" href="/app/explore/?organization=` + bootstrap.Organization.ID + `">Explore</a>`
	if page.Code != http.StatusOK || !strings.Contains(pageBody, "Follow the evidence.") || !strings.Contains(pageBody, currentLink) || !strings.Contains(pageBody, defaultExploreQuery) || strings.Contains(pageBody, "Authorized query results") {
		t.Fatalf("explore status=%d body=%s", page.Code, pageBody)
	}
	if !strings.Contains(pageBody, `method="post" action="/app/explore/?organization=`+bootstrap.Organization.ID+`"`) || strings.Contains(pageBody, "?query=") {
		t.Fatalf("explore form did not keep query in POST body: %s", pageBody)
	}
	head := perform(handler, http.MethodHead, target, nil, []*http.Cookie{cookie})
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != page.Header().Get("Content-Length") {
		t.Fatalf("explore HEAD status=%d length=%q body=%d", head.Code, head.Header().Get("Content-Length"), head.Body.Len())
	}

	now := server.now()
	sourceToken, err := store.CreateSource(context.Background(), "explore-source", model.Scope{OrganizationID: bootstrap.Organization.ID, ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "explore-source", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "application.http.request", Attributes: map[string]string{"http.status_code": "200", "http.route": "/explore-proof"}}}}
	if _, err = store.Ingest(context.Background(), sourceToken, batch, now); err != nil {
		t.Fatal(err)
	}
	if err = store.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	csrf, err := authhttp.CSRFToken(cookie.Value, "query:execute")
	if err != nil {
		t.Fatal(err)
	}
	queryText := `logs | where route == "/explore-proof" | window 1h | limit 10`
	form := url.Values{"csrf_token": []string{csrf}, "query": []string{queryText}}.Encode()
	headers := http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}}
	result := perform(handler, http.MethodPost, target, strings.NewReader(form), []*http.Cookie{cookie}, headers)
	resultBody := result.Body.String()
	for _, required := range []string{"Authorized query results", "/explore-proof", "Scanned rows", "Matched rows", "Scanned bytes", "Execution", html.EscapeString(queryText)} {
		if !strings.Contains(resultBody, required) {
			t.Fatalf("result omitted %q: status=%d body=%s", required, result.Code, resultBody)
		}
	}
	if result.Code != http.StatusOK || strings.Contains(result.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("query status=%d type=%q body=%s", result.Code, result.Header().Get("Content-Type"), resultBody)
	}

	invalidForm := url.Values{"csrf_token": []string{"invalid"}, "query": []string{"logs | limit 10"}}.Encode()
	invalid := perform(handler, http.MethodPost, target, strings.NewReader(invalidForm), []*http.Cookie{cookie}, headers)
	if invalid.Code != http.StatusForbidden || !strings.Contains(invalid.Body.String(), "query form expired") || strings.Contains(invalid.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("invalid CSRF status=%d body=%s", invalid.Code, invalid.Body.String())
	}

	badQuery := url.Values{"csrf_token": []string{csrf}, "query": []string{"logs | become unbounded"}}.Encode()
	rejected := perform(handler, http.MethodPost, target, strings.NewReader(badQuery), []*http.Cookie{cookie}, headers)
	if rejected.Code != http.StatusUnprocessableEntity || !strings.Contains(rejected.Body.String(), "could not be parsed") || !strings.Contains(rejected.Body.String(), "logs | become unbounded") {
		t.Fatalf("rejected query status=%d body=%s", rejected.Code, rejected.Body.String())
	}
}

func TestHTMLLoginFailsClosed(t *testing.T) {
	server, store, identities, _ := newUITestServer(t)
	defer store.Close()
	defer identities.Close()
	handler := server.Handler()

	wrongOrigin := http.Header{"Origin": []string{"https://attacker.example"}, "Content-Type": []string{"application/x-www-form-urlencoded"}}
	result := perform(handler, http.MethodPost, "https://observatory.example/login/", strings.NewReader("identifier=operator&password=do-not-echo"), nil, wrongOrigin)
	if result.Code != http.StatusForbidden || !strings.Contains(result.Body.String(), loginFormFailure) || strings.Contains(result.Body.String(), "do-not-echo") || strings.Contains(result.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("wrong origin status=%d body=%s", result.Code, result.Body.String())
	}
	csrfCookie, csrfToken := loginFormCSRF(t, handler)
	extraField := http.Header{"Origin": []string{"https://observatory.example"}, "Content-Type": []string{"application/x-www-form-urlencoded"}}
	extraForm := url.Values{"csrf_token": []string{csrfToken}, "identifier": []string{"operator"}, "password": []string{"wrong"}, "next": []string{"https://attacker.example"}}.Encode()
	result = perform(handler, http.MethodPost, "https://observatory.example/login/", strings.NewReader(extraForm), []*http.Cookie{csrfCookie}, extraField)
	if result.Code != http.StatusForbidden || !strings.Contains(result.Body.String(), loginFormFailure) || strings.Contains(result.Body.String(), "attacker.example") || result.Header().Get("Location") != "" {
		t.Fatalf("extra field status=%d location=%q body=%s", result.Code, result.Header().Get("Location"), result.Body.String())
	}
}

func TestHTMLLoginUsesTokenWhenBrowserOmitsOrObscuresOriginMetadata(t *testing.T) {
	server, store, identities, _ := newUITestServer(t)
	defer store.Close()
	defer identities.Close()
	handler := server.Handler()

	page := perform(handler, http.MethodGet, "https://observatory.example/login/", nil, nil)
	if page.Code != http.StatusOK {
		t.Fatalf("login page status=%d body=%s", page.Code, page.Body.String())
	}
	var csrfCookie *http.Cookie
	for _, cookie := range page.Result().Cookies() {
		if cookie.Name == loginCSRFCookieName {
			csrfCookie = cookie
		}
	}
	if csrfCookie == nil || !csrfCookie.Secure || !csrfCookie.HttpOnly || csrfCookie.SameSite != http.SameSiteStrictMode || csrfCookie.MaxAge != 600 {
		t.Fatalf("login CSRF cookie=%+v", csrfCookie)
	}
	const marker = `name="csrf_token" value="`
	start := strings.Index(page.Body.String(), marker)
	if start < 0 {
		t.Fatalf("login page omitted CSRF token: %s", page.Body.String())
	}
	start += len(marker)
	end := strings.IndexByte(page.Body.String()[start:], '"')
	if end < 0 {
		t.Fatal("login page CSRF token is unterminated")
	}
	token := page.Body.String()[start : start+end]
	if token == "" || token != csrfCookie.Value {
		t.Fatal("login form and cookie CSRF tokens differ")
	}

	form := url.Values{"csrf_token": []string{token}, "identifier": []string{"not-a-user"}, "password": []string{"not-a-password"}}.Encode()
	contentType := http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}}
	omittedMetadata := perform(handler, http.MethodPost, "https://observatory.example/login/", strings.NewReader(form), []*http.Cookie{csrfCookie}, contentType)
	if omittedMetadata.Code != http.StatusUnauthorized || strings.Contains(omittedMetadata.Body.String(), "not-a-password") {
		t.Fatalf("origin-metadata fallback status=%d body=%s", omittedMetadata.Code, omittedMetadata.Body.String())
	}
	opaqueSameOriginHeaders := contentType.Clone()
	opaqueSameOriginHeaders.Set("Origin", "null")
	opaqueSameOriginHeaders.Set("Sec-Fetch-Site", "same-origin")
	opaqueSameOrigin := perform(handler, http.MethodPost, "https://observatory.example/login/", strings.NewReader(form), []*http.Cookie{csrfCookie}, opaqueSameOriginHeaders)
	if opaqueSameOrigin.Code != http.StatusUnauthorized || strings.Contains(opaqueSameOrigin.Body.String(), "not-a-password") {
		t.Fatalf("opaque same-origin fallback status=%d body=%s", opaqueSameOrigin.Code, opaqueSameOrigin.Body.String())
	}

	withoutToken := perform(handler, http.MethodPost, "https://observatory.example/login/", strings.NewReader("identifier=not-a-user&password=not-a-password"), nil, contentType)
	if withoutToken.Code != http.StatusForbidden {
		t.Fatalf("originless tokenless status=%d body=%s", withoutToken.Code, withoutToken.Body.String())
	}
	opaqueWithoutToken := perform(handler, http.MethodPost, "https://observatory.example/login/", strings.NewReader("identifier=not-a-user&password=not-a-password"), nil, opaqueSameOriginHeaders)
	if opaqueWithoutToken.Code != http.StatusForbidden {
		t.Fatalf("opaque tokenless status=%d body=%s", opaqueWithoutToken.Code, opaqueWithoutToken.Body.String())
	}
	opaqueWithoutFetchMetadata := contentType.Clone()
	opaqueWithoutFetchMetadata.Set("Origin", "null")
	opaqueTokenOnly := perform(handler, http.MethodPost, "https://observatory.example/login/", strings.NewReader(form), []*http.Cookie{csrfCookie}, opaqueWithoutFetchMetadata)
	if opaqueTokenOnly.Code != http.StatusUnauthorized || !strings.Contains(opaqueTokenOnly.Body.String(), loginCredentialFailure) {
		t.Fatalf("opaque origin without same-origin fetch metadata status=%d body=%s", opaqueTokenOnly.Code, opaqueTokenOnly.Body.String())
	}
	wrongOrigin := contentType.Clone()
	wrongOrigin.Set("Origin", "https://attacker.example")
	crossSite := perform(handler, http.MethodPost, "https://observatory.example/login/", strings.NewReader(form), []*http.Cookie{csrfCookie}, wrongOrigin)
	if crossSite.Code != http.StatusForbidden {
		t.Fatalf("cross-site token replay status=%d body=%s", crossSite.Code, crossSite.Body.String())
	}
}

func TestTemporaryOperatorMustRotatePasswordBeforeUsingApplication(t *testing.T) {
	server, store, identities, _ := newRotationTestServer(t)
	defer store.Close()
	defer identities.Close()
	handler := server.Handler()
	const temporary = "temporary correct horse battery staple"
	const replacement = "permanent correct horse battery staple"

	headers := http.Header{"Origin": []string{"https://observatory.example"}, "Content-Type": []string{"application/x-www-form-urlencoded"}}
	login := loginHTMLResponse(t, handler, "operator", temporary)
	if login.Code != http.StatusSeeOther || login.Header().Get("Location") != "/account/password/" || strings.Contains(login.Body.String(), temporary) {
		t.Fatalf("login status=%d location=%q body=%s", login.Code, login.Header().Get("Location"), login.Body.String())
	}
	var cookie *http.Cookie
	for _, candidate := range login.Result().Cookies() {
		if candidate.Name == "__Host-observatory_session" {
			cookie = candidate
			break
		}
	}
	if cookie == nil {
		t.Fatalf("login cookies=%+v", login.Result().Cookies())
	}
	blocked := perform(handler, http.MethodGet, "https://observatory.example/app/", nil, []*http.Cookie{cookie})
	if blocked.Code != http.StatusSeeOther || blocked.Header().Get("Location") != "/account/password/" {
		t.Fatalf("blocked app status=%d location=%q", blocked.Code, blocked.Header().Get("Location"))
	}
	blockedWrite := perform(handler, http.MethodPost, "https://observatory.example/api/v1/query", strings.NewReader(`{}`), []*http.Cookie{cookie}, headers)
	if blockedWrite.Code != http.StatusForbidden {
		t.Fatalf("blocked write status=%d body=%s", blockedWrite.Code, blockedWrite.Body.String())
	}
	page := perform(handler, http.MethodGet, "https://observatory.example/account/password/", nil, []*http.Cookie{cookie})
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Choose your password") || strings.Contains(page.Body.String(), temporary) {
		t.Fatalf("password page status=%d body=%s", page.Code, page.Body.String())
	}
	head := perform(handler, http.MethodHead, "https://observatory.example/account/password/", nil, []*http.Cookie{cookie})
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != page.Header().Get("Content-Length") {
		t.Fatalf("password HEAD status=%d length=%q body=%d", head.Code, head.Header().Get("Content-Length"), head.Body.Len())
	}
	csrf, err := authhttp.CSRFToken(cookie.Value, "account:password:change")
	if err != nil {
		t.Fatal(err)
	}
	crossSiteHeaders := http.Header{"Origin": []string{"https://attacker.example"}, "Sec-Fetch-Site": []string{"cross-site"}, "Content-Type": []string{"application/x-www-form-urlencoded"}}
	crossSiteForm := url.Values{"csrf_token": []string{csrf}, "current_password": []string{temporary}, "new_password": []string{replacement}, "confirm_password": []string{replacement}}.Encode()
	crossSite := perform(handler, http.MethodPost, "https://observatory.example/account/password/", strings.NewReader(crossSiteForm), []*http.Cookie{cookie}, crossSiteHeaders)
	if crossSite.Code != http.StatusForbidden || !strings.Contains(crossSite.Body.String(), passwordFormFailure) || strings.Contains(crossSite.Body.String(), temporary) || strings.Contains(crossSite.Body.String(), replacement) || strings.Contains(crossSite.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("cross-site password status=%d body=%s", crossSite.Code, crossSite.Body.String())
	}
	invalidTokenForm := url.Values{"csrf_token": []string{"invalid"}, "current_password": []string{temporary}, "new_password": []string{replacement}, "confirm_password": []string{replacement}}.Encode()
	invalidToken := perform(handler, http.MethodPost, "https://observatory.example/account/password/", strings.NewReader(invalidTokenForm), []*http.Cookie{cookie}, headers)
	if invalidToken.Code != http.StatusForbidden || !strings.Contains(invalidToken.Body.String(), passwordFormFailure) || strings.Contains(invalidToken.Body.String(), temporary) || strings.Contains(invalidToken.Body.String(), replacement) || strings.Contains(invalidToken.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("invalid-token password status=%d body=%s", invalidToken.Code, invalidToken.Body.String())
	}
	mismatch := url.Values{"csrf_token": []string{csrf}, "current_password": []string{temporary}, "new_password": []string{replacement}, "confirm_password": []string{"different password value"}}.Encode()
	rejected := perform(handler, http.MethodPost, "https://observatory.example/account/password/", strings.NewReader(mismatch), []*http.Cookie{cookie}, headers)
	if rejected.Code != http.StatusUnprocessableEntity || !strings.Contains(rejected.Body.String(), passwordMatchFailure) || strings.Contains(rejected.Body.String(), temporary) || strings.Contains(rejected.Body.String(), replacement) {
		t.Fatalf("mismatch status=%d body=%s", rejected.Code, rejected.Body.String())
	}
	change := url.Values{"csrf_token": []string{csrf}, "current_password": []string{temporary}, "new_password": []string{replacement}, "confirm_password": []string{replacement}}.Encode()
	privacyHeaders := http.Header{"Origin": []string{"null"}, "Content-Type": []string{"application/x-www-form-urlencoded"}}
	changed := perform(handler, http.MethodPost, "https://observatory.example/account/password/", strings.NewReader(change), []*http.Cookie{cookie}, privacyHeaders)
	if changed.Code != http.StatusSeeOther || changed.Header().Get("Location") != "/login/?password=changed" {
		t.Fatalf("change status=%d location=%q body=%s", changed.Code, changed.Header().Get("Location"), changed.Body.String())
	}
	oldSession := perform(handler, http.MethodGet, "https://observatory.example/app/", nil, []*http.Cookie{cookie})
	if oldSession.Code != http.StatusSeeOther || oldSession.Header().Get("Location") != "/login/" {
		t.Fatalf("old session status=%d location=%q", oldSession.Code, oldSession.Header().Get("Location"))
	}
	if _, _, err = identities.Auth.Authenticate(t.Context(), "operator", temporary, time.Hour); err == nil {
		t.Fatal("temporary password remained valid")
	}
	_, principal, err := identities.Auth.Authenticate(t.Context(), "operator", replacement, time.Hour)
	if err != nil || principal.User.PasswordChangeRequired {
		t.Fatalf("replacement principal=%+v err=%v", principal, err)
	}

	newLogin := loginHTMLResponse(t, handler, "operator", replacement)
	if newLogin.Code != http.StatusSeeOther || newLogin.Header().Get("Location") != "/app/" {
		t.Fatalf("new login status=%d location=%q", newLogin.Code, newLogin.Header().Get("Location"))
	}
}

func TestAPITemporaryOperatorReceivesScopedRotationToken(t *testing.T) {
	server, store, identities, _ := newRotationTestServer(t)
	defer store.Close()
	defer identities.Close()
	handler := server.Handler()
	loginHeaders := http.Header{"Origin": []string{"https://observatory.example"}, "Content-Type": []string{"application/json"}}
	login := perform(handler, http.MethodPost, "https://observatory.example/api/v1/session", strings.NewReader(`{"identifier":"operator","password":"temporary correct horse battery staple"}`), nil, loginHeaders)
	var session struct {
		PasswordChangeRequired bool   `json:"password_change_required"`
		PasswordChangeCSRF     string `json:"password_change_csrf"`
	}
	if login.Code != http.StatusOK || json.Unmarshal(login.Body.Bytes(), &session) != nil || !session.PasswordChangeRequired || session.PasswordChangeCSRF == "" {
		t.Fatalf("login status=%d session=%+v body=%s", login.Code, session, login.Body.String())
	}
	cookies := login.Result().Cookies()
	changeHeaders := http.Header{"Origin": []string{"https://observatory.example"}, "Content-Type": []string{"application/json"}, "X-CSRF-Token": []string{session.PasswordChangeCSRF}}
	changed := perform(handler, http.MethodPost, "https://observatory.example/api/v1/account/password", strings.NewReader(`{"current_password":"temporary correct horse battery staple","new_password":"API replacement password value"}`), cookies, changeHeaders)
	if changed.Code != http.StatusNoContent || changed.Body.Len() != 0 {
		t.Fatalf("change status=%d body=%s", changed.Code, changed.Body.String())
	}
	_, principal, err := identities.Auth.Authenticate(t.Context(), "operator", "API replacement password value", time.Hour)
	if err != nil || principal.User.PasswordChangeRequired {
		t.Fatalf("principal=%+v err=%v", principal, err)
	}
}

func TestLiveRefreshStreamIsAuthorizedAndCarriesNoTelemetry(t *testing.T) {
	server, store, identities, bootstrap := newUITestServer(t)
	defer store.Close()
	defer identities.Close()
	handler := server.Handler()
	unauthorized := perform(handler, http.MethodGet, "https://observatory.example/app/events?organization="+url.QueryEscape(bootstrap.Organization.ID), nil, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized stream status=%d", unauthorized.Code)
	}
	cookie := loginHTML(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "https://observatory.example/app/events?organization="+url.QueryEscape(bootstrap.Organization.ID), nil).WithContext(ctx)
	request.AddCookie(cookie)
	stream := newStreamRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(stream, request)
		close(done)
	}()
	waitFlush := func() {
		t.Helper()
		select {
		case <-stream.flushed:
		case <-ctx.Done():
			t.Fatal("stream did not flush before timeout")
		}
	}
	waitFlush()
	if stream.statusCode() != http.StatusOK || stream.Header().Get("Content-Type") != "text/event-stream; charset=utf-8" || stream.Header().Get("X-Accel-Buffering") != "no" || stream.bodyString() != "event: ready\ndata: {}\n\n" {
		t.Fatalf("stream status=%d headers=%v body=%q", stream.statusCode(), stream.Header(), stream.bodyString())
	}
	server.refresh.publish(bootstrap.Organization.ID)
	waitFlush()
	streamBody := stream.bodyString()
	if streamBody != "event: ready\ndata: {}\n\nevent: refresh\ndata: {}\n\n" || strings.Contains(streamBody, bootstrap.Organization.ID) || strings.Contains(streamBody, "service") {
		t.Fatalf("stream body=%q", streamBody)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream did not stop after cancellation")
	}
}

func TestDashboardManagementIsScopedCSRFProtectedAndExportable(t *testing.T) {
	server, store, identities, bootstrap := newUITestServer(t)
	defer store.Close()
	defer identities.Close()
	handler := server.Handler()
	cookie := loginHTML(t, handler)
	csrf, err := authhttp.CSRFToken(cookie.Value, "dashboards:manage")
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"Origin": []string{"https://observatory.example"}, "Content-Type": []string{"application/x-www-form-urlencoded"}}

	invalid := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{"invalid"},
		"name": []string{"Recent errors"}, "description": []string{"A bounded recent error view."},
		"query": []string{"logs | where status >= 500 | window 1h | limit 50"},
	}.Encode()
	denied := perform(handler, http.MethodPost, "https://observatory.example/app/queries/", strings.NewReader(invalid), []*http.Cookie{cookie}, headers)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("invalid CSRF status=%d", denied.Code)
	}

	queryForm := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf},
		"name": []string{"Recent errors"}, "description": []string{"A bounded recent error view."},
		"query": []string{"logs | where status >= 500 | window 1h | limit 50"},
	}.Encode()
	privacyHeaders := http.Header{"Origin": []string{"null"}, "Content-Type": []string{"application/x-www-form-urlencoded"}}
	createdQuery := perform(handler, http.MethodPost, "https://observatory.example/app/queries/", strings.NewReader(queryForm), []*http.Cookie{cookie}, privacyHeaders)
	if createdQuery.Code != http.StatusSeeOther || !strings.HasPrefix(createdQuery.Header().Get("Location"), "/app/?organization=") {
		t.Fatalf("query status=%d location=%q body=%s", createdQuery.Code, createdQuery.Header().Get("Location"), createdQuery.Body.String())
	}
	queries, err := store.SavedQueries(context.Background(), bootstrap.Organization.ID)
	if err != nil || len(queries) != 1 {
		t.Fatalf("queries=%+v err=%v", queries, err)
	}
	mismatchedDashboard := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf},
		"slug": []string{"invalid-stat"}, "name": []string{"Invalid stat"},
		"description": []string{"A non-summary query cannot become a statistic."}, "panel_title": []string{"Invalid"},
		"saved_query_id": []string{queries[0].ID}, "visualization": []string{"stat"},
	}.Encode()
	mismatched := perform(handler, http.MethodPost, "https://observatory.example/app/dashboards/", strings.NewReader(mismatchedDashboard), []*http.Cookie{cookie}, headers)
	if mismatched.Code != http.StatusUnprocessableEntity {
		t.Fatalf("mismatched presentation status=%d body=%s", mismatched.Code, mismatched.Body.String())
	}

	dashboardForm := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf},
		"slug": []string{"recent-errors"}, "name": []string{"Recent errors"},
		"description": []string{"An accessible bounded error dashboard."}, "panel_title": []string{"Errors"},
		"saved_query_id": []string{queries[0].ID}, "visualization": []string{"table"},
	}.Encode()
	createdDashboard := perform(handler, http.MethodPost, "https://observatory.example/app/dashboards/", strings.NewReader(dashboardForm), []*http.Cookie{cookie}, headers)
	if createdDashboard.Code != http.StatusSeeOther || !strings.HasPrefix(createdDashboard.Header().Get("Location"), "/app/dashboards/recent-errors/") {
		t.Fatalf("dashboard status=%d location=%q body=%s", createdDashboard.Code, createdDashboard.Header().Get("Location"), createdDashboard.Body.String())
	}

	target := "https://observatory.example/app/dashboards/recent-errors/?organization=" + url.QueryEscape(bootstrap.Organization.ID)
	dashboard := perform(handler, http.MethodGet, target, nil, []*http.Cookie{cookie})
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), "An accessible bounded error dashboard.") || !strings.Contains(dashboard.Body.String(), "Recent errors") || !strings.Contains(dashboard.Body.String(), ">Errors</h2>") {
		t.Fatalf("dashboard status=%d body=%s", dashboard.Code, dashboard.Body.String())
	}
	dashboardHead := perform(handler, http.MethodHead, target, nil, []*http.Cookie{cookie})
	if dashboardHead.Code != http.StatusOK || dashboardHead.Body.Len() != 0 || dashboardHead.Header().Get("Content-Length") != dashboard.Header().Get("Content-Length") {
		t.Fatalf("dashboard HEAD status=%d length=%q", dashboardHead.Code, dashboardHead.Header().Get("Content-Length"))
	}
	storedDashboard, err := store.Dashboard(context.Background(), bootstrap.Organization.ID, "recent-errors")
	if err != nil || storedDashboard.Revision != 1 || !strings.Contains(dashboard.Body.String(), "Update dashboard details") || !strings.Contains(dashboard.Body.String(), `name="expected_revision" value="1"`) {
		t.Fatalf("stored dashboard=%+v err=%v body=%s", storedDashboard, err, dashboard.Body.String())
	}
	revisionForm := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf},
		"dashboard_id": []string{storedDashboard.ID}, "expected_revision": []string{strconv.Itoa(storedDashboard.Revision)},
		"slug": []string{storedDashboard.Slug}, "name": []string{"Current errors"},
		"description": []string{"A revision-safe bounded error dashboard."},
	}.Encode()
	revised := perform(handler, http.MethodPost, target, strings.NewReader(revisionForm), []*http.Cookie{cookie}, headers)
	if revised.Code != http.StatusSeeOther {
		t.Fatalf("revision status=%d body=%s", revised.Code, revised.Body.String())
	}
	stale := perform(handler, http.MethodPost, target, strings.NewReader(revisionForm), []*http.Cookie{cookie}, headers)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale revision status=%d body=%s", stale.Code, stale.Body.String())
	}
	storedDashboard, err = store.Dashboard(context.Background(), bootstrap.Organization.ID, "recent-errors")
	if err != nil || storedDashboard.Revision != 2 || storedDashboard.Name != "Current errors" {
		t.Fatalf("revised dashboard=%+v err=%v", storedDashboard, err)
	}
	addPanelForm := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf},
		"dashboard_id": []string{storedDashboard.ID}, "expected_revision": []string{strconv.Itoa(storedDashboard.Revision)},
		"panel_title": []string{"Recent failures"}, "saved_query_id": []string{queries[0].ID}, "visualization": []string{"table"},
	}.Encode()
	addTarget := "https://observatory.example/app/dashboards/recent-errors/panels/?organization=" + url.QueryEscape(bootstrap.Organization.ID)
	added := perform(handler, http.MethodPost, addTarget, strings.NewReader(addPanelForm), []*http.Cookie{cookie}, headers)
	if added.Code != http.StatusSeeOther {
		t.Fatalf("add panel status=%d body=%s", added.Code, added.Body.String())
	}
	storedDashboard, err = store.Dashboard(context.Background(), bootstrap.Organization.ID, "recent-errors")
	if err != nil || storedDashboard.Revision != 3 || len(storedDashboard.Panels) != 2 {
		t.Fatalf("dashboard after add=%+v err=%v", storedDashboard, err)
	}
	addedPanel := storedDashboard.Panels[1]
	updatePanelForm := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf},
		"dashboard_id": []string{storedDashboard.ID}, "expected_revision": []string{strconv.Itoa(storedDashboard.Revision)},
		"panel_title": []string{"Renamed failures"}, "saved_query_id": []string{queries[0].ID}, "visualization": []string{"table"},
	}.Encode()
	updatePanelTarget := "https://observatory.example/app/dashboards/recent-errors/panels/" + url.PathEscape(addedPanel.ID) + "/?organization=" + url.QueryEscape(bootstrap.Organization.ID)
	updatedPanel := perform(handler, http.MethodPost, updatePanelTarget, strings.NewReader(updatePanelForm), []*http.Cookie{cookie}, headers)
	if updatedPanel.Code != http.StatusSeeOther {
		t.Fatalf("update panel status=%d body=%s", updatedPanel.Code, updatedPanel.Body.String())
	}
	storedDashboard, err = store.Dashboard(context.Background(), bootstrap.Organization.ID, "recent-errors")
	if err != nil || storedDashboard.Revision != 4 || storedDashboard.Panels[1].Title != "Renamed failures" {
		t.Fatalf("dashboard after panel update=%+v err=%v", storedDashboard, err)
	}
	mismatchedRevision := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf},
		"dashboard_id": []string{storedDashboard.ID}, "expected_revision": []string{strconv.Itoa(storedDashboard.Revision)},
		"panel_title": []string{"Invalid chart"}, "saved_query_id": []string{queries[0].ID}, "visualization": []string{"timeseries"},
	}.Encode()
	mismatchedPanel := perform(handler, http.MethodPost, updatePanelTarget, strings.NewReader(mismatchedRevision), []*http.Cookie{cookie}, headers)
	if mismatchedPanel.Code != http.StatusUnprocessableEntity {
		t.Fatalf("mismatched panel status=%d body=%s", mismatchedPanel.Code, mismatchedPanel.Body.String())
	}
	removePanelForm := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf},
		"dashboard_id": []string{storedDashboard.ID}, "expected_revision": []string{strconv.Itoa(storedDashboard.Revision)},
	}.Encode()
	removeTarget := "https://observatory.example/app/dashboards/recent-errors/panels/" + url.PathEscape(addedPanel.ID) + "/remove/?organization=" + url.QueryEscape(bootstrap.Organization.ID)
	removed := perform(handler, http.MethodPost, removeTarget, strings.NewReader(removePanelForm), []*http.Cookie{cookie}, headers)
	if removed.Code != http.StatusSeeOther {
		t.Fatalf("remove panel status=%d body=%s", removed.Code, removed.Body.String())
	}
	storedDashboard, err = store.Dashboard(context.Background(), bootstrap.Organization.ID, "recent-errors")
	if err != nil || storedDashboard.Revision != 5 || len(storedDashboard.Panels) != 1 {
		t.Fatalf("dashboard after remove=%+v err=%v", storedDashboard, err)
	}

	exportTarget := "https://observatory.example/app/dashboards/recent-errors/export.json?organization=" + url.QueryEscape(bootstrap.Organization.ID)
	exported := perform(handler, http.MethodGet, exportTarget, nil, []*http.Cookie{cookie})
	if exported.Code != http.StatusOK || exported.Header().Get("Content-Type") != "application/json" || !strings.Contains(exported.Body.String(), `"version": 1`) || strings.Contains(exported.Body.String(), bootstrap.Organization.ID) || strings.Contains(exported.Body.String(), bootstrap.User.ID) {
		t.Fatalf("export status=%d headers=%v body=%s", exported.Code, exported.Header(), exported.Body.String())
	}
	exportedHead := perform(handler, http.MethodHead, exportTarget, nil, []*http.Cookie{cookie})
	if exportedHead.Code != http.StatusOK || exportedHead.Body.Len() != 0 || exportedHead.Header().Get("Content-Length") != exported.Header().Get("Content-Length") {
		t.Fatalf("export HEAD status=%d length=%q", exportedHead.Code, exportedHead.Header().Get("Content-Length"))
	}
	unauthorized := perform(handler, http.MethodGet, exportTarget, nil, nil)
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Body.String() == exported.Body.String() {
		t.Fatalf("unauthorized export status=%d", unauthorized.Code)
	}
}

func TestIncidentRulesEvaluationInboxAndResponseAreScoped(t *testing.T) {
	server, store, identities, bootstrap := newUITestServer(t)
	defer store.Close()
	defer identities.Close()
	pushes := &recordingPushDispatcher{}
	server.options.PushDispatcher = pushes
	server.options.PushPublicKey = base64.RawURLEncoding.EncodeToString(append([]byte{4}, make([]byte, 64)...))
	handler := server.Handler()
	cookie := loginHTML(t, handler)
	now := server.now()
	saved, err := store.SaveQuery(context.Background(), storage.SavedQueryInput{
		OrganizationID: bootstrap.Organization.ID, ActorUserID: bootstrap.User.ID, MaxRows: 100,
		Name: "Recent failures", Description: "Recent HTTP failures.", Query: "logs | where status >= 500 | window 1h | limit 50",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.CreateSource(context.Background(), "incident-source", model.Scope{OrganizationID: bootstrap.Organization.ID, ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "incident-source", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "http.request", Attributes: map[string]string{"http.status_code": "503", "http.route": "/failed"}}}}
	if _, err = store.Ingest(context.Background(), token, batch, now); err != nil {
		t.Fatal(err)
	}
	if err = store.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	csrf, err := authhttp.CSRFToken(cookie.Value, "incidents:manage")
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"Origin": []string{"https://observatory.example"}, "Content-Type": []string{"application/x-www-form-urlencoded"}}
	form := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf},
		"name": []string{"HTTP failures"}, "description": []string{"Open when a bounded saved query finds a failure."},
		"saved_query_id": []string{saved.ID}, "severity": []string{"critical"}, "minimum_matches": []string{"1"},
		"required_consecutive": []string{"1"}, "evaluation_interval": []string{"15s"},
	}
	invalid := cloneValues(form)
	invalid.Set("csrf_token", "invalid")
	denied := perform(handler, http.MethodPost, "https://observatory.example/app/alert-rules/", strings.NewReader(invalid.Encode()), []*http.Cookie{cookie}, headers)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("invalid CSRF status=%d body=%s", denied.Code, denied.Body.String())
	}
	privacyHeaders := http.Header{"Origin": []string{"null"}, "Content-Type": []string{"application/x-www-form-urlencoded"}}
	created := perform(handler, http.MethodPost, "https://observatory.example/app/alert-rules/", strings.NewReader(form.Encode()), []*http.Cookie{cookie}, privacyHeaders)
	if created.Code != http.StatusSeeOther || !strings.HasPrefix(created.Header().Get("Location"), "/app/incidents/?organization=") {
		t.Fatalf("create status=%d location=%q body=%s", created.Code, created.Header().Get("Location"), created.Body.String())
	}

	updates, remove, err := server.refresh.subscribe(bootstrap.Organization.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	if evaluated, evaluationErr := server.EvaluateAlerts(context.Background()); evaluationErr != nil || evaluated != 1 {
		t.Fatalf("evaluated=%d err=%v", evaluated, evaluationErr)
	}
	if len(pushes.organizations) != 1 || pushes.organizations[0] != bootstrap.Organization.ID {
		t.Fatalf("push organizations=%v", pushes.organizations)
	}
	select {
	case <-updates:
	default:
		t.Fatal("incident change did not publish a generic refresh")
	}
	incidents, err := store.Incidents(context.Background(), bootstrap.Organization.ID, false, 10)
	if err != nil || len(incidents) != 1 || incidents[0].State != "firing" {
		t.Fatalf("incidents=%+v err=%v", incidents, err)
	}

	path := "https://observatory.example/app/incidents/?organization=" + url.QueryEscape(bootstrap.Organization.ID)
	inbox := perform(handler, http.MethodGet, path, nil, []*http.Cookie{cookie})
	if inbox.Code != http.StatusOK || !strings.Contains(inbox.Body.String(), "What needs attention?") || !strings.Contains(inbox.Body.String(), "HTTP failures") || !strings.Contains(inbox.Body.String(), "critical · firing") || !strings.Contains(inbox.Body.String(), "data-cache-inbox") || !strings.Contains(inbox.Body.String(), "data-push-toggle") || !strings.Contains(inbox.Body.String(), `data-open-incident-count="1"`) || strings.Contains(inbox.Body.String(), "/failed") {
		t.Fatalf("inbox status=%d body=%s", inbox.Code, inbox.Body.String())
	}
	pushCSRF, err := authhttp.CSRFToken(cookie.Value, "push:manage")
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authSecret := make([]byte, 16)
	if _, err = rand.Read(authSecret); err != nil {
		t.Fatal(err)
	}
	pushBody, _ := json.Marshal(map[string]any{"organization_id": bootstrap.Organization.ID, "endpoint": "https://push.example.test/send/browser", "keys": map[string]string{"p256dh": base64.RawURLEncoding.EncodeToString(clientKey.PublicKey().Bytes()), "auth": base64.RawURLEncoding.EncodeToString(authSecret)}})
	pushHeaders := make(http.Header)
	pushHeaders.Set("Origin", "https://observatory.example")
	pushHeaders.Set("Content-Type", "application/json")
	pushHeaders.Set("X-CSRF-Token", pushCSRF)
	invalidPushHeaders := pushHeaders.Clone()
	invalidPushHeaders.Set("X-CSRF-Token", "invalid")
	invalidPush := perform(handler, http.MethodPost, "https://observatory.example/api/v1/push/subscription", bytes.NewReader(pushBody), []*http.Cookie{cookie}, invalidPushHeaders)
	if invalidPush.Code != http.StatusForbidden {
		t.Fatalf("invalid push CSRF status=%d body=%s", invalidPush.Code, invalidPush.Body.String())
	}
	crossOriginPushHeaders := pushHeaders.Clone()
	crossOriginPushHeaders.Set("Origin", "https://attacker.example")
	crossOriginPush := perform(handler, http.MethodPost, "https://observatory.example/api/v1/push/subscription", bytes.NewReader(pushBody), []*http.Cookie{cookie}, crossOriginPushHeaders)
	if crossOriginPush.Code != http.StatusForbidden {
		t.Fatalf("cross-origin push status=%d body=%s", crossOriginPush.Code, crossOriginPush.Body.String())
	}
	registered := perform(handler, http.MethodPost, "https://observatory.example/api/v1/push/subscription", bytes.NewReader(pushBody), []*http.Cookie{cookie}, pushHeaders)
	if registered.Code != http.StatusCreated || !strings.Contains(registered.Body.String(), `"id":"push_`) {
		t.Fatalf("push registration status=%d body=%s", registered.Code, registered.Body.String())
	}
	if subscriptions, listErr := store.PushSubscriptions(context.Background(), bootstrap.Organization.ID); listErr != nil || len(subscriptions) != 1 || subscriptions[0].UserID != bootstrap.User.ID {
		t.Fatalf("push subscriptions=%+v err=%v", subscriptions, listErr)
	}
	statusBody, _ := json.Marshal(map[string]any{"organization_id": bootstrap.Organization.ID, "endpoint": "https://push.example.test/send/browser", "keys": map[string]string{"p256dh": "", "auth": ""}})
	pushStatus := perform(handler, http.MethodPost, "https://observatory.example/api/v1/push/subscription/status", bytes.NewReader(statusBody), []*http.Cookie{cookie}, pushHeaders)
	if pushStatus.Code != http.StatusOK || !strings.Contains(pushStatus.Body.String(), `"subscribed":true`) {
		t.Fatalf("push status=%d body=%s", pushStatus.Code, pushStatus.Body.String())
	}
	privateEndpointBody := bytes.Replace(pushBody, []byte("https://push.example.test/send/browser"), []byte("https://127.0.0.1/send/browser"), 1)
	rejected := perform(handler, http.MethodPost, "https://observatory.example/api/v1/push/subscription", bytes.NewReader(privateEndpointBody), []*http.Cookie{cookie}, pushHeaders)
	if rejected.Code != http.StatusUnprocessableEntity || strings.Contains(rejected.Body.String(), "127.0.0.1") {
		t.Fatalf("private endpoint status=%d body=%s", rejected.Code, rejected.Body.String())
	}
	invalidCurveBody, _ := json.Marshal(map[string]any{"organization_id": bootstrap.Organization.ID, "endpoint": "https://push.example.test/send/invalid-curve", "keys": map[string]string{"p256dh": base64.RawURLEncoding.EncodeToString(append([]byte{4}, make([]byte, 64)...)), "auth": base64.RawURLEncoding.EncodeToString(authSecret)}})
	invalidCurve := perform(handler, http.MethodPost, "https://observatory.example/api/v1/push/subscription", bytes.NewReader(invalidCurveBody), []*http.Cookie{cookie}, pushHeaders)
	if invalidCurve.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid curve status=%d body=%s", invalidCurve.Code, invalidCurve.Body.String())
	}
	deleteBody, _ := json.Marshal(map[string]any{"organization_id": bootstrap.Organization.ID, "endpoint": "https://push.example.test/send/browser", "keys": map[string]string{"p256dh": "", "auth": ""}})
	deleted := perform(handler, http.MethodDelete, "https://observatory.example/api/v1/push/subscription", bytes.NewReader(deleteBody), []*http.Cookie{cookie}, pushHeaders)
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"remaining":false`) {
		t.Fatalf("push deletion status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	offlineInbox := perform(handler, http.MethodGet, "https://observatory.example/app/incidents/offline/?organization="+url.QueryEscape(bootstrap.Organization.ID), nil, []*http.Cookie{cookie})
	if offlineInbox.Code != http.StatusOK || !strings.Contains(offlineInbox.Body.String(), "Saved incident inbox") || !strings.Contains(offlineInbox.Body.String(), "HTTP failures") {
		t.Fatalf("offline inbox status=%d body=%s", offlineInbox.Code, offlineInbox.Body.String())
	}
	for _, forbidden := range []string{incidents[0].ID, saved.Query, bootstrap.User.ID, "csrf_token", "/failed", "Acknowledge", "Resolve"} {
		if strings.Contains(offlineInbox.Body.String(), forbidden) {
			t.Fatalf("offline inbox exposed %q: %s", forbidden, offlineInbox.Body.String())
		}
	}
	unauthenticatedOffline := perform(handler, http.MethodGet, "https://observatory.example/app/incidents/offline/?organization="+url.QueryEscape(bootstrap.Organization.ID), nil, nil)
	if unauthenticatedOffline.Code != http.StatusSeeOther || unauthenticatedOffline.Header().Get("Location") != "/login/" {
		t.Fatalf("unauthenticated offline status=%d", unauthenticatedOffline.Code)
	}
	inboxHead := perform(handler, http.MethodHead, path, nil, []*http.Cookie{cookie})
	if inboxHead.Code != http.StatusOK || inboxHead.Body.Len() != 0 || inboxHead.Header().Get("Content-Length") != inbox.Header().Get("Content-Length") {
		t.Fatalf("inbox HEAD status=%d length=%q body=%d", inboxHead.Code, inboxHead.Header().Get("Content-Length"), inboxHead.Body.Len())
	}
	missingOrganization := perform(handler, http.MethodGet, "https://observatory.example/app/incidents/", nil, []*http.Cookie{cookie})
	if missingOrganization.Code != http.StatusBadRequest {
		t.Fatalf("missing organization status=%d", missingOrganization.Code)
	}

	action := url.Values{"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf}, "action": []string{"acknowledge"}, "silence_duration": []string{""}}.Encode()
	acknowledged := perform(handler, http.MethodPost, "https://observatory.example/app/incidents/"+incidents[0].ID+"/", strings.NewReader(action), []*http.Cookie{cookie}, headers)
	if acknowledged.Code != http.StatusSeeOther {
		t.Fatalf("acknowledge status=%d body=%s", acknowledged.Code, acknowledged.Body.String())
	}
	current, err := store.Incidents(context.Background(), bootstrap.Organization.ID, false, 10)
	if err != nil || len(current) != 1 || current[0].State != "acknowledged" || current[0].AcknowledgedBy != bootstrap.User.ID {
		t.Fatalf("current=%+v err=%v", current, err)
	}
}

type recordingPushDispatcher struct{ organizations []string }

func (dispatcher *recordingPushDispatcher) Enqueue(organizationID string) bool {
	dispatcher.organizations = append(dispatcher.organizations, organizationID)
	return true
}

func cloneValues(input url.Values) url.Values {
	result := make(url.Values, len(input))
	for key, values := range input {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func TestAssistedQueryBuilderCreatesTypedTimeSeriesWithTableAlternative(t *testing.T) {
	server, store, identities, bootstrap := newUITestServer(t)
	defer store.Close()
	defer identities.Close()
	handler := server.Handler()
	cookie := loginHTML(t, handler)
	csrf, err := authhttp.CSRFToken(cookie.Value, "dashboards:manage")
	if err != nil {
		t.Fatal(err)
	}
	now := server.now()
	token, err := store.CreateSource(context.Background(), "builder-source", model.Scope{OrganizationID: bootstrap.Organization.ID, ProjectID: "project-a", EnvironmentID: "production", ServiceID: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "builder-source", StreamID: "requests", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{
		{Timestamp: now.Add(-6 * time.Minute), Name: "application.http.request", Attributes: map[string]string{"http.status_code": "503", "http.route": "/failed"}},
		{Timestamp: now.Add(-1 * time.Minute), Name: "application.http.request", Attributes: map[string]string{"http.status_code": "500", "http.route": "/failed"}},
	}}
	if _, err = store.Ingest(context.Background(), token, batch, now); err != nil {
		t.Fatal(err)
	}
	if err = store.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"Origin": []string{"https://observatory.example"}, "Content-Type": []string{"application/x-www-form-urlencoded"}}
	builderForm := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf},
		"name": []string{"Errors over time"}, "description": []string{"Five-minute error counts."},
		"signal": []string{"logs"}, "filter_field": []string{"status"}, "filter_operator": []string{">="}, "filter_value": []string{"500"},
		"window": []string{"1h"}, "aggregate": []string{"count"}, "aggregate_field": []string{""}, "group_by": []string{"route"}, "bucket": []string{"5m"}, "limit": []string{"50"},
	}.Encode()
	createdQuery := perform(handler, http.MethodPost, "https://observatory.example/app/queries/builder/", strings.NewReader(builderForm), []*http.Cookie{cookie}, headers)
	if createdQuery.Code != http.StatusSeeOther {
		t.Fatalf("builder status=%d body=%s", createdQuery.Code, createdQuery.Body.String())
	}
	queries, err := store.SavedQueries(context.Background(), bootstrap.Organization.ID)
	if err != nil || len(queries) != 1 {
		t.Fatalf("queries=%+v err=%v", queries, err)
	}
	expectedText := `logs | where status >= "500" | window 1h | summarize count() by route, window(5m) | limit 50`
	if queries[0].Query != expectedText || queries[0].AST.Signal != model.SignalLogs || len(queries[0].AST.Filters) != 1 || queries[0].AST.Filters[0].Value != "500" || queries[0].AST.Summary == nil || queries[0].AST.Bucket != 5*time.Minute {
		t.Fatalf("saved query=%+v", queries[0])
	}
	dashboardForm := url.Values{
		"organization_id": []string{bootstrap.Organization.ID}, "csrf_token": []string{csrf},
		"slug": []string{"error-rate"}, "name": []string{"Error rate"}, "description": []string{"A bounded error trend."},
		"panel_title": []string{"Errors by route"}, "saved_query_id": []string{queries[0].ID}, "visualization": []string{"timeseries"},
	}.Encode()
	createdDashboard := perform(handler, http.MethodPost, "https://observatory.example/app/dashboards/", strings.NewReader(dashboardForm), []*http.Cookie{cookie}, headers)
	if createdDashboard.Code != http.StatusSeeOther {
		t.Fatalf("dashboard status=%d body=%s", createdDashboard.Code, createdDashboard.Body.String())
	}
	target := "https://observatory.example/app/dashboards/error-rate/?organization=" + url.QueryEscape(bootstrap.Organization.ID)
	dashboard := perform(handler, http.MethodGet, target, nil, []*http.Cookie{cookie})
	body := dashboard.Body.String()
	if dashboard.Code != http.StatusOK || !strings.Contains(body, "Errors by route visual summary") || strings.Count(body, "<meter ") != 2 || !strings.Contains(body, "<table>") || !strings.Contains(body, "<caption>Errors by route</caption>") {
		t.Fatalf("dashboard status=%d body=%s", dashboard.Code, body)
	}
}

func TestAssistedQueryBuilderEscapesStageSeparatorsAndRejectsInvalidCombinations(t *testing.T) {
	values := url.Values{
		"signal": []string{"logs"}, "filter_field": []string{"name"}, "filter_operator": []string{"=="}, "filter_value": []string{"worker | limit 250"},
		"window": []string{"1h"}, "aggregate": []string{"none"}, "aggregate_field": []string{""}, "group_by": []string{""}, "bucket": []string{""}, "limit": []string{"50"},
	}
	text, err := buildAssistedQuery(values, 1000)
	if err != nil || strings.Contains(text, `"worker | limit 250"`) || !strings.Contains(text, `\u007c`) {
		t.Fatalf("text=%q err=%v", text, err)
	}
	ast, err := query.Parse(text, 1000)
	if err != nil || len(ast.Filters) != 1 || ast.Filters[0].Value != "worker | limit 250" || ast.Limit != 50 {
		t.Fatalf("AST=%+v err=%v", ast, err)
	}
	values.Set("bucket", "5m")
	if _, err = buildAssistedQuery(values, 1000); err == nil {
		t.Fatal("time bucket without an aggregate was accepted")
	}
}

func TestResultChartIsBoundedAndFailsClosedForNegativeValues(t *testing.T) {
	result := query.Result{Columns: []query.Column{{Field: "window_start", Type: schema.TypeTime}, {Field: "count", Type: schema.TypeInteger}}}
	for index := range 60 {
		label := fmt.Sprintf("2026-08-17T07:%02d:00Z", index)
		value := strconv.Itoa(index)
		result.Rows = append(result.Rows, query.Row{Values: []*string{&label, &value}})
	}
	chart := resultChart("Requests", result)
	if len(chart.Points) != 48 || chart.Points[47].Maximum != "47" || chart.Points[47].Value != "47" {
		t.Fatalf("chart=%+v", chart)
	}
	negative := "-1"
	result.Rows[0].Values[1] = &negative
	if chart = resultChart("Requests", result); len(chart.Points) != 0 {
		t.Fatalf("negative chart=%+v", chart)
	}
}

type streamRecorder struct {
	mu      sync.Mutex
	header  http.Header
	status  int
	body    bytes.Buffer
	flushed chan struct{}
}

func newStreamRecorder() *streamRecorder {
	return &streamRecorder{header: make(http.Header), flushed: make(chan struct{}, 4)}
}

func (recorder *streamRecorder) Header() http.Header { return recorder.header }

func (recorder *streamRecorder) WriteHeader(status int) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.status == 0 {
		recorder.status = status
	}
}

func (recorder *streamRecorder) Write(body []byte) (int, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.status == 0 {
		recorder.status = http.StatusOK
	}
	return recorder.body.Write(body)
}

func (recorder *streamRecorder) Flush() {
	select {
	case recorder.flushed <- struct{}{}:
	default:
	}
}

func (recorder *streamRecorder) statusCode() int {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.status
}

func (recorder *streamRecorder) bodyString() string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.body.String()
}

func newUITestServer(t *testing.T) (*Server, *storage.Store, *identity.Services, identity.BootstrapResult) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.Open(root)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	bootstrap, err := identities.Bootstrap(context.Background(), identity.BootstrapInput{Username: "operator", Email: "operator@example.test", DisplayName: "Operator", Password: "correct horse battery staple"})
	if err != nil {
		identities.Close()
		store.Close()
		t.Fatal(err)
	}
	server, err := New(store, identities, testOptions())
	if err != nil {
		identities.Close()
		store.Close()
		t.Fatal(err)
	}
	server.now = func() time.Time { return time.Date(2026, 8, 17, 7, 30, 0, 0, time.UTC) }
	return server, store, identities, bootstrap
}

func newRotationTestServer(t *testing.T) (*Server, *storage.Store, *identity.Services, identity.BootstrapResult) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.Open(root)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	bootstrap, err := identities.Bootstrap(t.Context(), identity.BootstrapInput{Username: "operator", Email: "operator@example.test", DisplayName: "Operator", Password: "temporary correct horse battery staple", RequirePasswordChange: true})
	if err != nil {
		identities.Close()
		store.Close()
		t.Fatal(err)
	}
	server, err := New(store, identities, testOptions())
	if err != nil {
		identities.Close()
		store.Close()
		t.Fatal(err)
	}
	server.now = func() time.Time { return time.Date(2026, 8, 18, 5, 30, 0, 0, time.UTC) }
	return server, store, identities, bootstrap
}

func loginHTML(t *testing.T, handler http.Handler) *http.Cookie {
	t.Helper()
	result := loginHTMLResponse(t, handler, "operator", "correct horse battery staple")
	if result.Code != http.StatusSeeOther || result.Header().Get("Location") != "/app/" {
		t.Fatalf("login status=%d location=%q body=%s", result.Code, result.Header().Get("Location"), result.Body.String())
	}
	for _, cookie := range result.Result().Cookies() {
		if cookie.Name == "__Host-observatory_session" && cookie.Secure && cookie.HttpOnly && cookie.SameSite == http.SameSiteStrictMode {
			return cookie
		}
	}
	t.Fatalf("login cookies=%+v", result.Result().Cookies())
	return nil
}

func loginHTMLResponse(t *testing.T, handler http.Handler, identifier, password string) *httptest.ResponseRecorder {
	t.Helper()
	csrfCookie, csrfToken := loginFormCSRF(t, handler)
	form := url.Values{"csrf_token": []string{csrfToken}, "identifier": []string{identifier}, "password": []string{password}}.Encode()
	headers := http.Header{"Origin": []string{"https://observatory.example"}, "Content-Type": []string{"application/x-www-form-urlencoded; charset=utf-8"}}
	return perform(handler, http.MethodPost, "https://observatory.example/login/", strings.NewReader(form), []*http.Cookie{csrfCookie}, headers)
}

func loginFormCSRF(t *testing.T, handler http.Handler) (*http.Cookie, string) {
	t.Helper()
	page := perform(handler, http.MethodGet, "https://observatory.example/login/", nil, nil)
	if page.Code != http.StatusOK {
		t.Fatalf("login page status=%d body=%s", page.Code, page.Body.String())
	}
	var csrfCookie *http.Cookie
	for _, cookie := range page.Result().Cookies() {
		if cookie.Name == loginCSRFCookieName {
			csrfCookie = cookie
			break
		}
	}
	if csrfCookie == nil || !csrfCookie.Secure || !csrfCookie.HttpOnly || csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("login CSRF cookie=%+v", csrfCookie)
	}
	const marker = `name="csrf_token" value="`
	start := strings.Index(page.Body.String(), marker)
	if start < 0 {
		t.Fatalf("login page omitted CSRF token: %s", page.Body.String())
	}
	start += len(marker)
	end := strings.IndexByte(page.Body.String()[start:], '"')
	if end < 0 {
		t.Fatal("login page CSRF token is unterminated")
	}
	token := page.Body.String()[start : start+end]
	if token == "" || token != csrfCookie.Value {
		t.Fatal("login form and cookie CSRF tokens differ")
	}
	return csrfCookie, token
}

func perform(handler http.Handler, method, target string, body io.Reader, cookies []*http.Cookie, headerSets ...http.Header) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, body)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	for _, headers := range headerSets {
		for name, values := range headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
	}
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, request)
	return result
}
