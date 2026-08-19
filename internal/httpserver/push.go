// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"crypto/ecdh"
	"encoding/base64"
	"net/http"

	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/storage"
	"gamertan.com/observatory/internal/webpush"
	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/authhttp"
	"gamertan.com/web/websec"
)

type pushSubscriptionRequest struct {
	OrganizationID string `json:"organization_id"`
	Endpoint       string `json:"endpoint"`
	Keys           struct {
		P256DH string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

func (s *Server) savePushSubscription(w http.ResponseWriter, r *http.Request) {
	request, principal, ok := s.authorizePushRequest(w, r)
	if !ok {
		return
	}
	p256dh, p256Err := base64.RawURLEncoding.DecodeString(request.Keys.P256DH)
	authSecret, authErr := base64.RawURLEncoding.DecodeString(request.Keys.Auth)
	if p256Err != nil || authErr != nil || len(p256dh) != 65 || len(authSecret) != 16 {
		writeProblem(w, http.StatusUnprocessableEntity, "push subscription rejected")
		return
	}
	if _, err := ecdh.P256().NewPublicKey(p256dh); err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "push subscription rejected")
		return
	}
	if _, err := webpush.ValidateEndpoint(request.Endpoint); err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "push subscription rejected")
		return
	}
	subscription, err := s.store.SavePushSubscription(r.Context(), storage.PushSubscriptionInput{OrganizationID: request.OrganizationID, UserID: principal.User.ID, Endpoint: request.Endpoint, P256DH: p256dh, Auth: authSecret}, s.now())
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "push subscription rejected")
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		ID string `json:"id"`
	}{subscription.ID})
}

func (s *Server) deletePushSubscription(w http.ResponseWriter, r *http.Request) {
	request, principal, ok := s.authorizePushRequest(w, r)
	if !ok {
		return
	}
	if _, err := webpush.ValidateEndpoint(request.Endpoint); err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "push subscription rejected")
		return
	}
	remaining, err := s.store.DeletePushSubscription(r.Context(), request.OrganizationID, principal.User.ID, request.Endpoint)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "push subscription not found")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Remaining bool `json:"remaining"`
	}{remaining})
}

func (s *Server) pushSubscriptionStatus(w http.ResponseWriter, r *http.Request) {
	request, principal, ok := s.authorizePushRequest(w, r)
	if !ok {
		return
	}
	if _, err := webpush.ValidateEndpoint(request.Endpoint); err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "push subscription rejected")
		return
	}
	subscribed, err := s.store.HasPushSubscription(r.Context(), request.OrganizationID, principal.User.ID, request.Endpoint)
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "push subscription status unavailable")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Subscribed bool `json:"subscribed"`
	}{subscribed})
}

func (s *Server) authorizePushRequest(w http.ResponseWriter, r *http.Request) (pushSubscriptionRequest, auth.Principal, bool) {
	if s.options.PushDispatcher == nil {
		writeProblem(w, http.StatusNotFound, "Web Push is not configured")
		return pushSubscriptionRequest{}, auth.Principal{}, false
	}
	if !websec.SameOrigin(r, s.options.PublicOrigin) {
		writeProblem(w, http.StatusForbidden, "same-origin request required")
		return pushSubscriptionRequest{}, auth.Principal{}, false
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "authentication required")
		return pushSubscriptionRequest{}, auth.Principal{}, false
	}
	body := http.MaxBytesReader(w, r.Body, 8<<10)
	defer body.Close()
	var request pushSubscriptionRequest
	if err := decodeOne(body, &request); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid push subscription request")
		return pushSubscriptionRequest{}, auth.Principal{}, false
	}
	scope := access.Scope{OrganizationID: request.OrganizationID}
	decision, err := s.identity.Access.Authorize(r.Context(), principal.User.ID, scope, identity.PermissionIncidentsRead)
	if err != nil || !decision.Allowed {
		writeProblem(w, http.StatusForbidden, "incident access denied")
		return pushSubscriptionRequest{}, auth.Principal{}, false
	}
	if err = s.identity.ValidateResourceScope(r.Context(), scope); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid organization")
		return pushSubscriptionRequest{}, auth.Principal{}, false
	}
	token, sessionOK := authhttp.SessionToken(r, s.cookie)
	if !sessionOK || !authhttp.VerifyCSRF(token, "push:manage", r.Header.Get("X-CSRF-Token")) {
		writeProblem(w, http.StatusForbidden, "valid push CSRF token required")
		return pushSubscriptionRequest{}, auth.Principal{}, false
	}
	return request, principal, true
}
