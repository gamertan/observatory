//go:build observatory_browser_fixture

// SPDX-License-Identifier: AGPL-3.0-only

// Command browsertest serves a disposable HTTPS Observatory instance for the
// real-browser verification campaign. It is excluded from ordinary builds.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gamertan.com/observatory/internal/httpserver"
	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/storage"
)

const (
	fixtureUsername = "browser-operator"
	fixturePassword = "browser-fixture-password"
)

type pushDispatcher struct{}

func (pushDispatcher) Enqueue(string) bool { return true }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "browser fixture failed:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := os.MkdirTemp("", "observatory-browser-fixture-")
	if err != nil {
		return errors.New("create browser fixture root")
	}
	defer os.RemoveAll(root)
	if err = os.Chmod(root, 0o700); err != nil {
		return errors.New("protect browser fixture root")
	}

	certificate, spki, err := localCertificate()
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
	if err != nil {
		return errors.New("listen for browser fixture")
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return errors.New("read browser fixture listener")
	}
	origin := "https://localhost:" + port

	store, err := storage.Open(filepath.Join(root, "data"))
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(filepath.Join(root, "data"))
	if err != nil {
		return err
	}
	defer identities.Close()
	bootstrap, err := identities.Bootstrap(context.Background(), identity.BootstrapInput{
		Username: fixtureUsername, Email: "browser@example.test", DisplayName: "Browser Operator", Password: fixturePassword,
	})
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	scope := model.Scope{OrganizationID: bootstrap.Organization.ID, ProjectID: "browser-project", EnvironmentID: "test", ServiceID: "browser-service"}
	token, err := store.CreateSource(context.Background(), "browser-source", scope)
	if err != nil {
		return err
	}
	if _, err = store.Ingest(context.Background(), token, logBatch(1, now), now); err != nil {
		return err
	}
	if err = store.Recover(context.Background()); err != nil {
		return err
	}
	saved, err := store.SaveQuery(context.Background(), storage.SavedQueryInput{
		OrganizationID: scope.OrganizationID, Name: "Browser fixture evidence", Description: "Exact browser-campaign evidence.",
		Query: "logs | window 1h | limit 10", ActorUserID: bootstrap.User.ID, MaxRows: 100,
	}, now)
	if err != nil {
		return err
	}
	if _, err = store.SaveAlertRule(context.Background(), storage.AlertRuleInput{
		OrganizationID: scope.OrganizationID, Name: "Browser fixture incident", Description: "Exercises the private offline incident boundary.",
		SavedQueryID: saved.ID, Severity: "critical", MinimumMatches: 1, RequiredConsecutive: 1,
		EvaluationInterval: 15 * time.Second, Enabled: true, ActorUserID: bootstrap.User.ID,
	}, now); err != nil {
		return err
	}

	vapid, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("create browser fixture Web Push key")
	}
	server, err := httpserver.New(store, identities, httpserver.Options{
		PublicOrigin: origin, MaxBodyBytes: 1 << 20, MaxQueryRows: 100,
		QueryBudget:     query.Budget{MaxDuration: 2 * time.Second, MaxRows: 100, MaxScannedBytes: 32 << 20, MaxMemoryBytes: 16 << 20},
		SessionLifetime: time.Hour, PushPublicKey: base64.RawURLEncoding.EncodeToString(vapid.PublicKey().Bytes()), PushDispatcher: pushDispatcher{},
	})
	if err != nil {
		return err
	}
	if _, err = server.EvaluateAlerts(context.Background()); err != nil {
		return err
	}
	handler := browserFixture(server.Handler())
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- httpServer.Serve(listener) }()

	updatesDone := make(chan struct{})
	defer close(updatesDone)
	go publishUpdates(handler, origin, token, updatesDone)

	fmt.Println(origin)
	fmt.Println(spki)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-signals:
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdown)
	case serveErr := <-serveErrors:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return serveErr
	}
}

// browserFixture bounds the fixture EventSource connection so the browser
// campaign can prove native reconnection. It does not alter request origin
// metadata; form submissions exercise the production token-bound policy.
func browserFixture(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/events" {
			ctx, cancel := context.WithTimeout(r.Context(), 1250*time.Millisecond)
			defer cancel()
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func logBatch(sequence uint64, observed time.Time) model.Batch {
	return model.Batch{Version: model.BatchVersion, SourceID: "browser-source", StreamID: "browser-stream", Sequence: sequence, ObservedAt: observed, Signal: model.SignalLogs, Records: []model.Observation{{
		Timestamp: observed, Name: "browser.fixture", Severity: "information", Body: "bounded browser fixture observation",
		Attributes: map[string]string{"http.route": "/browser-fixture", "http.status_code": "200"},
	}}}
}

func publishUpdates(handler http.Handler, origin, token string, done <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	sequence := uint64(2)
	for {
		select {
		case <-done:
			return
		case observed := <-ticker.C:
			body, err := json.Marshal(logBatch(sequence, observed.UTC()))
			if err != nil {
				return
			}
			request := httptest.NewRequest(http.MethodPost, origin+"/api/v1/ingest/native", bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code == http.StatusAccepted {
				sequence++
			}
		}
	}
}

func localCertificate() (tls.Certificate, string, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", errors.New("create local TLS key")
	}
	maximum := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, maximum)
	if err != nil {
		return tls.Certificate{}, "", errors.New("create local TLS serial")
	}
	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Observatory browser fixture"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &private.PublicKey, private)
	if err != nil {
		return tls.Certificate{}, "", errors.New("create local TLS certificate")
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return tls.Certificate{}, "", errors.New("encode local TLS key")
	}
	encodedPublic, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return tls.Certificate{}, "", errors.New("encode local TLS public key")
	}
	digest := sha256.Sum256(encodedPublic)
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}),
	)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return certificate, base64.StdEncoding.EncodeToString(digest[:]), nil
}
