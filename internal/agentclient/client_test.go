// SPDX-License-Identifier: AGPL-3.0-only

package agentclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/httpserver"
	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/nativeprotocol"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/storage"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestSendRequiresMatchingAcknowledgementAndDoesNotRedirect(t *testing.T) {
	credential := "obs1.source." + strings.Repeat("a", 64)
	var authorization, path string
	client, err := New("https://observatory.example", credential, transportFunc(func(request *http.Request) (*http.Response, error) {
		authorization = request.Header.Get("Authorization")
		path = request.URL.Path
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		digest := sha256.Sum256(body)
		if request.Header.Get(nativeprotocol.WireDigestHeader) != hex.EncodeToString(digest[:]) || request.Header.Get(nativeprotocol.StreamHeader) != "access" || request.Header.Get(nativeprotocol.SequenceHeader) != "1" {
			t.Fatalf("missing framed batch metadata: %v", request.Header)
		}
		response := fmt.Sprintf(`{"source_id":"source","stream_id":"access","sequence":1,"digest":"%s","batch_digest":"%s","duplicate":false}`, strings.Repeat("a", 64), hex.EncodeToString(digest[:]))
		return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request"}}}
	if _, err := client.Send(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if authorization != "Bearer "+credential || path != "/api/v2/ingest/native" {
		t.Fatalf("authorization=%q path=%q", authorization, path)
	}
}

func TestSendAcceptsRealServerBatchDigestRatherThanPrivateSegmentDigest(t *testing.T) {
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
	token, err := store.CreateSource(context.Background(), "source", model.Scope{OrganizationID: "organization", ProjectID: "project", EnvironmentID: "production", ServiceID: "service"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := httpserver.New(store, identities, httpserver.Options{
		PublicOrigin: "https://observatory.example", MaxBodyBytes: 1 << 20, MaxQueryRows: 100,
		QueryBudget: query.Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 1 << 20, MaxMemoryBytes: 1 << 20}, SessionLifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := New("https://observatory.example", token, transportFunc(func(request *http.Request) (*http.Response, error) {
		request.RemoteAddr = "127.0.0.1:40000"
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response.Result(), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request"}}}
	ack, err := client.Send(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := batch.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if ack.BatchDigest != expected || ack.Digest == ack.BatchDigest {
		t.Fatalf("ack=%+v expected batch digest=%s", ack, expected)
	}
}

func TestSendRejectsMismatchedAcknowledgementWithoutEchoingBody(t *testing.T) {
	credential := "obs1.source." + strings.Repeat("a", 64)
	client, err := New("https://observatory.example", credential, transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"source_id":"source","stream_id":"access","sequence":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","batch_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := model.Batch{Version: 1, SourceID: "source", StreamID: "access", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now, Name: "request", Body: "do-not-echo"}}}
	_, err = client.Send(context.Background(), batch)
	if err == nil || strings.Contains(err.Error(), "do-not-echo") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendAlertTransitionUsesExactEndpointAndRejectsMismatchedAcknowledgement(t *testing.T) {
	credential := "obs1.source." + strings.Repeat("a", 64)
	now := time.Date(2026, 8, 18, 23, 50, 0, 0, time.UTC)
	transition := model.AlertTransition{Version: model.AlertTransitionVersion, RuleID: "rule-a", RuleRevision: 2, AgentEpoch: strings.Repeat("b", 32), Sequence: 3, StreamID: "requests", BatchSequence: 8, SegmentDigest: strings.Repeat("c", 64), WindowStart: now.Add(-time.Minute), WindowEnd: now, State: "matched", ObservedAt: now}
	digest, err := transition.Digest()
	if err != nil {
		t.Fatal(err)
	}
	var path, authorization string
	client, err := New("https://observatory.example", credential, transportFunc(func(request *http.Request) (*http.Response, error) {
		path = request.URL.Path
		authorization = request.Header.Get("Authorization")
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil || !strings.Contains(string(body), `"segment_digest":"`+transition.SegmentDigest+`"`) {
			t.Fatalf("body=%q err=%v", string(body), readErr)
		}
		response := fmt.Sprintf(`{"source_id":"source","rule_id":"rule-a","rule_revision":2,"agent_epoch":"%s","sequence":3,"digest":"%s","duplicate":false}`, transition.AgentEpoch, digest)
		return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	ack, err := client.SendAlertTransition(context.Background(), transition)
	if err != nil || ack.Digest != digest || path != "/api/v1/agent/alert-transition" || authorization != "Bearer "+credential {
		t.Fatalf("ack=%+v path=%q authorization=%q err=%v", ack, path, authorization, err)
	}

	mismatch, err := New("https://observatory.example", credential, transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"source_id":"source","rule_id":"rule-a","rule_revision":2,"agent_epoch":"%s","sequence":4,"digest":"%s","duplicate":false}`, transition.AgentEpoch, digest)))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mismatch.SendAlertTransition(context.Background(), transition); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatch err=%v", err)
	}
	wrongSource, err := New("https://observatory.example", credential, transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"source_id":"other","rule_id":"rule-a","rule_revision":2,"agent_epoch":"%s","sequence":3,"digest":"%s","duplicate":false}`, transition.AgentEpoch, digest)))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrongSource.SendAlertTransition(context.Background(), transition); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong source err=%v", err)
	}
}

func TestEnrollAndRevokeUseExactHTTPSEndpoints(t *testing.T) {
	enrollment := "obse1." + strings.Repeat("e", 64)
	credential := "obs1.source." + strings.Repeat("a", 64)
	var methods []string
	transport := transportFunc(func(request *http.Request) (*http.Response, error) {
		methods = append(methods, request.Method+" "+request.URL.Path)
		switch request.URL.Path {
		case "/api/v1/agent/enroll":
			if request.Header.Get("Authorization") != "Bearer "+enrollment {
				t.Fatal("enrollment authorization missing")
			}
			return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"source_id":"source","credential":"` + credential + `"}`))}, nil
		case "/api/v1/agent/source":
			if request.Header.Get("Authorization") != "Bearer "+credential {
				t.Fatal("source authorization missing")
			}
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody}, nil
		default:
			t.Fatalf("unexpected endpoint %s", request.URL.Path)
			return nil, nil
		}
	})
	result, err := Enroll(context.Background(), "https://observatory.example", enrollment, transport)
	if err != nil || result.SourceID != "source" || result.Credential != credential {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if err = RevokeSource(context.Background(), "https://observatory.example", credential, transport); err != nil {
		t.Fatal(err)
	}
	if len(methods) != 2 || methods[0] != "POST /api/v1/agent/enroll" || methods[1] != "DELETE /api/v1/agent/source" {
		t.Fatalf("methods=%v", methods)
	}
}
