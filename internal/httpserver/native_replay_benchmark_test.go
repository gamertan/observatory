// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/nativeprotocol"
	"gamertan.com/observatory/internal/storage"
)

func BenchmarkNativeExactReplay(b *testing.B) {
	root := filepath.Join(b.TempDir(), "data")
	if err := os.Mkdir(root, 0o700); err != nil {
		b.Fatal(err)
	}
	store, err := storage.Open(root)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	identities, err := identity.Open(root)
	if err != nil {
		b.Fatal(err)
	}
	defer identities.Close()
	token, err := store.CreateSource(context.Background(), "source", model.Scope{OrganizationID: "org", ProjectID: "project", EnvironmentID: "production", ServiceID: "service"})
	if err != nil {
		b.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 20, 0, 0, 0, time.UTC)
	server, err := New(store, identities, testOptions())
	if err != nil {
		b.Fatal(err)
	}
	server.now = func() time.Time { return now }
	handler := server.Handler()

	legacy := model.Batch{Version: model.BatchVersion, SourceID: "source", StreamID: "legacy", Sequence: 1, ObservedAt: now, Signal: model.SignalLogs, Records: benchmarkRecords(now)}
	legacyBody, _ := json.Marshal(legacy)
	framed := legacy
	framed.StreamID = "framed"
	framedBody, _ := json.Marshal(framed)
	framedEnvelope, _ := framed.Envelope(framedBody)
	seed := func(path string, body []byte, envelope *model.BatchEnvelope) {
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		if envelope != nil {
			nativeprotocol.SetHeaders(request.Header, *envelope)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			b.Fatalf("seed %s: %d %s", path, response.Code, response.Body.String())
		}
	}
	seed("/api/v1/ingest/native", legacyBody, nil)
	seed("/api/v2/ingest/native", framedBody, &framedEnvelope)

	for _, benchmark := range []struct {
		name     string
		path     string
		body     []byte
		envelope *model.BatchEnvelope
	}{{"legacy-v1", "/api/v1/ingest/native", legacyBody, nil}, {"framed-v2", "/api/v2/ingest/native", framedBody, &framedEnvelope}} {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(benchmark.body)))
			for range b.N {
				request := httptest.NewRequest(http.MethodPost, benchmark.path, bytes.NewReader(benchmark.body))
				request.Header.Set("Authorization", "Bearer "+token)
				request.Header.Set("Content-Type", "application/json")
				if benchmark.envelope != nil {
					nativeprotocol.SetHeaders(request.Header, *benchmark.envelope)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusAccepted {
					b.Fatalf("status=%d body=%s", response.Code, response.Body.String())
				}
			}
		})
	}
}

func benchmarkRecords(now time.Time) []model.Observation {
	records := make([]model.Observation, 500)
	for index := range records {
		records[index] = model.Observation{Timestamp: now, Name: "http.request", Attributes: map[string]string{"route": "/items", "status": "200", "method": "GET"}}
	}
	return records
}
