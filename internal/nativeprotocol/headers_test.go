// SPDX-License-Identifier: AGPL-3.0-only

package nativeprotocol

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
)

func TestEnvelopeHeadersRoundTripAndRejectAmbiguity(t *testing.T) {
	now := time.Date(2026, 8, 18, 20, 0, 0, 0, time.UTC)
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source", StreamID: "logs", Sequence: 7, ObservedAt: now, Signal: model.SignalLogs, Records: []model.Observation{{Timestamp: now.Add(-time.Second), Name: "first"}, {Timestamp: now, Name: "last"}}}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := batch.Envelope(body)
	if err != nil {
		t.Fatal(err)
	}
	header := make(http.Header)
	SetHeaders(header, envelope)
	parsed, err := ParseHeaders(header, 1<<20)
	if err != nil || parsed != envelope {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	header.Add(SequenceHeader, "8")
	if _, err = ParseHeaders(header, 1<<20); err == nil {
		t.Fatal("duplicate security-relevant header was accepted")
	}
}

func FuzzParseEnvelopeHeaders(f *testing.F) {
	f.Add("1", "logs", "1", "logs", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "1", "100", "2026-08-18T20:00:00Z", "2026-08-18T20:00:00Z")
	f.Fuzz(func(t *testing.T, version, stream, sequence, signal, wire, batch, count, size, first, last string) {
		header := make(http.Header)
		for name, value := range map[string]string{VersionHeader: version, StreamHeader: stream, SequenceHeader: sequence, SignalHeader: signal, WireDigestHeader: wire, BatchDigestHeader: batch, RecordCountHeader: count, EncodedBytesHeader: size, FirstObservedHeader: first, LastObservedHeader: last} {
			header.Set(name, value)
		}
		_, _ = ParseHeaders(header, 32<<20)
	})
}
