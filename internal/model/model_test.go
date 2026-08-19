// SPDX-License-Identifier: AGPL-3.0-only

package model

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestBatchEnvelopeBindsTransportAndTimePartitionHints(t *testing.T) {
	now := time.Date(2026, 8, 18, 20, 0, 0, 0, time.UTC)
	batch := Batch{Version: BatchVersion, SourceID: "source", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: SignalLogs, Records: []Observation{{Timestamp: now, Name: "latest"}, {Timestamp: now.Add(-time.Hour), Name: "earliest"}}}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := batch.Envelope(body)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.RecordCount != 2 || envelope.EncodedBytes != int64(len(body)) || envelope.FirstObservedAt != now.Add(-time.Hour) || envelope.LastObservedAt != now || envelope.WireDigest != envelope.BatchDigest {
		t.Fatalf("envelope=%+v", envelope)
	}
	if err = envelope.Match(batch, body); err != nil {
		t.Fatal(err)
	}
	padded := append([]byte(" \n"), body...)
	paddedEnvelope, err := batch.Envelope(padded)
	if err != nil || paddedEnvelope.WireDigest == envelope.WireDigest || paddedEnvelope.BatchDigest != envelope.BatchDigest || paddedEnvelope.EncodedBytes != int64(len(padded)) {
		t.Fatalf("padded=%+v err=%v", paddedEnvelope, err)
	}
	if err = envelope.Match(batch, padded); err == nil {
		t.Fatal("transport mutation was accepted")
	}
	// Overlapping time ranges are valid metadata, not a uniqueness key.
	batch.Sequence = 2
	batch.Records = []Observation{{Timestamp: now.Add(-30 * time.Minute), Name: "overlap"}}
	body, _ = json.Marshal(batch)
	if overlap, overlapErr := batch.Envelope(body); overlapErr != nil || overlap.FirstObservedAt != now.Add(-30*time.Minute) {
		t.Fatalf("overlap=%+v err=%v", overlap, overlapErr)
	}
}

func TestBatchDigestIsCanonicalAndContentBound(t *testing.T) {
	now := time.Date(2026, 8, 17, 18, 0, 0, 0, time.UTC)
	left := Batch{Version: BatchVersion, SourceID: "source", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: SignalLogs, Records: []Observation{{Timestamp: now, Name: "request", Attributes: map[string]string{"z": "last", "a": "first"}}}}
	right := left
	right.Records = []Observation{{Timestamp: now, Name: "request", Attributes: map[string]string{"a": "first", "z": "last"}}}
	leftDigest, err := left.Digest()
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := right.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest || len(leftDigest) != 64 || strings.Trim(leftDigest, "0123456789abcdef") != "" {
		t.Fatalf("left=%q right=%q", leftDigest, rightDigest)
	}
	right.Records[0].Name = "changed"
	changed, err := right.Digest()
	if err != nil || changed == leftDigest {
		t.Fatalf("changed=%q err=%v", changed, err)
	}
}

func validBatch(now time.Time) Batch {
	v := 1.5
	return Batch{Version: 1, SourceID: "src_1", StreamID: "metrics", Sequence: 1, ObservedAt: now, Signal: SignalMetrics, Records: []Observation{{Timestamp: now, Name: "http.duration", Value: &v, Attributes: map[string]string{"route": "/"}}}}
}

func TestBatchRejectsDistinctFieldCardinalityAbuse(t *testing.T) {
	now := time.Now().UTC()
	batch := Batch{Version: BatchVersion, SourceID: "source", StreamID: "logs", Sequence: 1, ObservedAt: now, Signal: SignalLogs}
	for recordIndex := 0; recordIndex < 17; recordIndex++ {
		record := Observation{Timestamp: now, Name: "record", Attributes: map[string]string{}}
		for fieldIndex := 0; fieldIndex < MaxAttributes; fieldIndex++ {
			record.Attributes[fmt.Sprintf("field.%d.%d", recordIndex, fieldIndex)] = "value"
		}
		batch.Records = append(batch.Records, record)
	}
	if err := batch.Validate(now); err == nil || !strings.Contains(err.Error(), "distinct attribute fields") {
		t.Fatalf("cardinality abuse err=%v", err)
	}
}

func TestBatchValidation(t *testing.T) {
	now := time.Now().UTC()
	if err := validBatch(now).Validate(now); err != nil {
		t.Fatal(err)
	}
	b := validBatch(now)
	b.SourceID = "../../tenant"
	if err := b.Validate(now); err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("expected path-like ID rejection, got %v", err)
	}
	b = validBatch(now)
	b.Records[0].Attributes["secret"] = strings.Repeat("x", MaxAttributeValue+1)
	if err := b.Validate(now); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected attribute bound, got %v", err)
	}
}

func TestBatchClockSkewAndRetentionWindowsFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*Batch){
		"old batch":      func(batch *Batch) { batch.ObservedAt = now.Add(-7*24*time.Hour - time.Nanosecond) },
		"future batch":   func(batch *Batch) { batch.ObservedAt = now.Add(10*time.Minute + time.Nanosecond) },
		"old record":     func(batch *Batch) { batch.Records[0].Timestamp = now.Add(-400*24*time.Hour - time.Nanosecond) },
		"future record":  func(batch *Batch) { batch.Records[0].Timestamp = now.Add(10*time.Minute + time.Nanosecond) },
		"zero observed":  func(batch *Batch) { batch.ObservedAt = time.Time{} },
		"zero timestamp": func(batch *Batch) { batch.Records[0].Timestamp = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			batch := validBatch(now)
			mutate(&batch)
			if err := batch.Validate(now); err == nil {
				t.Fatal("out-of-window telemetry was accepted")
			}
		})
	}
}

func TestObservationRejectsUnsafeIdentifiersAndNonFiniteValues(t *testing.T) {
	now := time.Now().UTC()
	nan := math.NaN()
	base := Batch{Version: BatchVersion, SourceID: "source", StreamID: "stream", Sequence: 1, ObservedAt: now, Signal: SignalLogs, Records: []Observation{{Timestamp: now, Name: "record"}}}
	for name, mutate := range map[string]func(*Observation){
		"trace":       func(record *Observation) { record.TraceID = "ABC" },
		"span":        func(record *Observation) { record.SpanID = strings.Repeat("g", 16) },
		"correlation": func(record *Observation) { record.CorrelationID = strings.Repeat("x", 129) },
		"value":       func(record *Observation) { record.Value = &nan },
	} {
		t.Run(name, func(t *testing.T) {
			batch := base
			batch.Records = append([]Observation(nil), base.Records...)
			mutate(&batch.Records[0])
			if err := batch.Validate(now); err == nil {
				t.Fatal("unsafe observation accepted")
			}
		})
	}
}
