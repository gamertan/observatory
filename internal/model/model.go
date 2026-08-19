// SPDX-License-Identifier: AGPL-3.0-only

package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// Digest returns the SHA-256 of the canonical JSON representation used by the
// native agent protocol. It binds an acknowledgement to the exact logical
// batch independently of either side's private compressed storage format.
func (b Batch) Digest() (string, error) {
	encoded, err := json.Marshal(b)
	if err != nil {
		return "", errors.New("encode batch digest")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

const (
	BatchVersion         = 1
	BatchEnvelopeVersion = 1
	MaxRecords           = 5_000
	MaxAttributes        = 64
	MaxAttributeKey      = 128
	MaxAttributeValue    = 4_096
	MaxName              = 256
	MaxBody              = 16_384
	MaxDistinctFields    = 1_024
)

// BatchEnvelope is the bounded transport metadata for one native batch. The
// enrolled credential supplies source and tenant scope; timestamps are useful
// partition hints and deliberately do not participate in record-level
// deduplication.
type BatchEnvelope struct {
	Version         int
	StreamID        string
	Sequence        uint64
	Signal          Signal
	WireDigest      string
	BatchDigest     string
	RecordCount     int
	EncodedBytes    int64
	FirstObservedAt time.Time
	LastObservedAt  time.Time
}

type Signal string

const (
	SignalLogs        Signal = "logs"
	SignalMetrics     Signal = "metrics"
	SignalTraces      Signal = "traces"
	SignalDeployments Signal = "deployments"
)

type Batch struct {
	Version    int           `json:"version"`
	SourceID   string        `json:"source_id"`
	StreamID   string        `json:"stream_id"`
	Sequence   uint64        `json:"sequence"`
	ObservedAt time.Time     `json:"observed_at"`
	Signal     Signal        `json:"signal"`
	Records    []Observation `json:"records"`
}

type Observation struct {
	Timestamp     time.Time         `json:"timestamp"`
	Name          string            `json:"name"`
	Severity      string            `json:"severity,omitempty"`
	Body          string            `json:"body,omitempty"`
	Value         *float64          `json:"value,omitempty"`
	TraceID       string            `json:"trace_id,omitempty"`
	SpanID        string            `json:"span_id,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

type Scope struct {
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	EnvironmentID  string `json:"environment_id"`
	ServiceID      string `json:"service_id"`
}

// Envelope returns transport metadata bound to the exact encoded body and the
// canonical logical batch. The two digests are intentionally distinct even
// when the current JSON encoder happens to produce identical bytes.
func (b Batch) Envelope(encoded []byte) (BatchEnvelope, error) {
	if len(encoded) == 0 {
		return BatchEnvelope{}, errors.New("encoded batch is empty")
	}
	batchDigest, err := b.Digest()
	if err != nil {
		return BatchEnvelope{}, err
	}
	wireDigest := sha256.Sum256(encoded)
	first, last := b.ObservationRange()
	return BatchEnvelope{
		Version:         BatchEnvelopeVersion,
		StreamID:        b.StreamID,
		Sequence:        b.Sequence,
		Signal:          b.Signal,
		WireDigest:      hex.EncodeToString(wireDigest[:]),
		BatchDigest:     batchDigest,
		RecordCount:     len(b.Records),
		EncodedBytes:    int64(len(encoded)),
		FirstObservedAt: first,
		LastObservedAt:  last,
	}, nil
}

func (b Batch) ObservationRange() (time.Time, time.Time) {
	if len(b.Records) == 0 {
		return time.Time{}, time.Time{}
	}
	first, last := b.Records[0].Timestamp.UTC(), b.Records[0].Timestamp.UTC()
	for _, record := range b.Records[1:] {
		observed := record.Timestamp.UTC()
		if observed.Before(first) {
			first = observed
		}
		if observed.After(last) {
			last = observed
		}
	}
	return first, last
}

func (e BatchEnvelope) Validate(maxEncodedBytes int64) error {
	if e.Version != BatchEnvelopeVersion {
		return errors.New("unsupported batch envelope version")
	}
	if err := ValidateStreamID(e.StreamID); err != nil {
		return err
	}
	if e.Sequence == 0 {
		return errors.New("sequence must be positive")
	}
	if !e.Signal.valid() {
		return errors.New("unsupported signal")
	}
	if !validLowerHex(e.WireDigest, sha256.Size*2) || !validLowerHex(e.BatchDigest, sha256.Size*2) {
		return errors.New("batch envelope digest is invalid")
	}
	if e.RecordCount < 1 || e.RecordCount > MaxRecords {
		return errors.New("batch envelope record count is invalid")
	}
	if e.EncodedBytes < 1 || e.EncodedBytes > maxEncodedBytes {
		return errors.New("batch envelope byte count is invalid")
	}
	if e.FirstObservedAt.IsZero() || e.LastObservedAt.IsZero() || e.LastObservedAt.Before(e.FirstObservedAt) {
		return errors.New("batch envelope time range is invalid")
	}
	return nil
}

// Match proves that the decoded batch and exact transport bytes agree with
// the agent-supplied envelope. Tenant scope remains absent by design.
func (e BatchEnvelope) Match(batch Batch, encoded []byte) error {
	if err := e.Validate(int64(len(encoded))); err != nil || e.EncodedBytes != int64(len(encoded)) {
		return errors.New("batch envelope does not match encoded body")
	}
	expected, err := batch.Envelope(encoded)
	if err != nil {
		return err
	}
	if e != expected {
		return errors.New("batch envelope does not match encoded body")
	}
	return nil
}

func (b Batch) Validate(now time.Time) error {
	if b.Version != BatchVersion {
		return fmt.Errorf("unsupported batch version %d", b.Version)
	}
	if err := validateID("source_id", b.SourceID); err != nil {
		return err
	}
	if err := validateID("stream_id", b.StreamID); err != nil {
		return err
	}
	if b.Sequence == 0 {
		return errors.New("sequence must be positive")
	}
	if !b.Signal.valid() {
		return errors.New("unsupported signal")
	}
	if b.ObservedAt.IsZero() || b.ObservedAt.Before(now.Add(-7*24*time.Hour)) || b.ObservedAt.After(now.Add(10*time.Minute)) {
		return errors.New("observed_at outside accepted clock-skew window")
	}
	if len(b.Records) == 0 || len(b.Records) > MaxRecords {
		return fmt.Errorf("records must contain between 1 and %d items", MaxRecords)
	}
	distinctFields := map[string]struct{}{}
	for i, record := range b.Records {
		if err := record.validate(b.Signal, now); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		for field := range record.Attributes {
			distinctFields[field] = struct{}{}
			if len(distinctFields) > MaxDistinctFields {
				return fmt.Errorf("batch contains more than %d distinct attribute fields", MaxDistinctFields)
			}
		}
	}
	return nil
}

func (s Signal) valid() bool {
	switch s {
	case SignalLogs, SignalMetrics, SignalTraces, SignalDeployments:
		return true
	default:
		return false
	}
}

func (o Observation) validate(signal Signal, now time.Time) error {
	if o.Timestamp.IsZero() || o.Timestamp.Before(now.Add(-400*24*time.Hour)) || o.Timestamp.After(now.Add(10*time.Minute)) {
		return errors.New("timestamp outside accepted window")
	}
	if err := validateText("name", o.Name, MaxName, false); err != nil {
		return err
	}
	if err := validateText("body", o.Body, MaxBody, true); err != nil {
		return err
	}
	if err := validateText("severity", o.Severity, 64, true); err != nil {
		return err
	}
	if o.TraceID != "" && !validLowerHex(o.TraceID, 32) {
		return errors.New("trace_id must be 16 bytes encoded as lowercase hexadecimal")
	}
	if o.SpanID != "" && !validLowerHex(o.SpanID, 16) {
		return errors.New("span_id must be 8 bytes encoded as lowercase hexadecimal")
	}
	if err := validateText("correlation_id", o.CorrelationID, 128, true); err != nil {
		return err
	}
	if signal == SignalMetrics && o.Value == nil {
		return errors.New("metric requires value")
	}
	if o.Value != nil && (math.IsNaN(*o.Value) || math.IsInf(*o.Value, 0)) {
		return errors.New("value must be finite")
	}
	if len(o.Attributes) > MaxAttributes {
		return fmt.Errorf("too many attributes: maximum %d", MaxAttributes)
	}
	for key, value := range o.Attributes {
		if err := validateText("attribute key", key, MaxAttributeKey, false); err != nil {
			return err
		}
		if err := validateText("attribute value", value, MaxAttributeValue, true); err != nil {
			return err
		}
	}
	return nil
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func (s Scope) Validate() error {
	for label, value := range map[string]string{
		"organization_id": s.OrganizationID,
		"project_id":      s.ProjectID,
		"environment_id":  s.EnvironmentID,
		"service_id":      s.ServiceID,
	} {
		if err := validateID(label, value); err != nil {
			return err
		}
	}
	return nil
}

func validateID(label, value string) error {
	if len(value) < 1 || len(value) > 128 {
		return fmt.Errorf("%s length must be between 1 and 128", label)
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return fmt.Errorf("%s contains an invalid character", label)
		}
	}
	return nil
}

func ValidateSourceID(value string) error { return validateID("source_id", value) }

func ValidateStreamID(value string) error { return validateID("stream_id", value) }

func validateText(label, value string, max int, empty bool) error {
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%s must be valid UTF-8 without NUL", label)
	}
	if !empty && value == "" {
		return fmt.Errorf("%s is required", label)
	}
	if len(value) > max {
		return fmt.Errorf("%s exceeds %d bytes", label, max)
	}
	return nil
}
