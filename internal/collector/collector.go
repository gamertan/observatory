// SPDX-License-Identifier: AGPL-3.0-only

package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gamertan.com/observatory/internal/model"
)

const MaxLineBytes = 1 << 20

var tendSafeValue = regexp.MustCompile(`^[A-Za-z0-9._:/@+-]{1,256}$`)
var tendOperationID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var tendArtifactDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var tendCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

func Parse(kind string, line []byte, fallback time.Time, sensitiveFields ...string) (model.Signal, model.Observation, error) {
	if len(line) == 0 || len(line) > MaxLineBytes || !utf8.Valid(line) || bytes.IndexByte(line, 0) >= 0 {
		return "", model.Observation{}, errors.New("collector line is outside accepted bounds")
	}
	switch kind {
	case "caddy_json":
		observation, err := parseCaddy(line, fallback, sensitiveFields)
		return model.SignalLogs, observation, err
	case "requestlog_jsonl":
		observation, err := parseRequestLog(line, fallback, sensitiveFields)
		return model.SignalLogs, observation, err
	case "tend_events_jsonl":
		observation, err := parseTend(line, fallback)
		return model.SignalDeployments, observation, err
	default:
		return "", model.Observation{}, errors.New("unsupported collector kind")
	}
}

func parseCaddy(line []byte, fallback time.Time, sensitiveFields []string) (model.Observation, error) {
	var record struct {
		Timestamp float64 `json:"ts"`
		Status    int     `json:"status"`
		Size      int64   `json:"size"`
		Duration  float64 `json:"duration"`
		RequestID string  `json:"request_id"`
		ClientIP  string  `json:"client_ip"`
		Referrer  string  `json:"referrer"`
		UserAgent string  `json:"user_agent"`
		Request   struct {
			Method  string              `json:"method"`
			URI     string              `json:"uri"`
			Headers map[string][]string `json:"headers"`
		} `json:"request"`
	}
	if err := json.Unmarshal(line, &record); err != nil {
		return model.Observation{}, errors.New("invalid Caddy JSON record")
	}
	timestamp := fallback
	if record.Timestamp > 0 {
		seconds, fraction := mathModf(record.Timestamp)
		timestamp = time.Unix(seconds, int64(fraction*1e9)).UTC()
	}
	path := "/"
	parsed, parseErr := url.ParseRequestURI(record.Request.URI)
	if parseErr == nil && parsed.Path != "" {
		path = parsed.EscapedPath()
	}
	attributes := map[string]string{
		"http.method":         bounded(record.Request.Method, 32),
		"http.path":           bounded(path, 4096),
		"http.status_code":    strconv.Itoa(record.Status),
		"http.response_bytes": strconv.FormatInt(record.Size, 10),
		"duration_ns":         strconv.FormatInt(int64(record.Duration*1e9), 10),
	}
	requestID := record.RequestID
	if !safeIdentifier(requestID) {
		requestID = firstHeader(record.Request.Headers, "X-Request-Id", "X-Request-ID")
	}
	if safeIdentifier(requestID) {
		attributes["request.id"] = requestID
	}
	selected := sensitiveFieldSet(sensitiveFields)
	if selected["client_ip"] {
		if address, err := netip.ParseAddr(record.ClientIP); err == nil && address.IsValid() && address.Zone() == "" {
			attributes["client.address"] = address.String()
		}
	}
	if selected["query"] && parseErr == nil && parsed.RawQuery != "" {
		attributes["url.query"] = bounded(parsed.RawQuery, 4096)
	}
	if selected["referrer"] {
		if value := boundedSensitive(record.Referrer, 4096); value != "" {
			attributes["http.request.referrer"] = value
		}
	}
	if selected["user_agent"] {
		if value := boundedSensitive(record.UserAgent, 1024); value != "" {
			attributes["user_agent.original"] = value
		}
	}
	return model.Observation{Timestamp: timestamp, Name: "caddy.http.request", CorrelationID: attributes["request.id"], Attributes: attributes}, nil
}

func parseRequestLog(line []byte, fallback time.Time, sensitiveFields []string) (model.Observation, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return model.Observation{}, errors.New("invalid requestlog JSON record")
	}
	timestamp := parseTimeFields(raw, fallback, "observed_at", "timestamp", "time")
	attributes := map[string]string{}
	copyString(raw, attributes, "method", "http.method", 32)
	copyString(raw, attributes, "route", "http.route", 4096)
	copyNumber(raw, attributes, "status", "http.status_code")
	copyNumber(raw, attributes, "bytes", "http.response_bytes")
	copyNumber(raw, attributes, "duration_ns", "duration_ns")
	copyString(raw, attributes, "authorization_outcome", "auth.outcome", 128)
	requestID := rawString(raw["request_id"], 128)
	if safeIdentifier(requestID) {
		attributes["request.id"] = requestID
	}
	selected := sensitiveFieldSet(sensitiveFields)
	if selected["client_ip"] {
		if address, err := netip.ParseAddr(rawString(raw["client_ip"], 64)); err == nil && address.IsValid() && address.Zone() == "" {
			attributes["client.address"] = address.String()
		}
	}
	if selected["query"] {
		copyString(raw, attributes, "query", "url.query", 4096)
	}
	if selected["referrer"] {
		copyString(raw, attributes, "referer", "http.request.referrer", 2048)
	}
	if selected["user_agent"] {
		copyString(raw, attributes, "user_agent", "user_agent.original", 1024)
	}
	if selected["session_id"] {
		copyString(raw, attributes, "session_id", "session.id", 256)
	}
	return model.Observation{Timestamp: timestamp, Name: "application.http.request", CorrelationID: requestID, Attributes: attributes}, nil
}

func sensitiveFieldSet(fields []string) map[string]bool {
	selected := make(map[string]bool, len(fields))
	for _, field := range fields {
		selected[field] = true
	}
	return selected
}

func boundedSensitive(value string, maximum int) string {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return ""
	}
	return value
}

func parseTend(line []byte, _ time.Time) (model.Observation, error) {
	if len(line) > 4096 {
		return model.Observation{}, errors.New("invalid Tend deployment event")
	}
	var record tendEvent
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.validate() != nil {
		return model.Observation{}, errors.New("invalid Tend deployment event")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return model.Observation{}, errors.New("invalid Tend deployment event")
	}
	timestamp, _ := time.Parse(time.RFC3339Nano, record.ObservedAt)
	attributes := map[string]string{
		"deployment.operation_id": record.OperationID,
		"service.name":            record.Service,
		"deployment.artifact":     record.ArtifactDigest,
		"deployment.commit":       record.Commit,
		"deployment.version":      record.ReleaseVersion,
		"deployment.phase":        record.Phase,
		"deployment.duration_ms":  strconv.FormatInt(record.DurationMillis, 10),
		"deployment.outcome":      record.Outcome,
	}
	if record.Slot != "" {
		attributes["deployment.slot"] = record.Slot
	}
	return model.Observation{Timestamp: timestamp.UTC(), Name: "tend.deployment", CorrelationID: record.OperationID, Attributes: attributes}, nil
}

type tendEvent struct {
	Version        int    `json:"version"`
	OperationID    string `json:"operation_id"`
	Service        string `json:"service"`
	ArtifactDigest string `json:"artifact_digest"`
	Commit         string `json:"commit"`
	ReleaseVersion string `json:"release_version"`
	Phase          string `json:"phase"`
	Slot           string `json:"slot"`
	DurationMillis int64  `json:"duration_ms"`
	Outcome        string `json:"outcome"`
	ObservedAt     string `json:"observed_at"`
}

func (event tendEvent) validate() error {
	if event.Version != 1 || !tendOperationID.MatchString(event.OperationID) || !tendArtifactDigest.MatchString(event.ArtifactDigest) || !tendCommit.MatchString(event.Commit) {
		return errors.New("identity or provenance is invalid")
	}
	for _, value := range []string{event.Service, event.ArtifactDigest, event.Commit, event.ReleaseVersion, event.Phase, event.Outcome} {
		if !tendSafeValue.MatchString(value) || strings.ContainsRune(value, '\x00') {
			return errors.New("value is invalid")
		}
	}
	if event.Slot != "" && !tendSafeValue.MatchString(event.Slot) {
		return errors.New("slot is invalid")
	}
	if event.DurationMillis < 0 {
		return errors.New("duration is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, event.ObservedAt); err != nil {
		return errors.New("timestamp is invalid")
	}
	return nil
}

func copyString(raw map[string]json.RawMessage, attributes map[string]string, source, target string, maximum int) {
	if value := rawString(raw[source], maximum); value != "" {
		attributes[target] = value
	}
}

func copyNumber(raw map[string]json.RawMessage, attributes map[string]string, source, target string) {
	value := strings.TrimSpace(string(raw[source]))
	if value == "" || len(value) > 64 {
		return
	}
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		attributes[target] = value
	}
}

func rawString(raw json.RawMessage, maximum int) string {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || len(value) > maximum || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return ""
	}
	return value
}

func parseTimeFields(raw map[string]json.RawMessage, fallback time.Time, names ...string) time.Time {
	for _, name := range names {
		value := rawString(raw[name], 128)
		if value == "" {
			continue
		}
		if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return parsed.UTC()
		}
	}
	return fallback.UTC()
}

func firstHeader(headers map[string][]string, names ...string) string {
	for _, name := range names {
		for key, values := range headers {
			if strings.EqualFold(key, name) && len(values) == 1 {
				return values[0]
			}
		}
	}
	return ""
}

func safeIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

func bounded(value string, maximum int) string {
	if len(value) > maximum {
		for maximum > 0 && !utf8.ValidString(value[:maximum]) {
			maximum--
		}
		return value[:maximum]
	}
	return value
}

func mathModf(value float64) (int64, float64) {
	seconds := int64(value)
	return seconds, value - float64(seconds)
}
