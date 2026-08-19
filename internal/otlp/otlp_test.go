// SPDX-License-Identifier: AGPL-3.0-only

package otlp

import (
	"bytes"
	"math"
	"testing"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestDecodeLogsDropsCredentialsAndPreservesTelemetry(t *testing.T) {
	now := time.Date(2026, 8, 17, 3, 0, 0, 0, time.UTC)
	request := &logspb.LogsData{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			stringAttribute("service.name", "eql"),
			stringAttribute("http.request.header.authorization", "Bearer do-not-store"),
		}},
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope: &commonpb.InstrumentationScope{Name: "test", Version: "1"},
			LogRecords: []*logspb.LogRecord{{
				TimeUnixNano: uint64(now.UnixNano()), EventName: "http.request", SeverityText: "INFO",
				Body:    &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "complete"}},
				TraceId: bytes.Repeat([]byte{0x11}, 16), SpanId: bytes.Repeat([]byte{0x22}, 8),
				Attributes: []*commonpb.KeyValue{stringAttribute("http.route", "/items/{id}")},
			}},
		}},
	}}}
	records, err := Decode(Logs, marshal(t, request), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Name != "http.request" || records[0].Body != "complete" || records[0].TraceID != "11111111111111111111111111111111" {
		t.Fatalf("records=%+v", records)
	}
	if records[0].Attributes["service.name"] != "eql" || records[0].Attributes["http.route"] != "/items/{id}" || records[0].Attributes["otel.scope.name"] != "test" {
		t.Fatalf("attributes=%+v", records[0].Attributes)
	}
	if _, exists := records[0].Attributes["http.request.header.authorization"]; exists {
		t.Fatal("credential-bearing attribute was retained")
	}
}

func TestDecodeMetricsAndTraces(t *testing.T) {
	now := time.Date(2026, 8, 17, 3, 0, 0, 0, time.UTC)
	point := &metricspb.NumberDataPoint{
		TimeUnixNano: uint64(now.UnixNano()),
		Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: 12.5},
		Attributes:   []*commonpb.KeyValue{stringAttribute("http.route", "/")},
	}
	metric := &metricspb.Metric{Name: "http.server.duration", Unit: "ms", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{point}}}}
	metricRequest := &metricspb.MetricsData{ResourceMetrics: []*metricspb.ResourceMetrics{{ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{metric}}}}}}
	metrics, err := Decode(Metrics, marshal(t, metricRequest), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 1 || metrics[0].Value == nil || *metrics[0].Value != 12.5 || metrics[0].Attributes["metric.unit"] != "ms" {
		t.Fatalf("metrics=%+v", metrics)
	}

	span := &tracepb.Span{
		TraceId: bytes.Repeat([]byte{0x33}, 16), SpanId: bytes.Repeat([]byte{0x44}, 8), Name: "GET /", Kind: tracepb.Span_SPAN_KIND_SERVER,
		StartTimeUnixNano: uint64(now.UnixNano()), EndTimeUnixNano: uint64(now.Add(7 * time.Millisecond).UnixNano()), Status: &tracepb.Status{Code: tracepb.Status_STATUS_CODE_OK},
	}
	traceRequest := &tracepb.TracesData{ResourceSpans: []*tracepb.ResourceSpans{{ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{span}}}}}}
	traces, err := Decode(Traces, marshal(t, traceRequest), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(traces) != 1 || traces[0].Name != "GET /" || traces[0].Value == nil || *traces[0].Value != float64((7*time.Millisecond).Nanoseconds()) || traces[0].Attributes["span.status"] != "STATUS_CODE_OK" {
		t.Fatalf("traces=%+v", traces)
	}
}

func TestDecodeRejectsMalformedAndNonFiniteData(t *testing.T) {
	now := time.Date(2026, 8, 17, 3, 0, 0, 0, time.UTC)
	badPoint := &metricspb.NumberDataPoint{TimeUnixNano: uint64(now.UnixNano()), Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: math.NaN()}}
	badMetricValue := &metricspb.Metric{Name: "bad", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{badPoint}}}}
	badMetric := &metricspb.MetricsData{ResourceMetrics: []*metricspb.ResourceMetrics{{ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{badMetricValue}}}}}}
	if _, err := Decode(Metrics, marshal(t, badMetric), now); err == nil {
		t.Fatal("non-finite metric accepted")
	}
	badTrace := &tracepb.TracesData{ResourceSpans: []*tracepb.ResourceSpans{{ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{TraceId: []byte{1}, SpanId: bytes.Repeat([]byte{2}, 8), Name: "bad", StartTimeUnixNano: uint64(now.UnixNano()), EndTimeUnixNano: uint64(now.UnixNano())}}}}}}}
	if _, err := Decode(Traces, marshal(t, badTrace), now); err == nil {
		t.Fatal("invalid trace identifier accepted")
	}
	if _, err := Decode(Logs, []byte{0xff, 0xff}, now); err == nil {
		t.Fatal("malformed protobuf accepted")
	}
}

func TestSuccessResponseIsDeterministicAndValid(t *testing.T) {
	for _, signal := range []Signal{Logs, Metrics, Traces} {
		first, err := SuccessResponse(signal)
		if err != nil {
			t.Fatal(err)
		}
		second, _ := SuccessResponse(signal)
		if !bytes.Equal(first, second) {
			t.Fatalf("%s response is not deterministic", signal)
		}
		if len(first) != 0 {
			t.Fatalf("%s response has non-canonical empty encoding", signal)
		}
	}
}

func FuzzDecode(f *testing.F) {
	now := time.Date(2026, 8, 17, 3, 0, 0, 0, time.UTC)
	seed, err := proto.Marshal(&logspb.LogsData{ResourceLogs: []*logspb.ResourceLogs{{ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{TimeUnixNano: uint64(now.UnixNano()), EventName: "seed"}}}}}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), seed)
	f.Add(uint8(1), []byte{0xff, 0x00})
	f.Fuzz(func(t *testing.T, selected uint8, body []byte) {
		if len(body) > 1<<20 {
			return
		}
		signal := []Signal{Logs, Metrics, Traces}[selected%3]
		records, _ := Decode(signal, body, now)
		if len(records) > 5_000 {
			t.Fatalf("decoded %d records", len(records))
		}
	})
}

func stringAttribute(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}}
}

func marshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
