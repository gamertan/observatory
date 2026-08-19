// SPDX-License-Identifier: AGPL-3.0-only

package otlp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gamertan.com/observatory/internal/model"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

type Signal string

const (
	Logs    Signal = "logs"
	Metrics Signal = "metrics"
	Traces  Signal = "traces"
)

func (signal Signal) ModelSignal() model.Signal {
	switch signal {
	case Logs:
		return model.SignalLogs
	case Metrics:
		return model.SignalMetrics
	case Traces:
		return model.SignalTraces
	default:
		return ""
	}
}

func (signal Signal) StreamID() string { return "otlp-" + string(signal) }

func Decode(signal Signal, body []byte, now time.Time) ([]model.Observation, error) {
	if len(body) == 0 || now.IsZero() {
		return nil, errors.New("OTLP request is empty or missing collection time")
	}
	options := proto.UnmarshalOptions{DiscardUnknown: true, RecursionLimit: 64}
	var records []model.Observation
	var err error
	switch signal {
	case Logs:
		request := new(logspb.LogsData)
		if err = options.Unmarshal(body, request); err == nil {
			records, err = decodeLogs(request)
		}
	case Metrics:
		request := new(metricspb.MetricsData)
		if err = options.Unmarshal(body, request); err == nil {
			records, err = decodeMetrics(request)
		}
	case Traces:
		request := new(tracepb.TracesData)
		if err = options.Unmarshal(body, request); err == nil {
			records, err = decodeTraces(request)
		}
	default:
		return nil, errors.New("unsupported OTLP signal")
	}
	if err != nil {
		return nil, errors.New("invalid OTLP protobuf payload")
	}
	if len(records) == 0 {
		return nil, errors.New("OTLP request contains no supported records")
	}
	if len(records) > model.MaxRecords {
		return nil, fmt.Errorf("OTLP request exceeds %d records", model.MaxRecords)
	}
	return records, nil
}

func SuccessResponse(signal Signal) ([]byte, error) {
	switch signal {
	case Logs, Metrics, Traces:
		// Each successful OTLP/HTTP protobuf response is an empty message when
		// there is no partial-success detail. The canonical protobuf encoding of
		// an empty message is an empty byte sequence.
		return []byte{}, nil
	default:
		return nil, errors.New("unsupported OTLP signal")
	}
}

func decodeLogs(request *logspb.LogsData) ([]model.Observation, error) {
	var records []model.Observation
	for _, resourceLogs := range request.GetResourceLogs() {
		resource, err := baseAttributes(resourceLogs.GetResource())
		if err != nil {
			return nil, err
		}
		for _, scopeLogs := range resourceLogs.GetScopeLogs() {
			base, err := scopeAttributes(resource, scopeLogs.GetScope())
			if err != nil {
				return nil, err
			}
			for _, record := range scopeLogs.GetLogRecords() {
				attributes, err := mergeAttributes(base, record.GetAttributes())
				if err != nil {
					return nil, err
				}
				if record.GetDroppedAttributesCount() > 0 {
					if err = addAttribute(attributes, "otel.dropped_attributes", strconv.FormatUint(uint64(record.GetDroppedAttributesCount()), 10)); err != nil {
						return nil, err
					}
				}
				body, err := anyValueText(record.GetBody(), model.MaxBody)
				if err != nil {
					return nil, err
				}
				name := record.GetEventName()
				if name == "" {
					name = "otlp.log"
				}
				when := record.GetTimeUnixNano()
				if when == 0 {
					when = record.GetObservedTimeUnixNano()
				}
				timestamp, err := timestamp(when)
				if err != nil {
					return nil, err
				}
				traceID, err := identifier(record.GetTraceId(), 16)
				if err != nil {
					return nil, err
				}
				spanID, err := identifier(record.GetSpanId(), 8)
				if err != nil {
					return nil, err
				}
				severity := record.GetSeverityText()
				if severity == "" && record.GetSeverityNumber() != 0 {
					severity = record.GetSeverityNumber().String()
				}
				records = append(records, model.Observation{Timestamp: timestamp, Name: name, Severity: severity, Body: body, TraceID: traceID, SpanID: spanID, CorrelationID: traceID, Attributes: attributes})
				if len(records) > model.MaxRecords {
					return nil, errors.New("OTLP logs exceed record limit")
				}
			}
		}
	}
	return records, nil
}

func decodeMetrics(request *metricspb.MetricsData) ([]model.Observation, error) {
	var records []model.Observation
	for _, resourceMetrics := range request.GetResourceMetrics() {
		resource, err := baseAttributes(resourceMetrics.GetResource())
		if err != nil {
			return nil, err
		}
		for _, scopeMetrics := range resourceMetrics.GetScopeMetrics() {
			base, err := scopeAttributes(resource, scopeMetrics.GetScope())
			if err != nil {
				return nil, err
			}
			for _, metric := range scopeMetrics.GetMetrics() {
				metricBase := cloneAttributes(base)
				if metric.GetUnit() != "" {
					if err = addAttribute(metricBase, "metric.unit", metric.GetUnit()); err != nil {
						return nil, err
					}
				}
				switch data := metric.Data.(type) {
				case *metricspb.Metric_Gauge:
					err = appendNumberPoints(&records, metric.GetName(), "gauge", "", metricBase, data.Gauge.GetDataPoints())
				case *metricspb.Metric_Sum:
					err = appendNumberPoints(&records, metric.GetName(), "sum", data.Sum.GetAggregationTemporality().String(), metricBase, data.Sum.GetDataPoints())
				case *metricspb.Metric_Histogram:
					err = appendHistogramPoints(&records, metric.GetName(), data.Histogram.GetAggregationTemporality().String(), metricBase, data.Histogram.GetDataPoints())
				case *metricspb.Metric_ExponentialHistogram:
					err = appendExponentialHistogramPoints(&records, metric.GetName(), data.ExponentialHistogram.GetAggregationTemporality().String(), metricBase, data.ExponentialHistogram.GetDataPoints())
				case *metricspb.Metric_Summary:
					err = appendSummaryPoints(&records, metric.GetName(), metricBase, data.Summary.GetDataPoints())
				default:
					err = errors.New("OTLP metric has unsupported data")
				}
				if err != nil {
					return nil, err
				}
				if len(records) > model.MaxRecords {
					return nil, errors.New("OTLP metrics exceed record limit")
				}
			}
		}
	}
	return records, nil
}

func appendNumberPoints(records *[]model.Observation, name, kind, temporality string, base map[string]string, points []*metricspb.NumberDataPoint) error {
	for _, point := range points {
		if point.GetFlags()&uint32(metricspb.DataPointFlags_DATA_POINT_FLAGS_NO_RECORDED_VALUE_MASK) != 0 {
			continue
		}
		attributes, err := metricAttributes(base, point.GetAttributes(), kind, temporality, point.GetStartTimeUnixNano())
		if err != nil {
			return err
		}
		var value float64
		switch number := point.Value.(type) {
		case *metricspb.NumberDataPoint_AsDouble:
			value = number.AsDouble
		case *metricspb.NumberDataPoint_AsInt:
			value = float64(number.AsInt)
			if err = addAttribute(attributes, "metric.int64", strconv.FormatInt(number.AsInt, 10)); err != nil {
				return err
			}
		default:
			return errors.New("OTLP number point has no value")
		}
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New("OTLP metric value is not finite")
		}
		timestamp, err := timestamp(point.GetTimeUnixNano())
		if err != nil {
			return err
		}
		*records = append(*records, model.Observation{Timestamp: timestamp, Name: name, Value: &value, Attributes: attributes})
	}
	return nil
}

func appendHistogramPoints(records *[]model.Observation, name, temporality string, base map[string]string, points []*metricspb.HistogramDataPoint) error {
	for _, point := range points {
		if point.GetFlags()&uint32(metricspb.DataPointFlags_DATA_POINT_FLAGS_NO_RECORDED_VALUE_MASK) != 0 {
			continue
		}
		attributes, err := metricAttributes(base, point.GetAttributes(), "histogram", temporality, point.GetStartTimeUnixNano())
		if err != nil {
			return err
		}
		bounds := point.GetExplicitBounds()
		if len(point.GetBucketCounts()) != len(bounds)+1 || !strictlyIncreasingFinite(bounds) {
			return errors.New("OTLP histogram buckets are invalid")
		}
		for key, value := range map[string]any{"metric.bucket_counts": point.GetBucketCounts(), "metric.explicit_bounds": point.GetExplicitBounds(), "metric.count": point.GetCount()} {
			if err = addJSONAttribute(attributes, key, value); err != nil {
				return err
			}
		}
		value := float64(point.GetCount())
		if point.Sum != nil {
			value = point.GetSum()
			if !finite(value) {
				return errors.New("OTLP histogram sum is not finite")
			}
			if err = addAttribute(attributes, "metric.sum", strconv.FormatFloat(value, 'g', -1, 64)); err != nil {
				return err
			}
		}
		if point.Min != nil {
			if !finite(point.GetMin()) {
				return errors.New("OTLP histogram minimum is not finite")
			}
			if err = addAttribute(attributes, "metric.min", strconv.FormatFloat(point.GetMin(), 'g', -1, 64)); err != nil {
				return err
			}
		}
		if point.Max != nil {
			if !finite(point.GetMax()) {
				return errors.New("OTLP histogram maximum is not finite")
			}
			if err = addAttribute(attributes, "metric.max", strconv.FormatFloat(point.GetMax(), 'g', -1, 64)); err != nil {
				return err
			}
		}
		timestamp, err := timestamp(point.GetTimeUnixNano())
		if err != nil {
			return err
		}
		*records = append(*records, model.Observation{Timestamp: timestamp, Name: name, Value: &value, Attributes: attributes})
	}
	return nil
}

func appendExponentialHistogramPoints(records *[]model.Observation, name, temporality string, base map[string]string, points []*metricspb.ExponentialHistogramDataPoint) error {
	for _, point := range points {
		if point.GetFlags()&uint32(metricspb.DataPointFlags_DATA_POINT_FLAGS_NO_RECORDED_VALUE_MASK) != 0 {
			continue
		}
		attributes, err := metricAttributes(base, point.GetAttributes(), "exponential_histogram", temporality, point.GetStartTimeUnixNano())
		if err != nil {
			return err
		}
		if point.GetScale() < -10 || point.GetScale() > 20 || !finite(point.GetZeroThreshold()) || point.GetZeroThreshold() < 0 {
			return errors.New("OTLP exponential histogram parameters are invalid")
		}
		values := map[string]any{
			"metric.count": point.GetCount(), "metric.scale": point.GetScale(), "metric.zero_count": point.GetZeroCount(),
			"metric.zero_threshold": point.GetZeroThreshold(), "metric.positive": point.GetPositive(), "metric.negative": point.GetNegative(),
		}
		for key, value := range values {
			if err = addJSONAttribute(attributes, key, value); err != nil {
				return err
			}
		}
		value := float64(point.GetCount())
		if point.Sum != nil {
			value = point.GetSum()
			if !finite(value) {
				return errors.New("OTLP exponential histogram sum is not finite")
			}
			if err = addAttribute(attributes, "metric.sum", strconv.FormatFloat(value, 'g', -1, 64)); err != nil {
				return err
			}
		}
		timestamp, err := timestamp(point.GetTimeUnixNano())
		if err != nil {
			return err
		}
		*records = append(*records, model.Observation{Timestamp: timestamp, Name: name, Value: &value, Attributes: attributes})
	}
	return nil
}

func appendSummaryPoints(records *[]model.Observation, name string, base map[string]string, points []*metricspb.SummaryDataPoint) error {
	for _, point := range points {
		if point.GetFlags()&uint32(metricspb.DataPointFlags_DATA_POINT_FLAGS_NO_RECORDED_VALUE_MASK) != 0 {
			continue
		}
		attributes, err := metricAttributes(base, point.GetAttributes(), "summary", "", point.GetStartTimeUnixNano())
		if err != nil {
			return err
		}
		if err = addJSONAttribute(attributes, "metric.count", point.GetCount()); err != nil {
			return err
		}
		quantiles := make([][2]float64, 0, len(point.GetQuantileValues()))
		for _, quantile := range point.GetQuantileValues() {
			if !finite(quantile.GetQuantile()) || quantile.GetQuantile() < 0 || quantile.GetQuantile() > 1 || !finite(quantile.GetValue()) {
				return errors.New("OTLP summary quantile is invalid")
			}
			quantiles = append(quantiles, [2]float64{quantile.GetQuantile(), quantile.GetValue()})
		}
		if err = addJSONAttribute(attributes, "metric.quantiles", quantiles); err != nil {
			return err
		}
		value := point.GetSum()
		if !finite(value) {
			return errors.New("OTLP summary sum is not finite")
		}
		if err = addAttribute(attributes, "metric.sum", strconv.FormatFloat(value, 'g', -1, 64)); err != nil {
			return err
		}
		timestamp, err := timestamp(point.GetTimeUnixNano())
		if err != nil {
			return err
		}
		*records = append(*records, model.Observation{Timestamp: timestamp, Name: name, Value: &value, Attributes: attributes})
	}
	return nil
}

func decodeTraces(request *tracepb.TracesData) ([]model.Observation, error) {
	var records []model.Observation
	for _, resourceSpans := range request.GetResourceSpans() {
		resource, err := baseAttributes(resourceSpans.GetResource())
		if err != nil {
			return nil, err
		}
		for _, scopeSpans := range resourceSpans.GetScopeSpans() {
			base, err := scopeAttributes(resource, scopeSpans.GetScope())
			if err != nil {
				return nil, err
			}
			for _, span := range scopeSpans.GetSpans() {
				attributes, err := mergeAttributes(base, span.GetAttributes())
				if err != nil {
					return nil, err
				}
				traceID, err := identifier(span.GetTraceId(), 16)
				if err != nil || traceID == "" {
					return nil, errors.New("OTLP span has invalid trace ID")
				}
				spanID, err := identifier(span.GetSpanId(), 8)
				if err != nil || spanID == "" {
					return nil, errors.New("OTLP span has invalid span ID")
				}
				if parent, parentErr := identifier(span.GetParentSpanId(), 8); parentErr != nil {
					return nil, parentErr
				} else if parent != "" {
					if err = addAttribute(attributes, "span.parent_id", parent); err != nil {
						return nil, err
					}
				}
				start, err := timestamp(span.GetStartTimeUnixNano())
				if err != nil {
					return nil, err
				}
				end, err := timestamp(span.GetEndTimeUnixNano())
				if err != nil || end.Before(start) {
					return nil, errors.New("OTLP span has invalid time range")
				}
				duration := float64(end.Sub(start).Nanoseconds())
				if err = addAttribute(attributes, "span.duration_ns", strconv.FormatInt(end.Sub(start).Nanoseconds(), 10)); err != nil {
					return nil, err
				}
				if err = addAttribute(attributes, "span.kind", span.GetKind().String()); err != nil {
					return nil, err
				}
				if status := span.GetStatus(); status != nil {
					if err = addAttribute(attributes, "span.status", status.GetCode().String()); err != nil {
						return nil, err
					}
				}
				for key, count := range map[string]uint64{"span.events_count": uint64(len(span.GetEvents())), "span.links_count": uint64(len(span.GetLinks())), "otel.dropped_attributes": uint64(span.GetDroppedAttributesCount()), "otel.dropped_events": uint64(span.GetDroppedEventsCount()), "otel.dropped_links": uint64(span.GetDroppedLinksCount())} {
					if count > 0 {
						if err = addAttribute(attributes, key, strconv.FormatUint(count, 10)); err != nil {
							return nil, err
						}
					}
				}
				records = append(records, model.Observation{Timestamp: start, Name: span.GetName(), Value: &duration, TraceID: traceID, SpanID: spanID, CorrelationID: traceID, Attributes: attributes})
				if len(records) > model.MaxRecords {
					return nil, errors.New("OTLP traces exceed record limit")
				}
			}
		}
	}
	return records, nil
}

func baseAttributes(resource *resourcepb.Resource) (map[string]string, error) {
	if resource == nil {
		return map[string]string{}, nil
	}
	attributes, err := mergeAttributes(nil, resource.GetAttributes())
	if err != nil {
		return nil, err
	}
	if resource.GetDroppedAttributesCount() > 0 {
		err = addAttribute(attributes, "otel.resource.dropped_attributes", strconv.FormatUint(uint64(resource.GetDroppedAttributesCount()), 10))
	}
	return attributes, err
}

func scopeAttributes(base map[string]string, scope *commonpb.InstrumentationScope) (map[string]string, error) {
	attributes := cloneAttributes(base)
	if scope == nil {
		return attributes, nil
	}
	if scope.GetName() != "" {
		if err := addAttribute(attributes, "otel.scope.name", scope.GetName()); err != nil {
			return nil, err
		}
	}
	if scope.GetVersion() != "" {
		if err := addAttribute(attributes, "otel.scope.version", scope.GetVersion()); err != nil {
			return nil, err
		}
	}
	for _, pair := range scope.GetAttributes() {
		if pair.GetKey() == "" || deniedKey(pair.GetKey()) {
			continue
		}
		value, err := anyValueText(pair.GetValue(), model.MaxAttributeValue)
		if err != nil {
			return nil, err
		}
		if err = addAttribute(attributes, "otel.scope.attribute."+pair.GetKey(), value); err != nil {
			return nil, err
		}
	}
	return attributes, nil
}

func metricAttributes(base map[string]string, pairs []*commonpb.KeyValue, kind, temporality string, start uint64) (map[string]string, error) {
	attributes, err := mergeAttributes(base, pairs)
	if err != nil {
		return nil, err
	}
	if err = addAttribute(attributes, "metric.kind", kind); err != nil {
		return nil, err
	}
	if temporality != "" {
		if err = addAttribute(attributes, "metric.temporality", temporality); err != nil {
			return nil, err
		}
	}
	if start != 0 {
		if err = addAttribute(attributes, "metric.start_unix_nano", strconv.FormatUint(start, 10)); err != nil {
			return nil, err
		}
	}
	return attributes, nil
}

func mergeAttributes(base map[string]string, pairs []*commonpb.KeyValue) (map[string]string, error) {
	attributes := cloneAttributes(base)
	for _, pair := range pairs {
		key := pair.GetKey()
		if key == "" || deniedKey(key) {
			continue
		}
		value, err := anyValueText(pair.GetValue(), model.MaxAttributeValue)
		if err != nil {
			return nil, err
		}
		if err = addAttribute(attributes, key, value); err != nil {
			return nil, err
		}
	}
	return attributes, nil
}

func cloneAttributes(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func addAttribute(attributes map[string]string, key, value string) error {
	if key == "" || len(key) > model.MaxAttributeKey || !utf8.ValidString(key) || strings.IndexByte(key, 0) >= 0 || len(value) > model.MaxAttributeValue || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return errors.New("OTLP attribute exceeds accepted bounds")
	}
	if _, exists := attributes[key]; !exists && len(attributes) >= model.MaxAttributes {
		return errors.New("OTLP record exceeds attribute limit")
	}
	attributes[key] = value
	return nil
}

func addJSONAttribute(attributes map[string]string, key string, value any) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) > model.MaxAttributeValue {
		return errors.New("OTLP structured attribute exceeds accepted bounds")
	}
	return addAttribute(attributes, key, string(body))
}

func anyValueText(value *commonpb.AnyValue, maximum int) (string, error) {
	converted, err := anyValue(value, 0)
	if err != nil {
		return "", err
	}
	if text, ok := converted.(string); ok {
		if len(text) > maximum || !utf8.ValidString(text) || strings.IndexByte(text, 0) >= 0 {
			return "", errors.New("OTLP string value exceeds accepted bounds")
		}
		return text, nil
	}
	body, err := json.Marshal(converted)
	if err != nil || len(body) > maximum {
		return "", errors.New("OTLP value exceeds accepted bounds")
	}
	return string(body), nil
}

func anyValue(value *commonpb.AnyValue, depth int) (any, error) {
	if value == nil {
		return "", nil
	}
	if depth > 8 {
		return nil, errors.New("OTLP value exceeds nesting limit")
	}
	switch content := value.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return content.StringValue, nil
	case *commonpb.AnyValue_BoolValue:
		return content.BoolValue, nil
	case *commonpb.AnyValue_IntValue:
		return content.IntValue, nil
	case *commonpb.AnyValue_DoubleValue:
		if math.IsNaN(content.DoubleValue) || math.IsInf(content.DoubleValue, 0) {
			return nil, errors.New("OTLP value is not finite")
		}
		return content.DoubleValue, nil
	case *commonpb.AnyValue_BytesValue:
		if len(content.BytesValue) > model.MaxAttributeValue/2 {
			return nil, errors.New("OTLP byte value exceeds accepted bounds")
		}
		return hex.EncodeToString(content.BytesValue), nil
	case *commonpb.AnyValue_ArrayValue:
		values := content.ArrayValue.GetValues()
		if len(values) > 64 {
			return nil, errors.New("OTLP array exceeds element limit")
		}
		result := make([]any, 0, len(values))
		for _, item := range values {
			converted, err := anyValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, converted)
		}
		return result, nil
	case *commonpb.AnyValue_KvlistValue:
		values := content.KvlistValue.GetValues()
		if len(values) > 64 {
			return nil, errors.New("OTLP key-value list exceeds element limit")
		}
		result := make(map[string]any, len(values))
		for _, pair := range values {
			key := pair.GetKey()
			if key == "" || deniedKey(key) {
				continue
			}
			converted, err := anyValue(pair.GetValue(), depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = converted
		}
		return result, nil
	case *commonpb.AnyValue_StringValueStrindex:
		return "", nil
	default:
		return "", nil
	}
}

func deniedKey(key string) bool {
	normalized := strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(strings.ToLower(key))
	for _, denied := range []string{"authorization", "proxy_authorization", "cookie", "set_cookie", "password", "passwd", "secret", "api_key", "apikey", "access_token", "refresh_token", "client_secret"} {
		if strings.Contains(normalized, denied) {
			return true
		}
	}
	return false
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func strictlyIncreasingFinite(values []float64) bool {
	for index, value := range values {
		if !finite(value) || index > 0 && value <= values[index-1] {
			return false
		}
	}
	return true
}

func identifier(value []byte, bytes int) (string, error) {
	if len(value) == 0 {
		return "", nil
	}
	if len(value) != bytes {
		return "", errors.New("OTLP identifier has invalid length")
	}
	return hex.EncodeToString(value), nil
}

func timestamp(nanoseconds uint64) (time.Time, error) {
	if nanoseconds == 0 {
		return time.Time{}, errors.New("OTLP timestamp is required")
	}
	if nanoseconds > math.MaxInt64 {
		return time.Time{}, errors.New("OTLP timestamp exceeds supported range")
	}
	return time.Unix(0, int64(nanoseconds)).UTC(), nil
}
