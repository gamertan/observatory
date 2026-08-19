// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
)

func metricRollupQueryEligible(ast query.AST, registry query.Registry) bool {
	if ast.Signal != model.SignalMetrics || ast.Summary == nil {
		return false
	}
	if ast.Bucket > 0 && (ast.Bucket < metricRollupWindow || ast.Bucket%metricRollupWindow != 0) {
		return false
	}
	for _, aggregate := range ast.Summary.Aggregates {
		if aggregate.Function != "count" && query.CanonicalField(aggregate.Field) != "value" {
			return false
		}
	}
	for _, filter := range ast.Filters {
		field := query.CanonicalField(filter.Field)
		switch field {
		case "value", "timestamp", "source.id", "stream.id", "severity", "body", "trace_id", "span_id", "correlation_id":
			return false
		}
		if !metricRollupDimensionAvailable(field, registry) {
			return false
		}
	}
	for _, field := range ast.Summary.GroupBy {
		canonical := query.CanonicalField(field)
		switch canonical {
		case "value", "timestamp", "source.id", "stream.id", "severity", "body", "trace_id", "span_id", "correlation_id":
			return false
		}
		if !metricRollupDimensionAvailable(canonical, registry) {
			return false
		}
	}
	return true
}

func metricRollupDimensionAvailable(field string, registry query.Registry) bool {
	switch query.CanonicalField(field) {
	case "project.id", "environment.id", "service.id", "name":
		return true
	}
	descriptor, unknown := query.ResolveDescriptor(model.SignalMetrics, field, registry)
	return !unknown && descriptor.Retention == schema.RetentionMetric && descriptor.Sensitivity != schema.SensitivitySensitive && descriptor.Cardinality != schema.CardinalityHigh
}

func (s *Store) estimateMetricRollupBytes(ctx context.Context, scope query.Scope, ast query.AST, now time.Time) (int64, error) {
	path := s.organizationProjectionPath(scope.OrganizationID)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("organization projection is unavailable")
	}
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return 0, errors.New("open metric rollup estimate")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	statement := `SELECT COALESCE(SUM(192+LENGTH(name)+LENGTH(attributes_json)+LENGTH(histogram_json)),0) FROM metric_rollups_5m WHERE organization_id=?`
	arguments := []any{scope.OrganizationID}
	for _, selected := range []struct{ column, value string }{{"project_id", scope.ProjectID}, {"environment_id", scope.EnvironmentID}, {"service_id", scope.ServiceID}} {
		if selected.value != "" {
			statement += " AND " + selected.column + "=?"
			arguments = append(arguments, selected.value)
		}
	}
	if ast.Window > 0 {
		statement += " AND bucket_start>=?"
		arguments = append(arguments, now.UTC().Add(-ast.Window).Truncate(metricRollupWindow).Format(time.RFC3339Nano))
	}
	var estimated int64
	if err = db.QueryRowContext(ctx, statement, arguments...).Scan(&estimated); err != nil || estimated < 0 {
		return 0, errors.New("estimate metric rollup scan")
	}
	return estimated, nil
}

type rollupAggregate struct {
	function              string
	count                 int64
	sum, minimum, maximum float64
	bins                  map[int64]int64
}

type rollupSummaryGroup struct {
	key        string
	values     []*string
	aggregates []rollupAggregate
}

func (s *Store) queryMetricRollups(ctx context.Context, path string, ast query.AST, scope query.Scope, registry query.Registry, budget query.Budget, now time.Time, result query.Result) (query.Result, error) {
	runContext, cancel := context.WithTimeout(ctx, budget.MaxDuration)
	defer cancel()
	started := time.Now()
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return query.Result{}, errors.New("open metric rollup projection")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	statement := `SELECT project_id,environment_id,service_id,bucket_start,name,attributes_json,sample_count,value_count,value_sum,value_min,value_max,last_value,last_timestamp,histogram_json FROM metric_rollups_5m WHERE organization_id=?`
	arguments := []any{scope.OrganizationID}
	for _, selected := range []struct{ column, value string }{{"project_id", scope.ProjectID}, {"environment_id", scope.EnvironmentID}, {"service_id", scope.ServiceID}} {
		if selected.value != "" {
			statement += " AND " + selected.column + "=?"
			arguments = append(arguments, selected.value)
		}
	}
	if ast.Window > 0 {
		statement += " AND bucket_start>=?"
		arguments = append(arguments, now.UTC().Add(-ast.Window).Truncate(metricRollupWindow).Format(time.RFC3339Nano))
	}
	statement += ` ORDER BY bucket_start DESC,project_id,environment_id,service_id,name,dimensions_digest`
	rows, err := db.QueryContext(runContext, statement, arguments...)
	if err != nil {
		return query.Result{}, queryExecutionError(runContext, err)
	}
	defer rows.Close()
	groups := map[string]*rollupSummaryGroup{}
	var memoryBytes int64
	for rows.Next() {
		var projectID, environmentID, serviceID, bucketText, name, attributesJSON, lastTimestamp, histogram string
		var sampleCount, valueCount int64
		var sum, minimum, maximum, lastValue float64
		if err = rows.Scan(&projectID, &environmentID, &serviceID, &bucketText, &name, &attributesJSON, &sampleCount, &valueCount, &sum, &minimum, &maximum, &lastValue, &lastTimestamp, &histogram); err != nil {
			return query.Result{}, errors.New("read metric rollup projection")
		}
		if result.Stats.ScannedRows == math.MaxInt64 {
			return query.Result{}, query.ErrBudgetExceeded
		}
		result.Stats.ScannedRows++
		readBytes := int64(192 + len(projectID) + len(environmentID) + len(serviceID) + len(bucketText) + len(name) + len(attributesJSON) + len(lastTimestamp) + len(histogram))
		if readBytes < 0 || readBytes > budget.MaxScannedBytes-result.Stats.ScannedBytes {
			return query.Result{}, query.ErrBudgetExceeded
		}
		result.Stats.ScannedBytes += readBytes
		bucket, parseErr := time.Parse(time.RFC3339Nano, bucketText)
		if parseErr != nil || sampleCount < 1 || valueCount < 1 || valueCount > sampleCount || math.IsNaN(sum) || math.IsInf(sum, 0) || math.IsNaN(minimum) || math.IsInf(minimum, 0) || math.IsNaN(maximum) || math.IsInf(maximum, 0) || math.IsNaN(lastValue) || math.IsInf(lastValue, 0) {
			return query.Result{}, errors.New("metric rollup projection is invalid")
		}
		attributes := map[string]string{}
		decoder := json.NewDecoder(strings.NewReader(attributesJSON))
		if err = decoder.Decode(&attributes); err != nil || len(attributes) > model.MaxAttributes {
			return query.Result{}, errors.New("metric rollup dimensions are invalid")
		}
		var trailing any
		if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return query.Result{}, errors.New("metric rollup dimensions are invalid")
		}
		record := projectedRecord{projectID: projectID, environmentID: environmentID, serviceID: serviceID, signal: model.SignalMetrics, timestamp: bucket.UTC(), name: name, value: &lastValue, attributes: attributes}
		matched, matchErr := matchesRecord(record, ast, registry)
		if matchErr != nil {
			return query.Result{}, matchErr
		}
		if !matched {
			continue
		}
		if result.Stats.MatchedRows == math.MaxInt64 {
			return query.Result{}, query.ErrBudgetExceeded
		}
		result.Stats.MatchedRows++
		bins, decodeErr := decodeHistogram(histogram)
		if decodeErr != nil {
			return query.Result{}, decodeErr
		}
		var values []*string
		if ast.Bucket > 0 {
			window := bucket.UTC().Truncate(ast.Bucket).Format(time.RFC3339Nano)
			values = append(values, stringPointer(window))
		}
		for _, field := range ast.Summary.GroupBy {
			value, present := record.field(field)
			if !present {
				values = append(values, nil)
				continue
			}
			column := result.Columns[len(values)]
			canonical, valid := canonicalResultValue(value, column.Type)
			if !valid {
				values = append(values, nil)
				continue
			}
			values = append(values, stringPointer(canonical))
		}
		key := groupKey(values)
		group := groups[key]
		if group == nil {
			group = &rollupSummaryGroup{key: key, values: values, aggregates: make([]rollupAggregate, len(ast.Summary.Aggregates))}
			for index, aggregate := range ast.Summary.Aggregates {
				group.aggregates[index] = rollupAggregate{function: aggregate.Function, bins: map[int64]int64{}}
			}
			groups[key] = group
			addition := int64(len(key) + len(values)*16 + len(group.aggregates)*96)
			if addition < 0 || addition > budget.MaxMemoryBytes-memoryBytes {
				return query.Result{}, query.ErrBudgetExceeded
			}
			memoryBytes += addition
		}
		for index, aggregate := range ast.Summary.Aggregates {
			state := &group.aggregates[index]
			if aggregate.Function == "count" {
				if sampleCount > math.MaxInt64-state.count {
					return query.Result{}, errors.New("metric rollup count exceeds numeric range")
				}
				state.count += sampleCount
				continue
			}
			if state.count == 0 {
				state.minimum, state.maximum = minimum, maximum
			} else {
				state.minimum = math.Min(state.minimum, minimum)
				state.maximum = math.Max(state.maximum, maximum)
			}
			if valueCount > math.MaxInt64-state.count {
				return query.Result{}, errors.New("metric rollup count exceeds numeric range")
			}
			state.count += valueCount
			state.sum += sum
			if math.IsNaN(state.sum) || math.IsInf(state.sum, 0) {
				return query.Result{}, errors.New("metric rollup sum exceeds numeric range")
			}
			if aggregate.Function == "p50" || aggregate.Function == "p95" || aggregate.Function == "p99" {
				result.Stats.Approximate = true
				for histogramBucket, count := range bins {
					if count > math.MaxInt64-state.bins[histogramBucket] {
						return query.Result{}, errors.New("metric histogram count exceeds numeric range")
					}
					state.bins[histogramBucket] += count
				}
				addition := int64(len(bins) * 24)
				if addition < 0 || addition > budget.MaxMemoryBytes-memoryBytes {
					return query.Result{}, query.ErrBudgetExceeded
				}
				memoryBytes += addition
			}
		}
		if memoryBytes > budget.MaxMemoryBytes {
			return query.Result{}, query.ErrBudgetExceeded
		}
	}
	if err = rows.Err(); err != nil {
		return query.Result{}, queryExecutionError(runContext, err)
	}
	ordered := make([]*rollupSummaryGroup, 0, len(groups))
	for _, group := range groups {
		ordered = append(ordered, group)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].key < ordered[j].key })
	for _, group := range ordered {
		row := query.Row{Values: append([]*string(nil), group.values...)}
		for _, aggregate := range group.aggregates {
			value, present := rollupAggregateValue(aggregate)
			if present {
				row.Values = append(row.Values, stringPointer(value))
			} else {
				row.Values = append(row.Values, nil)
			}
		}
		result.Rows = append(result.Rows, row)
	}
	if ast.Sort != nil {
		if err = sortRows(result.Rows, result.Columns, ast.Sort.Field, ast.Sort.Descending); err != nil {
			return query.Result{}, err
		}
	}
	if len(result.Rows) > ast.Limit {
		result.Rows = result.Rows[:ast.Limit]
		result.Stats.Truncated = true
	}
	result.Stats.DurationNS = time.Since(started).Nanoseconds()
	return result, nil
}

func rollupAggregateValue(state rollupAggregate) (string, bool) {
	if state.function == "count" {
		return strconv.FormatInt(state.count, 10), true
	}
	if state.count == 0 {
		return "", false
	}
	var value float64
	switch state.function {
	case "min":
		value = state.minimum
	case "max":
		value = state.maximum
	case "sum":
		value = state.sum
	case "avg":
		value = state.sum / float64(state.count)
	case "p50", "p95", "p99":
		percentile := map[string]float64{"p50": .50, "p95": .95, "p99": .99}[state.function]
		var ok bool
		value, ok = histogramPercentile(state.bins, percentile)
		if !ok {
			return "", false
		}
	default:
		return "", false
	}
	return strconv.FormatFloat(value, 'g', -1, 64), true
}
