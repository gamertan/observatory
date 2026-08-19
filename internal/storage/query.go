// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
)

type projectedRecord struct {
	projectID, environmentID, serviceID string
	sourceID, streamID                  string
	sequence                            uint64
	recordIndex                         int
	signal                              model.Signal
	timestamp                           time.Time
	name, severity, body                string
	value                               *float64
	traceID, spanID, correlationID      string
	attributes                          map[string]string
}

// Query executes a validated typed AST against one organization projection.
// Authorization scope is supplied by the server, never by stored telemetry.
func (s *Store) Query(ctx context.Context, ast query.AST, scope query.Scope, budget query.Budget, now time.Time) (query.Result, error) {
	if now.IsZero() {
		return query.Result{}, errors.New("query time is required")
	}
	registry, activeVersion, err := s.ActiveDescriptors(ctx, scope.OrganizationID)
	if err != nil {
		return query.Result{}, err
	}
	coldSegments, coldEstimate, err := s.coldSegmentsForQuery(ctx, ast, scope, now)
	if err != nil {
		return query.Result{}, err
	}
	useMetricRollups := metricRollupQueryEligible(ast, registry) && len(coldSegments) == 0
	useLogRollups := indexedLogCountSummaryEligible(ast) && len(coldSegments) == 0
	var estimated int64
	if useMetricRollups {
		estimated, err = s.estimateMetricRollupBytes(ctx, scope, ast, now)
	} else if useLogRollups {
		estimated, err = s.estimateLogRollupBytes(ctx, scope, ast, now)
	} else {
		estimated, err = s.EstimateOrganizationBytes(scope.OrganizationID)
		if err == nil {
			// Record queries whose predicates are fully pushed into SQLite stop
			// after limit+1 rows. Their logical scan is therefore bounded by
			// the existing result-memory guard, not by the size of every signal
			// and index in the organization's projection file. Keep whole-file
			// planning for summaries, alternate sorts, regular expressions, and
			// cold-segment reads; execution continues to enforce the exact scan,
			// row, memory, and duration budgets in every case.
			if len(coldSegments) == 0 && projectionRowLimit(ast) > 0 && estimated > budget.MaxMemoryBytes {
				estimated = budget.MaxMemoryBytes
			}
			if coldEstimate > math.MaxInt64-estimated {
				return query.Result{}, errors.New("query scan estimate overflow")
			}
			estimated += coldEstimate
		}
	}
	if err != nil {
		return query.Result{}, err
	}
	explain, err := query.Plan(ast, scope, registry, estimated, budget)
	if err != nil {
		return query.Result{}, err
	}
	columns, err := resultColumns(ast, registry)
	if err != nil {
		return query.Result{}, err
	}
	result := query.Result{Version: query.ResultVersion, Explain: explain, Columns: columns, Rows: []query.Row{}}
	if len(coldSegments) > 0 && !useMetricRollups {
		for _, source := range append([]string(nil), result.Explain.ProjectedSources...) {
			result.Explain.ProjectedSources = append(result.Explain.ProjectedSources, source+"/cold:raw")
		}
	}
	path := filepath.Join(s.root, "organizations", scope.OrganizationID, "projection.sqlite")
	info, err := os.Lstat(path)
	projectionExists := err == nil
	if (err != nil && !errors.Is(err, os.ErrNotExist)) || (projectionExists && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0)) {
		return query.Result{}, errors.New("organization projection is unavailable")
	}
	if useMetricRollups {
		if !projectionExists {
			return result, nil
		}
		for index := range result.Explain.ProjectedSources {
			result.Explain.ProjectedSources[index] += "/rollup:5m"
		}
		return s.queryMetricRollups(ctx, path, ast, scope, registry, budget, now, result)
	}
	if projectionExists && useLogRollups {
		for index := range result.Explain.ProjectedSources {
			result.Explain.ProjectedSources[index] += "/rollup:http-status-route:5m"
		}
		return s.queryIndexedLogCountSummary(ctx, path, ast, scope, budget, now, result)
	}

	runContext, cancel := context.WithTimeout(ctx, budget.MaxDuration)
	defer cancel()
	started := time.Now()
	var records []projectedRecord
	var memoryBytes int64
	earlyLimit := ast.Summary == nil && (ast.Sort == nil || query.CanonicalField(ast.Sort.Field) == "timestamp" && ast.Sort.Descending)
	if projectionExists {
		dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
		db, openErr := sql.Open("sqlite", dsn)
		if openErr != nil {
			return query.Result{}, errors.New("open organization projection")
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		statement, arguments, selectionErr := projectionSelection(ast, scope, registry, activeVersion, now)
		if selectionErr != nil {
			return query.Result{}, selectionErr
		}
		rows, queryErr := db.QueryContext(runContext, statement, arguments...)
		if queryErr != nil {
			return query.Result{}, queryExecutionError(runContext, queryErr)
		}
		for rows.Next() {
			record, readBytes, scanErr := scanProjected(rows)
			if scanErr != nil {
				_ = rows.Close()
				if runContext.Err() != nil {
					return query.Result{}, query.ErrBudgetExceeded
				}
				return query.Result{}, errors.New("read organization projection")
			}
			if readBytes > budget.MaxScannedBytes-result.Stats.ScannedBytes {
				_ = rows.Close()
				return query.Result{}, query.ErrBudgetExceeded
			}
			if result.Stats.ScannedRows == math.MaxInt64 {
				_ = rows.Close()
				return query.Result{}, query.ErrBudgetExceeded
			}
			result.Stats.ScannedRows++
			result.Stats.ScannedBytes += readBytes
			matched, matchErr := matchesRecord(record, ast, registry)
			if matchErr != nil {
				_ = rows.Close()
				return query.Result{}, matchErr
			}
			if !matched {
				continue
			}
			if result.Stats.MatchedRows == math.MaxInt64 {
				_ = rows.Close()
				return query.Result{}, query.ErrBudgetExceeded
			}
			result.Stats.MatchedRows++
			if readBytes+256 > budget.MaxMemoryBytes-memoryBytes {
				_ = rows.Close()
				return query.Result{}, query.ErrBudgetExceeded
			}
			memoryBytes += readBytes + 256
			records = append(records, record)
			if earlyLimit && len(records) > ast.Limit {
				result.Stats.Truncated = true
				break
			}
			if err = runContext.Err(); err != nil {
				_ = rows.Close()
				return query.Result{}, query.ErrBudgetExceeded
			}
		}
		if err = rows.Err(); err != nil {
			_ = rows.Close()
			return query.Result{}, queryExecutionError(runContext, err)
		}
		if err = rows.Close(); err != nil {
			return query.Result{}, errors.New("close organization projection query")
		}
	}
	if !(earlyLimit && result.Stats.Truncated) {
		records, memoryBytes, err = s.appendRawQuerySegments(runContext, coldSegments, ast, registry, budget, now, &result, records, memoryBytes)
		if err != nil {
			return query.Result{}, err
		}
	}
	if len(coldSegments) > 0 {
		sortRawQueryRecords(records)
	}
	return finishQueryResult(result, records, ast, columns, registry, memoryBytes, budget.MaxMemoryBytes, started)
}

func (s *Store) appendRawQuerySegments(ctx context.Context, segments []rawQuerySegment, ast query.AST, registry query.Registry, budget query.Budget, now time.Time, result *query.Result, records []projectedRecord, memoryBytes int64) ([]projectedRecord, int64, error) {
	for _, segment := range segments {
		if segment.uncompressedBytes > budget.MaxMemoryBytes || segment.uncompressedBytes > budget.MaxScannedBytes-result.Stats.ScannedBytes {
			return nil, 0, query.ErrBudgetExceeded
		}
		batch, err := s.segments.Read(segment.path, segment.digest)
		if err != nil {
			return nil, 0, errors.New("read raw query segment")
		}
		if batch.SourceID != segment.sourceID || batch.StreamID != segment.streamID || batch.Sequence != segment.sequence || batch.Signal != ast.Signal || batch.Validate(batch.ObservedAt) != nil || validateMetricRollupCardinality(batch) != nil {
			return nil, 0, errors.New("raw query segment is invalid")
		}
		first, last := observationRange(batch)
		if !first.Equal(segment.firstObservedAt) || !last.Equal(segment.lastObservedAt) {
			return nil, 0, errors.New("raw query segment range does not match its catalog")
		}
		result.Stats.ScannedBytes += segment.uncompressedBytes
		for index := range batch.Records {
			if result.Stats.ScannedRows == math.MaxInt64 {
				return nil, 0, query.ErrBudgetExceeded
			}
			result.Stats.ScannedRows++
			record := rawRecord(segment, batch, index)
			if ast.Window > 0 && record.timestamp.Before(now.UTC().Add(-ast.Window)) {
				continue
			}
			matched, matchErr := matchesRecord(record, ast, registry)
			if matchErr != nil {
				return nil, 0, matchErr
			}
			if !matched {
				continue
			}
			if result.Stats.MatchedRows == math.MaxInt64 {
				return nil, 0, query.ErrBudgetExceeded
			}
			result.Stats.MatchedRows++
			recordMemory := rawRecordMemory(record)
			if recordMemory > budget.MaxMemoryBytes-memoryBytes {
				return nil, 0, query.ErrBudgetExceeded
			}
			memoryBytes += recordMemory
			records = append(records, record)
			if ctx.Err() != nil {
				return nil, 0, query.ErrBudgetExceeded
			}
		}
	}
	return records, memoryBytes, nil
}

func sortRawQueryRecords(records []projectedRecord) {
	sort.SliceStable(records, func(left, right int) bool {
		if records[left].timestamp.Equal(records[right].timestamp) {
			if records[left].sourceID == records[right].sourceID {
				if records[left].streamID == records[right].streamID {
					if records[left].sequence == records[right].sequence {
						return records[left].recordIndex > records[right].recordIndex
					}
					return records[left].sequence > records[right].sequence
				}
				return records[left].streamID < records[right].streamID
			}
			return records[left].sourceID < records[right].sourceID
		}
		return records[left].timestamp.After(records[right].timestamp)
	})
}

func finishQueryResult(result query.Result, records []projectedRecord, ast query.AST, columns []query.Column, registry query.Registry, memoryBytes, maxMemoryBytes int64, started time.Time) (query.Result, error) {
	var err error
	if ast.Summary == nil {
		result.Rows, err = materializeRecords(records, columns)
	} else {
		result.Rows, memoryBytes, err = summarizeRecords(records, ast, columns, registry, memoryBytes, maxMemoryBytes)
	}
	if err != nil {
		return query.Result{}, err
	}
	if ast.Sort != nil {
		if err = sortRows(result.Rows, columns, ast.Sort.Field, ast.Sort.Descending); err != nil {
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

func projectionSelection(ast query.AST, scope query.Scope, registry query.Registry, activeVersion int, now time.Time) (string, []any, error) {
	statement := `SELECT o.project_id,o.environment_id,o.service_id,o.source_id,o.stream_id,o.sequence,o.record_index,o.signal,o.timestamp,o.name,o.severity,o.body,o.value,o.trace_id,o.span_id,o.correlation_id,o.attributes_json FROM observations o`
	if index := summaryProjectionIndex(ast); index != "" {
		statement += " INDEXED BY " + index
	}
	var joins, predicates []string
	var joinArguments, predicateArguments []any
	indexedJoin := 0
	for _, filter := range ast.Filters {
		if filter.Op == "=~" {
			continue
		}
		field := query.CanonicalField(filter.Field)
		expression, expressionArguments := sqlFieldExpression(field)
		descriptor, unknown := query.ResolveDescriptor(ast.Signal, field, registry)
		value, err := typedFilterValue(filter.Value, descriptor.Type)
		if err != nil {
			return "", nil, err
		}
		operator := map[string]string{"==": "=", "!=": "!=", ">": ">", ">=": ">=", "<": "<", "<=": "<="}[filter.Op]
		if operator == "" {
			return "", nil, query.ErrTypeMismatch
		}
		_, builtin := query.BuiltinDescriptor(ast.Signal, field)
		if !unknown && !builtin && descriptor.Index != schema.IndexNone && activeVersion > 1 {
			table, tableErr := projectionIndexTable(activeVersion)
			if tableErr != nil {
				return "", nil, tableErr
			}
			column := "value_text"
			if descriptor.Type == schema.TypeInteger || descriptor.Type == schema.TypeFloat || descriptor.Type == schema.TypeDuration {
				column = "value_number"
			}
			if descriptor.Type == schema.TypeTime {
				parsed, parseErr := time.Parse(time.RFC3339Nano, filter.Value)
				if parseErr != nil {
					return "", nil, query.ErrTypeMismatch
				}
				value = parsed.UTC().Format(indexedTimeFormat)
			}
			alias := fmt.Sprintf("idx%d", indexedJoin)
			indexedJoin++
			joins = append(joins, " JOIN "+table+" "+alias+" ON "+alias+".signal=o.signal AND "+alias+".field=? AND "+alias+".source_id=o.source_id AND "+alias+".stream_id=o.stream_id AND "+alias+".sequence=o.sequence AND "+alias+".record_index=o.record_index AND "+alias+"."+column+operator+"?")
			joinArguments = append(joinArguments, descriptor.Field, value)
		} else {
			predicates = append(predicates, expression+operator+"?")
			predicateArguments = append(predicateArguments, expressionArguments...)
			predicateArguments = append(predicateArguments, value)
		}
	}
	statement += strings.Join(joins, "") + ` WHERE o.organization_id=? AND o.signal=?`
	arguments := append(joinArguments, scope.OrganizationID, string(ast.Signal))
	for _, selected := range []struct {
		column, value string
	}{{"project_id", scope.ProjectID}, {"environment_id", scope.EnvironmentID}, {"service_id", scope.ServiceID}} {
		if selected.value != "" {
			statement += " AND o." + selected.column + "=?"
			arguments = append(arguments, selected.value)
		}
	}
	if ast.Window > 0 {
		statement += " AND o.timestamp>=?"
		arguments = append(arguments, now.UTC().Add(-ast.Window).Format(time.RFC3339Nano))
	}
	for _, predicate := range predicates {
		statement += " AND " + predicate
	}
	arguments = append(arguments, predicateArguments...)
	if ast.Summary == nil {
		statement += ` ORDER BY o.timestamp DESC,o.source_id,o.stream_id,o.sequence DESC,o.record_index DESC`
	}
	if limit := projectionRowLimit(ast); limit > 0 {
		statement += ` LIMIT ?`
		arguments = append(arguments, limit)
	}
	return statement, arguments, nil
}

// projectionRowLimit returns the number of rows SQLite may return for a
// record query whose final result can be decided in timestamp order. The
// extra row preserves the result's truncated signal. Regular expressions are
// evaluated in Go, so they cannot safely use a pre-match SQL limit.
func projectionRowLimit(ast query.AST) int {
	if ast.Summary != nil || ast.Sort != nil && (query.CanonicalField(ast.Sort.Field) != "timestamp" || !ast.Sort.Descending) {
		return 0
	}
	for _, filter := range ast.Filters {
		if filter.Op == "=~" {
			return 0
		}
	}
	return ast.Limit + 1
}

// summaryProjectionIndex keeps selective built-in filters on their reviewed
// projection index. Summary execution is independent of input order and later
// sorts its deterministic result rows, so it must not trade the selective
// filter path for the record-level timestamp order used by ordinary queries.
func summaryProjectionIndex(ast query.AST) string {
	if ast.Summary == nil {
		return ""
	}
	for _, filter := range ast.Filters {
		if filter.Op == "=~" || filter.Op == "!=" {
			continue
		}
		switch query.CanonicalField(filter.Field) {
		case "http.status_code":
			return "observations_http_status"
		case "http.route":
			return "observations_http_route"
		case "duration_ns":
			return "observations_duration"
		case "name":
			return "observations_name"
		case "severity":
			return "observations_severity"
		case "value":
			return "observations_value"
		}
	}
	return ""
}

func sqlFieldExpression(field string) (string, []any) {
	switch query.CanonicalField(field) {
	case "project.id":
		return "o.project_id", nil
	case "environment.id":
		return "o.environment_id", nil
	case "service.id":
		return "o.service_id", nil
	case "source.id":
		return "o.source_id", nil
	case "stream.id":
		return "o.stream_id", nil
	case "timestamp", "name", "severity", "body", "value", "trace_id", "span_id", "correlation_id":
		return "o." + query.CanonicalField(field), nil
	case "http.route":
		return `json_extract(o.attributes_json,'$."http.route"')`, nil
	case "http.status_code":
		return `CAST(json_extract(o.attributes_json,'$."http.status_code"') AS INTEGER)`, nil
	case "duration_ns":
		return `CAST(json_extract(o.attributes_json,'$."duration_ns"') AS REAL)`, nil
	default:
		return "json_extract(o.attributes_json,?)", []any{`$."` + query.CanonicalField(field) + `"`}
	}
}

func typedFilterValue(value string, valueType schema.Type) (any, error) {
	switch valueType {
	case schema.TypeInteger:
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, query.ErrTypeMismatch
		}
		return parsed, nil
	case schema.TypeFloat, schema.TypeDuration:
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return nil, query.ErrTypeMismatch
		}
		return parsed, nil
	case schema.TypeBoolean:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, query.ErrTypeMismatch
		}
		return strconv.FormatBool(parsed), nil
	case schema.TypeTime:
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return nil, query.ErrTypeMismatch
		}
		return parsed.UTC().Format(time.RFC3339Nano), nil
	default:
		return value, nil
	}
}

func scanProjected(rows *sql.Rows) (projectedRecord, int64, error) {
	var record projectedRecord
	var timestamp, signal, attributes string
	var severity, body, traceID, spanID, correlationID sql.NullString
	var value sql.NullFloat64
	err := rows.Scan(&record.projectID, &record.environmentID, &record.serviceID, &record.sourceID, &record.streamID, &record.sequence, &record.recordIndex, &signal, &timestamp, &record.name, &severity, &body, &value, &traceID, &spanID, &correlationID, &attributes)
	if err != nil {
		return projectedRecord{}, 0, err
	}
	record.signal = model.Signal(signal)
	record.timestamp, err = time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return projectedRecord{}, 0, err
	}
	record.severity, record.body = severity.String, body.String
	record.traceID, record.spanID, record.correlationID = traceID.String, spanID.String, correlationID.String
	if value.Valid {
		record.value = &value.Float64
	}
	if err = json.Unmarshal([]byte(attributes), &record.attributes); err != nil {
		return projectedRecord{}, 0, errors.New("invalid projected attributes")
	}
	if record.attributes == nil {
		record.attributes = map[string]string{}
	}
	readBytes := int64(len(record.projectID) + len(record.environmentID) + len(record.serviceID) + len(record.sourceID) + len(record.streamID) + len(signal) + len(timestamp) + len(record.name) + len(record.severity) + len(record.body) + len(record.traceID) + len(record.spanID) + len(record.correlationID) + len(attributes) + 64)
	return record, readBytes, nil
}

func matchesRecord(record projectedRecord, ast query.AST, registry query.Registry) (bool, error) {
	return query.MatchesFilters(ast, registry, record.field)
}

func (record projectedRecord) field(field string) (string, bool) {
	switch query.CanonicalField(field) {
	case "project.id":
		return record.projectID, record.projectID != ""
	case "environment.id":
		return record.environmentID, record.environmentID != ""
	case "service.id":
		return record.serviceID, record.serviceID != ""
	case "source.id":
		return record.sourceID, record.sourceID != ""
	case "stream.id":
		return record.streamID, record.streamID != ""
	case "timestamp":
		return record.timestamp.UTC().Format(time.RFC3339Nano), true
	case "name":
		return record.name, record.name != ""
	case "severity":
		return record.severity, record.severity != ""
	case "body":
		return record.body, record.body != ""
	case "value":
		if record.value == nil {
			return "", false
		}
		return strconv.FormatFloat(*record.value, 'g', -1, 64), true
	case "trace_id":
		return record.traceID, record.traceID != ""
	case "span_id":
		return record.spanID, record.spanID != ""
	case "correlation_id":
		return record.correlationID, record.correlationID != ""
	default:
		value, ok := record.attributes[query.CanonicalField(field)]
		return value, ok
	}
}

func resultColumns(ast query.AST, registry query.Registry) ([]query.Column, error) {
	if ast.Summary != nil {
		var columns []query.Column
		if ast.Bucket > 0 {
			columns = append(columns, query.Column{Field: "window_start", Type: schema.TypeTime, Unit: "s"})
		}
		for _, field := range ast.Summary.GroupBy {
			canonical := query.CanonicalField(field)
			descriptor, _ := query.ResolveDescriptor(ast.Signal, canonical, registry)
			columns = append(columns, query.Column{Field: canonical, Type: descriptor.Type, Unit: descriptor.Unit})
		}
		for _, aggregate := range ast.Summary.Aggregates {
			valueType := schema.TypeFloat
			if aggregate.Function == "count" {
				valueType = schema.TypeInteger
			}
			unit := ""
			if aggregate.Field != "" {
				descriptor, _ := query.ResolveDescriptor(ast.Signal, aggregate.Field, registry)
				unit = descriptor.Unit
			}
			columns = append(columns, query.Column{Field: aggregate.Alias, Type: valueType, Unit: unit})
		}
		return columns, nil
	}
	fields := []string{"timestamp", "service.id", "name"}
	switch ast.Signal {
	case model.SignalLogs:
		fields = append(fields, "severity")
	case model.SignalMetrics:
		fields = append(fields, "value")
	case model.SignalTraces:
		fields = append(fields, "trace_id", "span_id")
	case model.SignalDeployments:
		fields = append(fields, "correlation_id")
	}
	fields = append(fields, query.ReferencedFields(ast)...)
	seen := map[string]bool{}
	columns := make([]query.Column, 0, len(fields))
	for _, field := range fields {
		canonical := query.CanonicalField(field)
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		descriptor, _ := query.ResolveDescriptor(ast.Signal, canonical, registry)
		columns = append(columns, query.Column{Field: canonical, Type: descriptor.Type, Unit: descriptor.Unit})
	}
	return columns, nil
}

func materializeRecords(records []projectedRecord, columns []query.Column) ([]query.Row, error) {
	result := make([]query.Row, 0, len(records))
	for _, record := range records {
		row := query.Row{Values: make([]*string, len(columns))}
		for index, column := range columns {
			if value, ok := record.field(column.Field); ok {
				if canonical, valid := canonicalResultValue(value, column.Type); valid {
					row.Values[index] = stringPointer(canonical)
				}
			}
		}
		result = append(result, row)
	}
	return result, nil
}

type aggregateState struct {
	function      string
	count         int64
	sum, min, max float64
	values        []float64
}

type summaryGroup struct {
	key        string
	values     []*string
	aggregates []aggregateState
}

func summarizeRecords(records []projectedRecord, ast query.AST, columns []query.Column, registry query.Registry, memoryBytes, maxMemory int64) ([]query.Row, int64, error) {
	groups := map[string]*summaryGroup{}
	for _, record := range records {
		var values []*string
		if ast.Bucket > 0 {
			bucket := record.timestamp.UTC().Truncate(ast.Bucket).Format(time.RFC3339Nano)
			values = append(values, stringPointer(bucket))
		}
		for _, field := range ast.Summary.GroupBy {
			value, ok := record.field(field)
			if ok {
				column := columns[len(values)]
				if canonical, valid := canonicalResultValue(value, column.Type); valid {
					values = append(values, stringPointer(canonical))
				} else {
					values = append(values, nil)
				}
			} else {
				values = append(values, nil)
			}
		}
		key := groupKey(values)
		group := groups[key]
		if group == nil {
			group = &summaryGroup{key: key, values: values, aggregates: make([]aggregateState, len(ast.Summary.Aggregates))}
			for index, aggregate := range ast.Summary.Aggregates {
				group.aggregates[index].function = aggregate.Function
			}
			groups[key] = group
			memoryBytes += int64(len(key) + len(values)*16 + len(group.aggregates)*64)
		}
		for index, aggregate := range ast.Summary.Aggregates {
			state := &group.aggregates[index]
			if aggregate.Function == "count" {
				state.count++
				continue
			}
			value, ok := record.field(aggregate.Field)
			if !ok {
				continue
			}
			descriptor, _ := query.ResolveDescriptor(ast.Signal, aggregate.Field, registry)
			if descriptor.Type != schema.TypeInteger && descriptor.Type != schema.TypeFloat && descriptor.Type != schema.TypeDuration {
				return nil, memoryBytes, query.ErrTypeMismatch
			}
			number, err := strconv.ParseFloat(value, 64)
			if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
				continue
			}
			if state.count == 0 {
				state.min, state.max = number, number
			} else {
				state.min = math.Min(state.min, number)
				state.max = math.Max(state.max, number)
			}
			state.count++
			state.sum += number
			if aggregate.Function == "p50" || aggregate.Function == "p95" || aggregate.Function == "p99" {
				state.values = append(state.values, number)
				memoryBytes += 8
			}
		}
		if memoryBytes > maxMemory {
			return nil, memoryBytes, query.ErrBudgetExceeded
		}
	}
	ordered := make([]*summaryGroup, 0, len(groups))
	for _, group := range groups {
		ordered = append(ordered, group)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].key < ordered[j].key })
	rows := make([]query.Row, 0, len(ordered))
	for _, group := range ordered {
		row := query.Row{Values: append([]*string(nil), group.values...)}
		for _, state := range group.aggregates {
			value, ok := aggregateValue(state)
			if ok {
				row.Values = append(row.Values, stringPointer(value))
			} else {
				row.Values = append(row.Values, nil)
			}
		}
		if len(row.Values) != len(columns) {
			return nil, memoryBytes, errors.New("summary result shape is invalid")
		}
		rows = append(rows, row)
	}
	return rows, memoryBytes, nil
}

func aggregateValue(state aggregateState) (string, bool) {
	if state.function == "count" {
		return strconv.FormatInt(state.count, 10), true
	}
	if state.count == 0 {
		return "", false
	}
	var value float64
	switch state.function {
	case "min":
		value = state.min
	case "max":
		value = state.max
	case "sum":
		value = state.sum
	case "avg":
		value = state.sum / float64(state.count)
	case "p50", "p95", "p99":
		sort.Float64s(state.values)
		percentile := map[string]float64{"p50": .50, "p95": .95, "p99": .99}[state.function]
		index := max(0, int(math.Ceil(percentile*float64(len(state.values))))-1)
		value = state.values[index]
	default:
		return "", false
	}
	return strconv.FormatFloat(value, 'g', -1, 64), true
}

func sortRows(rows []query.Row, columns []query.Column, field string, descending bool) error {
	canonical := query.CanonicalField(field)
	column := -1
	for index, candidate := range columns {
		if candidate.Field == canonical || candidate.Field == field {
			column = index
			break
		}
	}
	if column < 0 {
		return errors.New("query sort field is unavailable")
	}
	sort.SliceStable(rows, func(i, j int) bool {
		left, right := rows[i].Values[column], rows[j].Values[column]
		if left == nil {
			return false
		}
		if right == nil {
			return true
		}
		comparison, leftValid, rightValid := compareTyped(*left, *right, columns[column].Type)
		if !leftValid {
			return false
		}
		if !rightValid {
			return true
		}
		if descending {
			return comparison > 0
		}
		return comparison < 0
	})
	return nil
}

func compareTyped(left, right string, valueType schema.Type) (int, bool, bool) {
	if valueType == schema.TypeInteger || valueType == schema.TypeFloat || valueType == schema.TypeDuration {
		leftNumber, leftErr := strconv.ParseFloat(left, 64)
		rightNumber, rightErr := strconv.ParseFloat(right, 64)
		leftValid := leftErr == nil && !math.IsNaN(leftNumber) && !math.IsInf(leftNumber, 0)
		rightValid := rightErr == nil && !math.IsNaN(rightNumber) && !math.IsInf(rightNumber, 0)
		return compareFloat(leftNumber, rightNumber), leftValid, rightValid
	}
	if valueType == schema.TypeTime {
		leftTime, leftErr := time.Parse(time.RFC3339Nano, left)
		rightTime, rightErr := time.Parse(time.RFC3339Nano, right)
		return leftTime.Compare(rightTime), leftErr == nil, rightErr == nil
	}
	return strings.Compare(left, right), true, true
}

func canonicalResultValue(value string, valueType schema.Type) (string, bool) {
	switch valueType {
	case schema.TypeInteger:
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return "", false
		}
		return strconv.FormatInt(parsed, 10), true
	case schema.TypeFloat, schema.TypeDuration:
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return "", false
		}
		return strconv.FormatFloat(parsed, 'g', -1, 64), true
	case schema.TypeTime:
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return "", false
		}
		return parsed.UTC().Format(time.RFC3339Nano), true
	case schema.TypeBoolean:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return "", false
		}
		return strconv.FormatBool(parsed), true
	default:
		return value, true
	}
}

func compareFloat(left, right float64) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func groupKey(values []*string) string {
	var builder strings.Builder
	for _, value := range values {
		if value == nil {
			builder.WriteString("-1:")
			continue
		}
		builder.WriteString(strconv.Itoa(len(*value)))
		builder.WriteByte(':')
		builder.WriteString(*value)
	}
	return builder.String()
}

func stringPointer(value string) *string {
	copy := value
	return &copy
}

func queryExecutionError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return query.ErrBudgetExceeded
	}
	return fmt.Errorf("query projection: %w", err)
}
