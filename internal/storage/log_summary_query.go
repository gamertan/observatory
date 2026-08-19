// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
)

// indexedLogCountSummaryEligible identifies the typed status/route count
// summary maintained as an exact five-minute projection. Larger bucket sizes
// can combine those rows; a partial lower window boundary scans at most one
// five-minute fragment from the primary projection.
func indexedLogCountSummaryEligible(ast query.AST) bool {
	if ast.Signal != model.SignalLogs || ast.Summary == nil || len(ast.Summary.Aggregates) != 1 || len(ast.Summary.GroupBy) != 1 {
		return false
	}
	aggregate := ast.Summary.Aggregates[0]
	if aggregate.Function != "count" || aggregate.Field != "" || query.CanonicalField(ast.Summary.GroupBy[0]) != "http.route" {
		return false
	}
	if ast.Bucket != 0 && (ast.Bucket < logRollupWindow || ast.Bucket%logRollupWindow != 0) {
		return false
	}
	if len(ast.Filters) != 1 || query.CanonicalField(ast.Filters[0].Field) != "http.status_code" {
		return false
	}
	threshold, err := strconv.Atoi(ast.Filters[0].Value)
	return err == nil && threshold >= 100 && threshold <= 999 && ast.Filters[0].Op == ">="
}

// estimateLogRollupBytes accounts for the compact rows the optimized query
// reads, plus at most one raw five-minute fragment when the requested lower
// boundary does not align with a rollup bucket. It deliberately does not use
// a client-supplied estimate or treat logical observation bytes as physical
// scan cost.
func (s *Store) estimateLogRollupBytes(ctx context.Context, scope query.Scope, ast query.AST, now time.Time) (int64, error) {
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
		return 0, errors.New("open log rollup estimate")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	status, err := typedFilterValue(ast.Filters[0].Value, schema.TypeInteger)
	if err != nil {
		return 0, err
	}
	cutoff, rollupStart := logRollupWindowStart(ast, now)
	statement := `SELECT COALESCE(SUM(96+LENGTH(project_id)+LENGTH(environment_id)+LENGTH(service_id)+LENGTH(route)),0) FROM log_status_route_rollups_5m WHERE organization_id=? AND status>=?`
	arguments := []any{scope.OrganizationID, status}
	for _, selected := range []struct{ column, value string }{{"project_id", scope.ProjectID}, {"environment_id", scope.EnvironmentID}, {"service_id", scope.ServiceID}} {
		if selected.value != "" {
			statement += " AND " + selected.column + "=?"
			arguments = append(arguments, selected.value)
		}
	}
	if ast.Window > 0 {
		statement += ` AND bucket_start>=?`
		arguments = append(arguments, rollupStart)
	}
	var estimated int64
	if err = db.QueryRowContext(ctx, statement, arguments...).Scan(&estimated); err != nil || estimated < 0 {
		return 0, errors.New("estimate log rollup scan")
	}
	if ast.Window == 0 || !cutoff.Before(time.Unix(rollupStart, 0).UTC()) {
		return estimated, nil
	}
	raw := `SELECT COALESCE(SUM(` + logObservationBytesSQL + `),0) FROM observations o INDEXED BY observations_http_status WHERE o.organization_id=? AND o.signal=?`
	rawArguments := []any{scope.OrganizationID, string(ast.Signal)}
	for _, selected := range []struct{ column, value string }{{"project_id", scope.ProjectID}, {"environment_id", scope.EnvironmentID}, {"service_id", scope.ServiceID}} {
		if selected.value != "" {
			raw += " AND o." + selected.column + "=?"
			rawArguments = append(rawArguments, selected.value)
		}
	}
	raw += ` AND o.timestamp>=? AND o.timestamp<?`
	rawArguments = append(rawArguments, cutoff.Format(time.RFC3339Nano), time.Unix(rollupStart, 0).UTC().Format(time.RFC3339Nano))
	statusExpression := `json_extract(o.attributes_json,'$."http.status_code"')`
	raw += ` AND printf('%d',CAST(` + statusExpression + ` AS INTEGER))=` + statusExpression + ` AND CAST(` + statusExpression + ` AS INTEGER)>=?`
	rawArguments = append(rawArguments, status)
	var partial int64
	if err = db.QueryRowContext(ctx, raw, rawArguments...).Scan(&partial); err != nil || partial < 0 || partial > math.MaxInt64-estimated {
		return 0, errors.New("estimate partial log rollup scan")
	}
	return estimated + partial, nil
}

func logRollupWindowStart(ast query.AST, now time.Time) (time.Time, int64) {
	if ast.Window == 0 {
		return time.Time{}, math.MinInt64
	}
	cutoff := now.UTC().Add(-ast.Window)
	start := cutoff.Truncate(logRollupWindow)
	if !start.Equal(cutoff) {
		start = start.Add(logRollupWindow)
	}
	return cutoff, start.Unix()
}

type logSummaryKey struct {
	bucket       int64
	route        string
	routePresent bool
}

type logSummaryValue struct {
	count, scannedBytes int64
}

func (s *Store) queryIndexedLogCountSummary(ctx context.Context, path string, ast query.AST, scope query.Scope, budget query.Budget, now time.Time, result query.Result) (query.Result, error) {
	runContext, cancel := context.WithTimeout(ctx, budget.MaxDuration)
	defer cancel()
	started := time.Now()
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return query.Result{}, errors.New("open indexed log summary")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	status, statusErr := typedFilterValue(ast.Filters[0].Value, schema.TypeInteger)
	if statusErr != nil {
		return query.Result{}, statusErr
	}
	groups := map[logSummaryKey]logSummaryValue{}
	cutoff, rollupStart := logRollupWindowStart(ast, now)

	selects := []string{}
	arguments := []any{}
	groupColumns := "route,route_present"
	if ast.Bucket > 0 {
		seconds := int64(ast.Bucket / time.Second)
		selects = append(selects, `CAST(bucket_start/? AS INTEGER)*?`)
		arguments = append(arguments, seconds, seconds)
		groupColumns = "1,route,route_present"
	}
	selects = append(selects, `route`, `route_present`, `SUM(observation_count)`, `SUM(scanned_bytes)`)
	statement := `SELECT ` + joinSQL(selects) + ` FROM log_status_route_rollups_5m WHERE organization_id=?`
	arguments = append(arguments, scope.OrganizationID)
	for _, selected := range []struct{ column, value string }{{"project_id", scope.ProjectID}, {"environment_id", scope.EnvironmentID}, {"service_id", scope.ServiceID}} {
		if selected.value != "" {
			statement += " AND " + selected.column + "=?"
			arguments = append(arguments, selected.value)
		}
	}
	statement += ` AND status>=?`
	arguments = append(arguments, status)
	if ast.Window > 0 {
		statement += ` AND bucket_start>=?`
		arguments = append(arguments, rollupStart)
	}
	statement += ` GROUP BY ` + groupColumns
	rows, err := db.QueryContext(runContext, statement, arguments...)
	if err != nil {
		return query.Result{}, queryExecutionError(runContext, err)
	}
	if err = readLogSummaryRows(rows, ast.Bucket > 0, groups); err != nil {
		return query.Result{}, queryExecutionError(runContext, err)
	}

	if ast.Window > 0 && cutoff.Unix() < rollupStart {
		rawSelects := []string{}
		rawArguments := []any{}
		rawGroupColumns := `json_extract(o.attributes_json,'$."http.route"'),CASE WHEN json_type(o.attributes_json,'$."http.route"') IS NULL THEN 0 ELSE 1 END`
		if ast.Bucket > 0 {
			seconds := int64(ast.Bucket / time.Second)
			rawSelects = append(rawSelects, `CAST(unixepoch(o.timestamp)/? AS INTEGER)*?`)
			rawArguments = append(rawArguments, seconds, seconds)
			rawGroupColumns = `1,` + rawGroupColumns
		}
		rawSelects = append(rawSelects, `json_extract(o.attributes_json,'$."http.route"')`, `CASE WHEN json_type(o.attributes_json,'$."http.route"') IS NULL THEN 0 ELSE 1 END`, `COUNT(*)`, `COALESCE(SUM(`+logObservationBytesSQL+`),0)`)
		raw := `SELECT ` + joinSQL(rawSelects) + ` FROM observations o INDEXED BY observations_http_status WHERE o.organization_id=? AND o.signal=?`
		rawArguments = append(rawArguments, scope.OrganizationID, string(ast.Signal))
		for _, selected := range []struct{ column, value string }{{"project_id", scope.ProjectID}, {"environment_id", scope.EnvironmentID}, {"service_id", scope.ServiceID}} {
			if selected.value != "" {
				raw += " AND o." + selected.column + "=?"
				rawArguments = append(rawArguments, selected.value)
			}
		}
		raw += ` AND o.timestamp>=? AND o.timestamp<?`
		rawArguments = append(rawArguments, cutoff.Format(time.RFC3339Nano), time.Unix(rollupStart, 0).UTC().Format(time.RFC3339Nano))
		statusExpression := `json_extract(o.attributes_json,'$."http.status_code"')`
		raw += ` AND printf('%d',CAST(` + statusExpression + ` AS INTEGER))=` + statusExpression + ` AND CAST(` + statusExpression + ` AS INTEGER)>=? GROUP BY ` + rawGroupColumns
		rawArguments = append(rawArguments, status)
		partial, queryErr := db.QueryContext(runContext, raw, rawArguments...)
		if queryErr != nil {
			return query.Result{}, queryExecutionError(runContext, queryErr)
		}
		if err = readLogSummaryRows(partial, ast.Bucket > 0, groups); err != nil {
			return query.Result{}, queryExecutionError(runContext, err)
		}
	}

	keys := make([]logSummaryKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].bucket != keys[right].bucket {
			return keys[left].bucket < keys[right].bucket
		}
		if keys[left].routePresent != keys[right].routePresent {
			return !keys[left].routePresent
		}
		return keys[left].route < keys[right].route
	})
	var memoryBytes int64
	maximumInt := int64(^uint(0) >> 1)
	for _, key := range keys {
		value := groups[key]
		if value.count < 1 || value.scannedBytes < 0 || value.count > maximumInt-int64(result.Stats.ScannedRows) || value.scannedBytes > budget.MaxScannedBytes-result.Stats.ScannedBytes {
			return query.Result{}, query.ErrBudgetExceeded
		}
		addition := int64(256 + len(key.route))
		if addition > budget.MaxMemoryBytes-memoryBytes {
			return query.Result{}, query.ErrBudgetExceeded
		}
		memoryBytes += addition
		result.Stats.ScannedRows += int(value.count)
		result.Stats.MatchedRows += int(value.count)
		result.Stats.ScannedBytes += value.scannedBytes
		values := make([]*string, 0, len(result.Columns))
		if ast.Bucket > 0 {
			bucket := time.Unix(key.bucket, 0).UTC().Format(time.RFC3339Nano)
			values = append(values, stringPointer(bucket))
		}
		if key.routePresent {
			values = append(values, stringPointer(key.route))
		} else {
			values = append(values, nil)
		}
		values = append(values, stringPointer(strconv.FormatInt(value.count, 10)))
		result.Rows = append(result.Rows, query.Row{Values: values})
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

func readLogSummaryRows(rows *sql.Rows, bucketed bool, groups map[logSummaryKey]logSummaryValue) error {
	defer rows.Close()
	for rows.Next() {
		var bucket sql.NullInt64
		var route sql.NullString
		var routePresent int
		var count, scannedBytes int64
		var err error
		if bucketed {
			err = rows.Scan(&bucket, &route, &routePresent, &count, &scannedBytes)
		} else {
			err = rows.Scan(&route, &routePresent, &count, &scannedBytes)
		}
		if err != nil || bucketed && !bucket.Valid || routePresent < 0 || routePresent > 1 || routePresent == 1 && !route.Valid || count < 1 || scannedBytes < 0 {
			return errors.New("read indexed log summary")
		}
		key := logSummaryKey{routePresent: routePresent == 1}
		if bucketed {
			key.bucket = bucket.Int64
		}
		if route.Valid {
			key.route = route.String
		}
		current := groups[key]
		if count > math.MaxInt64-current.count || scannedBytes > math.MaxInt64-current.scannedBytes {
			return query.ErrBudgetExceeded
		}
		current.count += count
		current.scannedBytes += scannedBytes
		groups[key] = current
	}
	return rows.Err()
}

func joinSQL(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	joined := parts[0]
	for _, part := range parts[1:] {
		joined += "," + part
	}
	return joined
}
