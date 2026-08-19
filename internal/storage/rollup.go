// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
)

const (
	metricRollupVersion        = 1
	metricRollupWindow         = 5 * time.Minute
	maxMetricRollupGroupsBatch = 1024
	maxHistogramBins           = 8192
	maxHistogramJSON           = 256 << 10
	metricHistogramScale       = 64.0
	maxMetricMagnitude         = 1e25
)

type histogramBin struct {
	Bucket int64 `json:"bucket"`
	Count  int64 `json:"count"`
}

type metricRollup struct {
	bucket, projectID, environmentID, serviceID, name string
	dimensionsDigest, attributesJSON                  string
	sampleCount, valueCount                           int64
	sum, minimum, maximum, lastValue                  float64
	lastTimestamp                                     string
	bins                                              map[int64]int64
}

func validateMetricRollupCardinality(batch model.Batch) error {
	if batch.Signal != model.SignalMetrics {
		return nil
	}
	groups := map[string]struct{}{}
	sums := map[string]float64{}
	for _, observation := range batch.Records {
		if observation.Value == nil || math.Abs(*observation.Value) > maxMetricMagnitude {
			return errors.New("metric value exceeds rollup numeric range")
		}
		dimensions, err := retainedMetricDimensions(observation.Attributes, nil)
		if err != nil {
			return err
		}
		attributes, err := json.Marshal(dimensions)
		if err != nil {
			return errors.New("encode metric rollup dimensions")
		}
		bucket := observation.Timestamp.UTC().Truncate(metricRollupWindow).Format(time.RFC3339Nano)
		key := bucket + "\x00" + observation.Name + "\x00" + string(attributes)
		groups[key] = struct{}{}
		sums[key] += *observation.Value
		if math.IsNaN(sums[key]) || math.IsInf(sums[key], 0) {
			return errors.New("metric batch sum exceeds rollup numeric range")
		}
		if len(groups) > maxMetricRollupGroupsBatch {
			return fmt.Errorf("metric batch exceeds %d rollup groups", maxMetricRollupGroupsBatch)
		}
	}
	return nil
}

func ensureMetricRollups(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin metric rollup migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS storage_projection_state (id INTEGER PRIMARY KEY CHECK(id=1), metric_rollup_version INTEGER NOT NULL CHECK(metric_rollup_version BETWEEN 0 AND 1), base_index_version INTEGER NOT NULL DEFAULT 0 CHECK(base_index_version BETWEEN 0 AND 1))`,
		// Keep this insert compatible with preview databases whose state table
		// predates the independently versioned base-index migration. That
		// migration adds and initializes its own column transactionally.
		`INSERT OR IGNORE INTO storage_projection_state(id,metric_rollup_version) VALUES(1,0)`,
		`CREATE TABLE IF NOT EXISTS metric_rollups_5m (
			organization_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			environment_id TEXT NOT NULL,
			service_id TEXT NOT NULL,
			bucket_start TEXT NOT NULL,
			name TEXT NOT NULL,
			dimensions_digest TEXT NOT NULL,
			attributes_json TEXT NOT NULL,
			sample_count INTEGER NOT NULL CHECK(sample_count > 0),
			value_count INTEGER NOT NULL CHECK(value_count > 0),
			value_sum REAL NOT NULL,
			value_min REAL NOT NULL,
			value_max REAL NOT NULL,
			last_value REAL NOT NULL,
			last_timestamp TEXT NOT NULL,
			histogram_json TEXT NOT NULL,
			PRIMARY KEY(organization_id,project_id,environment_id,service_id,bucket_start,name,dimensions_digest)
		)`,
		`CREATE TABLE IF NOT EXISTS metric_rollup_segments (
			segment_digest TEXT PRIMARY KEY
		)`,
		`CREATE INDEX IF NOT EXISTS metric_rollups_time ON metric_rollups_5m(organization_id,bucket_start)`,
		`CREATE INDEX IF NOT EXISTS metric_rollups_scope ON metric_rollups_5m(organization_id,project_id,environment_id,service_id,bucket_start)`,
		`CREATE INDEX IF NOT EXISTS metric_rollups_name ON metric_rollups_5m(organization_id,name,bucket_start)`,
	} {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate metric rollups: %w", err)
		}
	}
	var version int
	if err = tx.QueryRowContext(ctx, `SELECT metric_rollup_version FROM storage_projection_state WHERE id=1`).Scan(&version); err != nil {
		return errors.New("read metric rollup migration state")
	}
	if version == 0 {
		if _, err = tx.ExecContext(ctx, `DELETE FROM metric_rollups_5m`); err != nil {
			return errors.New("clear incomplete metric rollup migration")
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM metric_rollup_segments`); err != nil {
			return errors.New("clear incomplete metric rollup segment ledger")
		}
		_, registry, _, registryErr := activeProjection(ctx, tx)
		if registryErr != nil {
			return registryErr
		}
		if err = backfillMetricRollups(ctx, tx, registry); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO metric_rollup_segments(segment_digest) SELECT DISTINCT segment_digest FROM observations WHERE signal=?`, model.SignalMetrics); err != nil {
			return errors.New("record backfilled metric rollup segments")
		}
		if _, err = tx.ExecContext(ctx, `UPDATE storage_projection_state SET metric_rollup_version=? WHERE id=1`, metricRollupVersion); err != nil {
			return errors.New("complete metric rollup migration")
		}
	} else if version != metricRollupVersion {
		return errors.New("unsupported metric rollup projection version")
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit metric rollup migration: %w", err)
	}
	return nil
}

func backfillMetricRollups(ctx context.Context, tx *sql.Tx, registry query.Registry) error {
	rows, err := tx.QueryContext(ctx, `SELECT organization_id,project_id,environment_id,service_id,timestamp,name,value,attributes_json FROM observations WHERE signal=? ORDER BY timestamp,organization_id,project_id,environment_id,service_id,name,attributes_json`, model.SignalMetrics)
	if err != nil {
		return errors.New("read metrics for rollup migration")
	}
	defer rows.Close()
	groups := map[string]*metricRollup{}
	currentBucket := ""
	for rows.Next() {
		var organizationID, projectID, environmentID, serviceID, timestampText, name, attributesJSON string
		var value float64
		if err = rows.Scan(&organizationID, &projectID, &environmentID, &serviceID, &timestampText, &name, &value, &attributesJSON); err != nil {
			return errors.New("read metric rollup migration row")
		}
		timestamp, parseErr := time.Parse(time.RFC3339Nano, timestampText)
		if parseErr != nil || math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > maxMetricMagnitude {
			return errors.New("metric rollup migration row is invalid")
		}
		var attributes map[string]string
		if err = json.Unmarshal([]byte(attributesJSON), &attributes); err != nil {
			return errors.New("metric rollup migration dimensions are invalid")
		}
		retainedAttributes, retainErr := retainedMetricDimensions(attributes, registry)
		if retainErr != nil {
			return retainErr
		}
		retainedJSON, marshalErr := json.Marshal(retainedAttributes)
		if marshalErr != nil {
			return errors.New("encode metric rollup migration dimensions")
		}
		attributesJSON = string(retainedJSON)
		bucket := timestamp.UTC().Truncate(metricRollupWindow).Format(time.RFC3339Nano)
		if currentBucket != "" && bucket != currentBucket {
			if err = flushMetricRollups(ctx, tx, groups); err != nil {
				return err
			}
			groups = map[string]*metricRollup{}
		}
		currentBucket = bucket
		rollupKey, digest := metricRollupKey(projectID, environmentID, serviceID, bucket, name, attributesJSON)
		key := organizationID + "\x00" + rollupKey
		rollup := groups[key]
		if rollup == nil {
			rollup = newMetricRollup(projectID, environmentID, serviceID, bucket, name, attributesJSON, digest)
			groups[key] = rollup
		}
		addMetricValue(rollup, timestamp, value)
		if len(groups) >= maxMetricRollupGroupsBatch {
			if err = flushMetricRollups(ctx, tx, groups); err != nil {
				return err
			}
			groups = map[string]*metricRollup{}
		}
	}
	if err = rows.Err(); err != nil {
		return errors.New("read metric rollup migration rows")
	}
	return flushMetricRollups(ctx, tx, groups)
}

func projectMetricRollups(ctx context.Context, tx *sql.Tx, scope model.Scope, batch model.Batch, segmentDigest string, registry query.Registry) error {
	if batch.Signal != model.SignalMetrics {
		return nil
	}
	ledger, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO metric_rollup_segments(segment_digest) VALUES(?)`, segmentDigest)
	if err != nil {
		return errors.New("record metric rollup segment")
	}
	inserted, err := ledger.RowsAffected()
	if err != nil {
		return errors.New("inspect metric rollup segment")
	}
	if inserted == 0 {
		return nil
	}
	groups := map[string]*metricRollup{}
	for _, observation := range batch.Records {
		retained, err := retainedMetricDimensions(observation.Attributes, registry)
		if err != nil {
			return err
		}
		attributes, err := json.Marshal(retained)
		if err != nil {
			return errors.New("encode metric rollup dimensions")
		}
		bucket := observation.Timestamp.UTC().Truncate(metricRollupWindow).Format(time.RFC3339Nano)
		key, digest := metricRollupKey(scope.ProjectID, scope.EnvironmentID, scope.ServiceID, bucket, observation.Name, string(attributes))
		rollup := groups[key]
		if rollup == nil {
			rollup = newMetricRollup(scope.ProjectID, scope.EnvironmentID, scope.ServiceID, bucket, observation.Name, string(attributes), digest)
			groups[key] = rollup
			if len(groups) > maxMetricRollupGroupsBatch {
				return fmt.Errorf("metric batch exceeds %d projected rollup groups", maxMetricRollupGroupsBatch)
			}
		}
		addMetricValue(rollup, observation.Timestamp.UTC(), *observation.Value)
	}
	for _, rollup := range groups {
		if err := mergeMetricRollup(ctx, tx, scope.OrganizationID, rollup); err != nil {
			return err
		}
	}
	return nil
}

func retainedMetricDimensions(attributes map[string]string, registry query.Registry) (map[string]string, error) {
	retained := map[string]string{}
	for field, value := range attributes {
		canonical := query.CanonicalField(field)
		descriptor, unknown := query.ResolveDescriptor(model.SignalMetrics, canonical, registry)
		if unknown || descriptor.Retention != schema.RetentionMetric || descriptor.Sensitivity == schema.SensitivitySensitive || descriptor.Cardinality == schema.CardinalityHigh {
			continue
		}
		if len(retained) >= model.MaxAttributes {
			return nil, errors.New("metric rollup dimension limit exceeded")
		}
		if _, exists := retained[canonical]; exists {
			return nil, errors.New("metric rollup dimensions contain a canonical alias collision")
		}
		retained[canonical] = value
	}
	return retained, nil
}

func newMetricRollup(projectID, environmentID, serviceID, bucket, name, attributesJSON, digest string) *metricRollup {
	return &metricRollup{bucket: bucket, projectID: projectID, environmentID: environmentID, serviceID: serviceID, name: name, dimensionsDigest: digest, attributesJSON: attributesJSON, bins: map[int64]int64{}}
}

func addMetricValue(rollup *metricRollup, timestamp time.Time, value float64) {
	rollup.sampleCount++
	rollup.valueCount++
	rollup.sum += value
	if rollup.valueCount == 1 || value < rollup.minimum {
		rollup.minimum = value
	}
	if rollup.valueCount == 1 || value > rollup.maximum {
		rollup.maximum = value
	}
	stamp := timestamp.UTC().Format(time.RFC3339Nano)
	if rollup.lastTimestamp == "" || stamp >= rollup.lastTimestamp {
		rollup.lastTimestamp, rollup.lastValue = stamp, value
	}
	rollup.bins[metricHistogramBucket(value)]++
}

func metricRollupKey(projectID, environmentID, serviceID, bucket, name, attributesJSON string) (string, string) {
	dimensions := sha256.Sum256([]byte(name + "\x00" + attributesJSON))
	digest := hex.EncodeToString(dimensions[:])
	return projectID + "\x00" + environmentID + "\x00" + serviceID + "\x00" + bucket + "\x00" + name + "\x00" + digest, digest
}

func flushMetricRollups(ctx context.Context, tx *sql.Tx, groups map[string]*metricRollup) error {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		// Backfill keys prefix the organization. Split once; identifiers cannot
		// contain NUL under the model validation contract.
		separator := -1
		for index := 0; index < len(key); index++ {
			if key[index] == 0 {
				separator = index
				break
			}
		}
		if separator < 1 {
			return errors.New("metric rollup migration key is invalid")
		}
		if err := mergeMetricRollup(ctx, tx, key[:separator], groups[key]); err != nil {
			return err
		}
	}
	return nil
}

func mergeMetricRollup(ctx context.Context, tx *sql.Tx, organizationID string, incoming *metricRollup) error {
	var stored metricRollup
	var histogram string
	err := tx.QueryRowContext(ctx, `SELECT attributes_json,sample_count,value_count,value_sum,value_min,value_max,last_value,last_timestamp,histogram_json FROM metric_rollups_5m WHERE organization_id=? AND project_id=? AND environment_id=? AND service_id=? AND bucket_start=? AND name=? AND dimensions_digest=?`, organizationID, incoming.projectID, incoming.environmentID, incoming.serviceID, incoming.bucket, incoming.name, incoming.dimensionsDigest).Scan(&stored.attributesJSON, &stored.sampleCount, &stored.valueCount, &stored.sum, &stored.minimum, &stored.maximum, &stored.lastValue, &stored.lastTimestamp, &histogram)
	if err == nil {
		if stored.attributesJSON != incoming.attributesJSON {
			return errors.New("metric rollup dimension digest collision")
		}
		stored.bins, err = decodeHistogram(histogram)
		if err != nil {
			return err
		}
		stored.projectID, stored.environmentID, stored.serviceID, stored.bucket, stored.name, stored.dimensionsDigest = incoming.projectID, incoming.environmentID, incoming.serviceID, incoming.bucket, incoming.name, incoming.dimensionsDigest
		if stored.sampleCount > math.MaxInt64-incoming.sampleCount || stored.valueCount > math.MaxInt64-incoming.valueCount {
			return errors.New("metric rollup count exceeds numeric range")
		}
		stored.sampleCount += incoming.sampleCount
		stored.valueCount += incoming.valueCount
		stored.sum += incoming.sum
		if math.IsNaN(stored.sum) || math.IsInf(stored.sum, 0) {
			return errors.New("metric rollup sum exceeds numeric range")
		}
		stored.minimum = math.Min(stored.minimum, incoming.minimum)
		stored.maximum = math.Max(stored.maximum, incoming.maximum)
		if incoming.lastTimestamp >= stored.lastTimestamp {
			stored.lastTimestamp, stored.lastValue = incoming.lastTimestamp, incoming.lastValue
		}
		for bucket, count := range incoming.bins {
			if stored.bins[bucket] > math.MaxInt64-count {
				return errors.New("metric histogram count exceeds numeric range")
			}
			stored.bins[bucket] += count
		}
		incoming = &stored
	} else if !errors.Is(err, sql.ErrNoRows) {
		return errors.New("read metric rollup")
	}
	histogram, err = encodeHistogram(incoming.bins)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO metric_rollups_5m(organization_id,project_id,environment_id,service_id,bucket_start,name,dimensions_digest,attributes_json,sample_count,value_count,value_sum,value_min,value_max,last_value,last_timestamp,histogram_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(organization_id,project_id,environment_id,service_id,bucket_start,name,dimensions_digest) DO UPDATE SET sample_count=excluded.sample_count,value_count=excluded.value_count,value_sum=excluded.value_sum,value_min=excluded.value_min,value_max=excluded.value_max,last_value=excluded.last_value,last_timestamp=excluded.last_timestamp,histogram_json=excluded.histogram_json WHERE metric_rollups_5m.attributes_json=excluded.attributes_json`, organizationID, incoming.projectID, incoming.environmentID, incoming.serviceID, incoming.bucket, incoming.name, incoming.dimensionsDigest, incoming.attributesJSON, incoming.sampleCount, incoming.valueCount, incoming.sum, incoming.minimum, incoming.maximum, incoming.lastValue, incoming.lastTimestamp, histogram)
	if err != nil {
		return errors.New("store metric rollup")
	}
	return nil
}

func encodeHistogram(bins map[int64]int64) (string, error) {
	if len(bins) < 1 || len(bins) > maxHistogramBins {
		return "", errors.New("metric histogram bin count is invalid")
	}
	keys := make([]int64, 0, len(bins))
	for bucket, count := range bins {
		if count < 1 {
			return "", errors.New("metric histogram count is invalid")
		}
		keys = append(keys, bucket)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	encoded := make([]histogramBin, 0, len(keys))
	for _, bucket := range keys {
		encoded = append(encoded, histogramBin{Bucket: bucket, Count: bins[bucket]})
	}
	body, err := json.Marshal(encoded)
	if err != nil || len(body) > maxHistogramJSON {
		return "", errors.New("metric histogram encoding exceeds limit")
	}
	return string(body), nil
}

func decodeHistogram(encoded string) (map[int64]int64, error) {
	if len(encoded) < 2 || len(encoded) > maxHistogramJSON {
		return nil, errors.New("metric histogram encoding is invalid")
	}
	var values []histogramBin
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&values); err != nil || len(values) < 1 || len(values) > maxHistogramBins {
		return nil, errors.New("metric histogram encoding is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("metric histogram encoding is invalid")
	}
	bins := make(map[int64]int64, len(values))
	var previous int64
	for index, value := range values {
		if value.Count < 1 || index > 0 && value.Bucket <= previous {
			return nil, errors.New("metric histogram encoding is invalid")
		}
		bins[value.Bucket] = value.Count
		previous = value.Bucket
	}
	return bins, nil
}

func metricHistogramBucket(value float64) int64 {
	if value == 0 {
		return 0
	}
	bucket := int64(math.Round(math.Log1p(math.Abs(value))*metricHistogramScale)) + 1
	if value < 0 {
		return -bucket
	}
	return bucket
}

func metricHistogramValue(bucket int64) float64 {
	if bucket == 0 {
		return 0
	}
	sign := 1.0
	if bucket < 0 {
		sign, bucket = -1, -bucket
	}
	return sign * math.Expm1(float64(bucket-1)/metricHistogramScale)
}

func histogramPercentile(bins map[int64]int64, percentile float64) (float64, bool) {
	var total int64
	keys := make([]int64, 0, len(bins))
	for bucket, count := range bins {
		if count < 1 || total > math.MaxInt64-count {
			return 0, false
		}
		total += count
		keys = append(keys, bucket)
	}
	if total == 0 {
		return 0, false
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	target := int64(math.Ceil(percentile * float64(total)))
	var seen int64
	for _, bucket := range keys {
		seen += bins[bucket]
		if seen >= target {
			return metricHistogramValue(bucket), true
		}
	}
	return 0, false
}

func histogramCanonical(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}
