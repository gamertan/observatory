//go:build observatory_capacity_fixture && linux

// SPDX-License-Identifier: AGPL-3.0-only

// Command capacitytest runs the bounded Observatory capacity and recovery
// campaign. It is excluded from ordinary builds and emits only aggregate,
// synthetic evidence.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/spool"
	"gamertan.com/observatory/internal/storage"
)

const (
	reportVersion                = 2
	visibilityObservationTimeout = 30 * time.Second
)

type settings struct {
	sustainRate     int
	sustainDuration time.Duration
	burstRate       int
	burstDuration   time.Duration
	minimumPrimary  int64
	queryIterations int
	organizations   int
	primaryWeight   int
	batchInterval   time.Duration
	requireCgroup   bool
	expectedCPUs    int
	expectedMemory  int64
}

type phaseReport struct {
	TargetRate             int     `json:"target_rate_per_second"`
	DurationSeconds        float64 `json:"target_duration_seconds"`
	Observations           int64   `json:"observations"`
	ElapsedSeconds         float64 `json:"elapsed_seconds"`
	AchievedRate           float64 `json:"achieved_rate_per_second"`
	IngestP50Milliseconds  float64 `json:"ingest_p50_milliseconds"`
	IngestP95Milliseconds  float64 `json:"ingest_p95_milliseconds"`
	IngestP99Milliseconds  float64 `json:"ingest_p99_milliseconds"`
	VisibleP50Milliseconds float64 `json:"visible_p50_milliseconds"`
	VisibleP95Milliseconds float64 `json:"visible_p95_milliseconds"`
	VisibleP99Milliseconds float64 `json:"visible_p99_milliseconds"`
}

type queryReport struct {
	Name                string  `json:"name"`
	Iterations          int     `json:"iterations"`
	P50Milliseconds     float64 `json:"p50_milliseconds"`
	P95Milliseconds     float64 `json:"p95_milliseconds"`
	P99Milliseconds     float64 `json:"p99_milliseconds"`
	MaximumScannedRows  int64   `json:"maximum_scanned_rows"`
	MaximumScannedBytes int64   `json:"maximum_scanned_bytes"`
}

type spoolReport struct {
	Batches             int     `json:"batches"`
	Observations        int64   `json:"observations"`
	OldestAgeHours      float64 `json:"oldest_age_hours"`
	Replayed            int64   `json:"replayed_observations"`
	RemainingAfterAck   int     `json:"remaining_after_ack"`
	DuplicateRecognized bool    `json:"duplicate_recognized"`
}

type retentionEvidence struct {
	ArchivedSegments      int   `json:"archived_segments"`
	ArchivedBytes         int64 `json:"archived_bytes"`
	RemovedSegments       int   `json:"removed_segments"`
	RemovedBytes          int64 `json:"removed_bytes"`
	ProjectionRowsRemoved int64 `json:"projection_rows_removed"`
	ColdQueryRows         int   `json:"cold_query_rows"`
}

type resourceReport struct {
	GOMAXPROCS       int     `json:"gomaxprocs"`
	CPUQuota         float64 `json:"cpu_quota"`
	MemoryLimitBytes int64   `json:"memory_limit_bytes"`
	MaximumRSSBytes  int64   `json:"maximum_rss_bytes"`
	DatasetBytes     int64   `json:"dataset_bytes"`
}

type projectionDrainReport struct {
	PendingSegments  int     `json:"pending_segments_at_start"`
	PendingBytes     int64   `json:"pending_bytes_at_start"`
	OldestLagSeconds float64 `json:"oldest_pending_lag_seconds_at_start"`
	ElapsedSeconds   float64 `json:"elapsed_seconds"`
}

type storageClass struct {
	Files int   `json:"files"`
	Bytes int64 `json:"bytes"`
}

type storageBreakdown struct {
	Raw               storageClass        `json:"raw_segments"`
	Projection        storageClass        `json:"projection_sqlite"`
	Control           storageClass        `json:"control_sqlite"`
	Other             storageClass        `json:"other"`
	Total             storageClass        `json:"total"`
	SQLitePageClasses sqlitePageBreakdown `json:"primary_projection_sqlite_page_classes"`
	SQLiteBytes       map[string]int64    `json:"primary_projection_sqlite_objects"`
}

type sqlitePageBreakdown struct {
	Tables   int64 `json:"tables_bytes"`
	Indexes  int64 `json:"indexes_bytes"`
	Internal int64 `json:"internal_bytes"`
	Total    int64 `json:"total_bytes"`
}

type campaignReport struct {
	Version             int                   `json:"version"`
	StartedAt           time.Time             `json:"started_at"`
	CompletedAt         time.Time             `json:"completed_at"`
	Organizations       int                   `json:"organizations"`
	PrimaryPhaseWeight  int                   `json:"primary_phase_weight"`
	TotalObservations   int64                 `json:"total_observations"`
	PrimaryObservations int64                 `json:"primary_observations"`
	Sustain             phaseReport           `json:"sustain"`
	Burst               phaseReport           `json:"burst"`
	FillSeconds         float64               `json:"fill_seconds"`
	ProjectionDrain     projectionDrainReport `json:"projection_drain"`
	PrimaryStorage      storageBreakdown      `json:"primary_storage"`
	Queries             []queryReport         `json:"queries"`
	Spool               spoolReport           `json:"spool"`
	Retention           retentionEvidence     `json:"retention"`
	Resources           resourceReport        `json:"resources"`
	Pass                bool                  `json:"pass"`
}

type sourceState struct {
	index          int
	weight         int64
	organizationID string
	sourceID       string
	token          string
	sequences      map[model.Signal]uint64
	count          atomic.Int64
}

type measurements struct {
	mu         sync.Mutex
	ingest     []time.Duration
	visibility []time.Duration
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "capacity campaign failed:", err)
		os.Exit(1)
	}
}

func run() error {
	configuration := settings{}
	flag.IntVar(&configuration.sustainRate, "sustain-rate", 2_000, "sustained mixed observations per second")
	flag.DurationVar(&configuration.sustainDuration, "sustain-duration", time.Hour, "sustained campaign duration")
	flag.IntVar(&configuration.burstRate, "burst-rate", 10_000, "burst observations per second")
	flag.DurationVar(&configuration.burstDuration, "burst-duration", time.Minute, "burst campaign duration")
	flag.Int64Var(&configuration.minimumPrimary, "minimum-primary-observations", 10_000_000, "minimum observations in the primary organization")
	flag.IntVar(&configuration.queryIterations, "query-iterations", 20, "iterations per common query")
	flag.IntVar(&configuration.organizations, "organizations", 4, "concurrent organizations")
	flag.IntVar(&configuration.primaryWeight, "primary-phase-weight", 1, "relative phase weight of the primary organization")
	flag.DurationVar(&configuration.batchInterval, "batch-interval", 500*time.Millisecond, "batch scheduling interval")
	flag.BoolVar(&configuration.requireCgroup, "require-cgroup", false, "require exact CPU and memory cgroup limits")
	flag.IntVar(&configuration.expectedCPUs, "expected-cpus", 4, "required CPU quota")
	flag.Int64Var(&configuration.expectedMemory, "expected-memory-bytes", 8<<30, "required memory limit")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("capacity campaign accepts no positional arguments")
	}
	if err := configuration.validate(); err != nil {
		return err
	}
	cpuQuota, memoryLimit, err := cgroupLimits()
	if err != nil && configuration.requireCgroup {
		return err
	}
	if configuration.requireCgroup && (math.Abs(cpuQuota-float64(configuration.expectedCPUs)) > 0.001 || memoryLimit != configuration.expectedMemory || runtime.GOMAXPROCS(0) != configuration.expectedCPUs) {
		return fmt.Errorf("resource boundary differs: cpu=%.3f memory=%d gomaxprocs=%d", cpuQuota, memoryLimit, runtime.GOMAXPROCS(0))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	root, err := os.MkdirTemp("", "observatory-capacity-")
	if err != nil {
		return errors.New("create capacity workspace")
	}
	defer os.RemoveAll(root)
	if err = os.Chmod(root, 0o700); err != nil {
		return errors.New("protect capacity workspace")
	}
	store, err := storage.Open(filepath.Join(root, "dataset"))
	if err != nil {
		return err
	}
	defer store.Close()
	projectorContext, stopProjector := context.WithCancel(ctx)
	projectorDone := make(chan struct{})
	projectorErrors := make(chan error, 1)
	go func() {
		defer close(projectorDone)
		store.RunProjector(projectorContext, 100*time.Millisecond, func(projectErr error) {
			select {
			case projectorErrors <- projectErr:
			default:
			}
		})
	}()
	defer func() {
		stopProjector()
		<-projectorDone
	}()
	states, err := createSources(ctx, store, configuration.organizations, configuration.primaryWeight)
	if err != nil {
		return err
	}
	report := campaignReport{Version: reportVersion, StartedAt: time.Now().UTC(), Organizations: len(states), PrimaryPhaseWeight: configuration.primaryWeight}
	seed := &atomic.Uint64{}
	fmt.Fprintln(os.Stderr, "stage=sustain")
	report.Sustain, err = runPhase(ctx, store, states, seed, configuration.sustainRate, configuration.sustainDuration, configuration.batchInterval)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "stage=burst")
	report.Burst, err = runPhase(ctx, store, states, seed, configuration.burstRate, configuration.burstDuration, configuration.batchInterval)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "stage=fill")
	fillStarted := time.Now()
	if err = fillPrimary(ctx, store, states[0], seed, configuration.minimumPrimary); err != nil {
		return err
	}
	report.FillSeconds = time.Since(fillStarted).Seconds()
	report.PrimaryObservations = states[0].count.Load()
	for _, state := range states {
		report.TotalObservations += state.count.Load()
	}
	if report.PrimaryObservations < configuration.minimumPrimary {
		return errors.New("primary dataset did not reach the required observation count")
	}
	drainStarted := time.Now()
	drainStart, statusErr := store.ProjectionStatus(ctx, drainStarted.UTC())
	if statusErr != nil {
		return statusErr
	}
	report.ProjectionDrain = projectionDrainReport{
		PendingSegments:  drainStart.PendingSegments,
		PendingBytes:     drainStart.PendingBytes,
		OldestLagSeconds: drainStart.OldestPendingLag.Seconds(),
	}
	if err = waitForProjection(ctx, store, projectorErrors, 10*time.Minute); err != nil {
		return err
	}
	report.ProjectionDrain.ElapsedSeconds = time.Since(drainStarted).Seconds()
	fmt.Fprintln(os.Stderr, "stage=queries")
	report.Queries, err = runQueries(ctx, store, states[0].organizationID, configuration.queryIterations)
	if err != nil {
		return err
	}
	report.PrimaryStorage, err = measureStorage(filepath.Join(root, "dataset"), states[0].organizationID)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "stage=spool")
	report.Spool, err = runSpoolReplay(ctx, filepath.Join(root, "outage"))
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "stage=retention")
	report.Retention, err = runRetention(ctx, filepath.Join(root, "retention"))
	if err != nil {
		return err
	}
	report.Resources = resourceReport{GOMAXPROCS: runtime.GOMAXPROCS(0), CPUQuota: cpuQuota, MemoryLimitBytes: memoryLimit}
	report.Resources.MaximumRSSBytes = maximumRSS()
	report.Resources.DatasetBytes, err = directoryBytes(root)
	if err != nil {
		return err
	}
	var campaignErrors []error
	if report.Sustain.AchievedRate < float64(configuration.sustainRate)*0.99 || report.Burst.AchievedRate < float64(configuration.burstRate)*0.99 {
		campaignErrors = append(campaignErrors, errors.New("target observation rate was not sustained"))
	}
	if report.Sustain.VisibleP95Milliseconds >= 2_000 || report.Burst.VisibleP95Milliseconds >= 2_000 {
		campaignErrors = append(campaignErrors, errors.New("p95 ingestion-to-query visibility exceeded two seconds"))
	}
	for _, result := range report.Queries {
		if result.P95Milliseconds >= 3_000 {
			campaignErrors = append(campaignErrors, fmt.Errorf("query %s exceeded the three-second p95 boundary", result.Name))
		}
	}
	if configuration.requireCgroup && report.Resources.MaximumRSSBytes >= configuration.expectedMemory {
		campaignErrors = append(campaignErrors, errors.New("maximum RSS reached the cgroup memory boundary"))
	}
	report.CompletedAt = time.Now().UTC()
	report.Pass = len(campaignErrors) == 0
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(report); err != nil {
		campaignErrors = append(campaignErrors, fmt.Errorf("encode capacity report: %w", err))
	}
	return errors.Join(campaignErrors...)
}

func (configuration settings) validate() error {
	if configuration.sustainRate < 1 || configuration.burstRate < configuration.sustainRate || configuration.sustainDuration < time.Second || configuration.burstDuration < time.Second || configuration.minimumPrimary < 1 || configuration.queryIterations < 1 || configuration.queryIterations > 100 || configuration.organizations != 4 || configuration.primaryWeight < 1 || configuration.primaryWeight > 32 || configuration.batchInterval < 100*time.Millisecond || configuration.batchInterval > time.Second || configuration.expectedCPUs < 1 || configuration.expectedMemory < 1<<30 {
		return errors.New("capacity campaign settings are invalid")
	}
	primaryShare := float64(configuration.primaryWeight) / float64(configuration.primaryWeight+configuration.organizations-1)
	for _, rate := range []int{configuration.sustainRate, configuration.burstRate} {
		if int(math.Ceil(float64(rate)*configuration.batchInterval.Seconds()*primaryShare)) > model.MaxRecords {
			return errors.New("weighted batch would exceed the model record limit")
		}
	}
	return nil
}

func createSources(ctx context.Context, store *storage.Store, count, primaryWeight int) ([]*sourceState, error) {
	states := make([]*sourceState, 0, count)
	for index := 0; index < count; index++ {
		state := &sourceState{index: index, weight: 1, organizationID: fmt.Sprintf("capacity-org-%d", index+1), sourceID: fmt.Sprintf("capacity-source-%d", index+1), sequences: map[model.Signal]uint64{}}
		if index == 0 {
			state.weight = int64(primaryWeight)
		}
		var err error
		state.token, err = store.CreateSource(ctx, state.sourceID, model.Scope{OrganizationID: state.organizationID, ProjectID: "observatory", EnvironmentID: "capacity", ServiceID: "server"})
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, nil
}

func runPhase(ctx context.Context, store *storage.Store, states []*sourceState, seed *atomic.Uint64, rate int, duration, interval time.Duration) (phaseReport, error) {
	target := int64(math.Round(float64(rate) * duration.Seconds()))
	batches := int(math.Ceil(float64(duration) / float64(interval)))
	started := time.Now()
	measure := &measurements{}
	errorsChannel := make(chan error, len(states))
	visibilityExpected := make(chan time.Time, batches)
	visibilityErrors := make(chan error, 1)
	visibilityDone := make(chan struct{})
	go func() {
		defer close(visibilityDone)
		for expected := range visibilityExpected {
			visible, err := latestVisibility(ctx, store, states[0].organizationID, expected)
			if err != nil {
				select {
				case visibilityErrors <- err:
				default:
				}
				return
			}
			measure.mu.Lock()
			measure.visibility = append(measure.visibility, visible)
			measure.mu.Unlock()
		}
	}()
	var wait sync.WaitGroup
	remaining := target
	weightTotal := int64(0)
	for _, state := range states {
		weightTotal += state.weight
	}
	for index, state := range states {
		stateTarget := target * state.weight / weightTotal
		if index == 0 {
			allocated := int64(0)
			for _, candidate := range states {
				allocated += target * candidate.weight / weightTotal
			}
			stateTarget += target - allocated
		}
		remaining -= stateTarget
		wait.Add(1)
		go func(current *sourceState, count int64) {
			defer wait.Done()
			if err := runScheduledSource(ctx, store, current, seed, count, batches, interval, started, measure, visibilityExpected); err != nil {
				errorsChannel <- err
			}
		}(state, stateTarget)
	}
	if remaining != 0 {
		return phaseReport{}, errors.New("phase allocation did not preserve target")
	}
	wait.Wait()
	elapsed := time.Since(started)
	close(visibilityExpected)
	<-visibilityDone
	close(errorsChannel)
	for phaseErr := range errorsChannel {
		if phaseErr != nil {
			return phaseReport{}, phaseErr
		}
	}
	select {
	case visibilityErr := <-visibilityErrors:
		return phaseReport{}, visibilityErr
	default:
	}
	measure.mu.Lock()
	ingest := append([]time.Duration(nil), measure.ingest...)
	visibility := append([]time.Duration(nil), measure.visibility...)
	measure.mu.Unlock()
	if len(ingest) == 0 || len(visibility) == 0 {
		return phaseReport{}, errors.New("phase produced no latency evidence")
	}
	return phaseReport{
		TargetRate: rate, DurationSeconds: duration.Seconds(), Observations: target, ElapsedSeconds: elapsed.Seconds(), AchievedRate: float64(target) / elapsed.Seconds(),
		IngestP50Milliseconds: milliseconds(percentile(ingest, 0.50)), IngestP95Milliseconds: milliseconds(percentile(ingest, 0.95)), IngestP99Milliseconds: milliseconds(percentile(ingest, 0.99)),
		VisibleP50Milliseconds: milliseconds(percentile(visibility, 0.50)), VisibleP95Milliseconds: milliseconds(percentile(visibility, 0.95)), VisibleP99Milliseconds: milliseconds(percentile(visibility, 0.99)),
	}, nil
}

func runScheduledSource(ctx context.Context, store *storage.Store, state *sourceState, seed *atomic.Uint64, target int64, batches int, interval time.Duration, phaseStart time.Time, measurements *measurements, visibilityExpected chan<- time.Time) error {
	base, remainder := target/int64(batches), target%int64(batches)
	for batchIndex := 0; batchIndex < batches; batchIndex++ {
		planned := phaseStart.Add(time.Duration(batchIndex) * interval)
		if delay := time.Until(planned); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		count := base
		if int64(batchIndex) < remainder {
			count++
		}
		if count == 0 {
			continue
		}
		signal := []model.Signal{model.SignalLogs, model.SignalMetrics, model.SignalTraces}[batchIndex%3]
		observed := time.Now().UTC()
		records := syntheticRecords(int(count), signal, observed, seed)
		state.sequences[signal]++
		batch := model.Batch{Version: model.BatchVersion, SourceID: state.sourceID, StreamID: string(signal), Sequence: state.sequences[signal], ObservedAt: observed, Signal: signal, Records: records}
		ingestStarted := time.Now()
		ack, err := store.Ingest(ctx, state.token, batch, observed)
		latency := time.Since(ingestStarted)
		if err != nil {
			return err
		}
		expected, err := batch.Digest()
		if err != nil || ack.BatchDigest != expected || ack.Duplicate {
			return errors.New("ingestion acknowledgement did not bind the scheduled batch")
		}
		state.count.Add(count)
		measurements.mu.Lock()
		measurements.ingest = append(measurements.ingest, latency)
		measurements.mu.Unlock()
		if state.index == 0 && signal == model.SignalLogs {
			visibilityExpected <- observed
		}
	}
	return nil
}

func syntheticRecords(count int, signal model.Signal, observed time.Time, seed *atomic.Uint64) []model.Observation {
	records := make([]model.Observation, count)
	routes := []string{"/", "/items", "/search", "/healthz"}
	for index := range records {
		id := seed.Add(1)
		timestamp := observed.Add(time.Duration(index) * time.Nanosecond)
		switch signal {
		case model.SignalLogs:
			status := "200"
			if id%50 == 0 {
				status = "503"
			}
			records[index] = model.Observation{Timestamp: timestamp, Name: "http.server.request", Severity: "information", CorrelationID: fmt.Sprintf("capacity-%d", id), Attributes: map[string]string{"http.route": routes[id%uint64(len(routes))], "http.status_code": status, "duration_ns": strconv.FormatUint(100_000+id%5_000_000, 10)}}
		case model.SignalMetrics:
			value := float64(id%10_000) / 100
			records[index] = model.Observation{Timestamp: timestamp, Name: "system.cpu.utilization", Value: &value}
		case model.SignalTraces:
			records[index] = model.Observation{Timestamp: timestamp, Name: "http.server", TraceID: fmt.Sprintf("%032x", id), SpanID: fmt.Sprintf("%016x", id), Attributes: map[string]string{"http.route": routes[id%uint64(len(routes))]}}
		}
	}
	return records
}

func latestVisibility(ctx context.Context, store *storage.Store, organizationID string, expected time.Time) (time.Duration, error) {
	ast, err := query.Parse("logs | sort timestamp desc | limit 1", 10)
	if err != nil {
		return 0, err
	}
	// The release boundary is the aggregate p95 below two seconds, not a
	// zero-outlier maximum. Keep observing a slow sample long enough to retain
	// the phase evidence; the report gate below still fails an excessive p95.
	deadline := time.Now().Add(visibilityObservationTimeout)
	for {
		result, queryErr := store.Query(ctx, ast, query.Scope{OrganizationID: organizationID}, capacityBudget(10), time.Now().UTC())
		if queryErr == nil && len(result.Rows) == 1 {
			var timestamp string
			for index, column := range result.Columns {
				if column.Field == "timestamp" && result.Rows[0].Values[index] != nil {
					timestamp = *result.Rows[0].Values[index]
				}
			}
			visibleAt, parseErr := time.Parse(time.RFC3339Nano, timestamp)
			if parseErr == nil && !visibleAt.Before(expected) {
				return time.Since(expected), nil
			}
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("latest visibility query remained stale for %s", visibilityObservationTimeout)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-timer.C:
		}
	}
}

func waitForProjection(ctx context.Context, store *storage.Store, projectorErrors <-chan error, maximum time.Duration) error {
	deadline := time.Now().Add(maximum)
	for {
		select {
		case err := <-projectorErrors:
			return fmt.Errorf("background projection failed: %w", err)
		default:
		}
		status, err := store.ProjectionStatus(ctx, time.Now().UTC())
		if err != nil {
			return err
		}
		if status.PendingSegments == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("projection backlog remained after %s: segments=%d bytes=%d lag=%s", maximum, status.PendingSegments, status.PendingBytes, status.OldestPendingLag)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func fillPrimary(ctx context.Context, store *storage.Store, state *sourceState, seed *atomic.Uint64, minimum int64) error {
	batchIndex := 0
	for state.count.Load() < minimum {
		remaining := minimum - state.count.Load()
		count := int64(model.MaxRecords)
		if remaining < count {
			count = remaining
		}
		signal := []model.Signal{model.SignalLogs, model.SignalMetrics, model.SignalTraces}[batchIndex%3]
		observed := time.Now().UTC()
		state.sequences[signal]++
		batch := model.Batch{Version: model.BatchVersion, SourceID: state.sourceID, StreamID: string(signal), Sequence: state.sequences[signal], ObservedAt: observed, Signal: signal, Records: syntheticRecords(int(count), signal, observed, seed)}
		ack, err := store.Ingest(ctx, state.token, batch, observed)
		if err != nil {
			return err
		}
		expected, _ := batch.Digest()
		if ack.BatchDigest != expected || ack.Duplicate {
			return errors.New("fill acknowledgement did not bind the batch")
		}
		state.count.Add(count)
		batchIndex++
		if batchIndex%100 == 0 {
			fmt.Fprintf(os.Stderr, "stage=fill observations=%d\n", state.count.Load())
		}
	}
	return nil
}

func runQueries(ctx context.Context, store *storage.Store, organizationID string, iterations int) ([]queryReport, error) {
	definitions := []struct{ name, text string }{
		{"recent-errors-by-route", `logs | where status >= 500 | window 24h | summarize count() by route, window(5m) | sort count desc | limit 50`},
		{"recent-items", `logs | where route == "/items" | window 24h | sort timestamp desc | limit 50`},
		{"metric-rollup", `metrics | window 24h | summarize count(), p95(value) by name, window(5m) | sort count desc | limit 50`},
	}
	reports := make([]queryReport, 0, len(definitions))
	for _, definition := range definitions {
		ast, err := query.Parse(definition.text, 50)
		if err != nil {
			return nil, err
		}
		var samples []time.Duration
		var maximumRows, maximumBytes int64
		for iteration := 0; iteration < iterations; iteration++ {
			started := time.Now()
			result, queryErr := store.Query(ctx, ast, query.Scope{OrganizationID: organizationID}, capacityBudget(50), time.Now().UTC())
			samples = append(samples, time.Since(started))
			if queryErr != nil {
				return nil, fmt.Errorf("capacity query %s failed: %w", definition.name, queryErr)
			}
			if len(result.Rows) == 0 {
				return nil, fmt.Errorf("capacity query %s returned no rows", definition.name)
			}
			maximumRows = max(maximumRows, int64(result.Stats.ScannedRows))
			maximumBytes = max(maximumBytes, result.Stats.ScannedBytes)
		}
		reports = append(reports, queryReport{Name: definition.name, Iterations: iterations, P50Milliseconds: milliseconds(percentile(samples, 0.50)), P95Milliseconds: milliseconds(percentile(samples, 0.95)), P99Milliseconds: milliseconds(percentile(samples, 0.99)), MaximumScannedRows: maximumRows, MaximumScannedBytes: maximumBytes})
	}
	return reports, nil
}

func runSpoolReplay(ctx context.Context, root string) (spoolReport, error) {
	now := time.Now().UTC()
	queue, err := spool.Open(filepath.Join(root, "spool"), 1<<30, 72*time.Hour)
	if err != nil {
		return spoolReport{}, err
	}
	store, err := storage.Open(filepath.Join(root, "server"))
	if err != nil {
		return spoolReport{}, err
	}
	defer store.Close()
	token, err := store.CreateSource(ctx, "outage-source", model.Scope{OrganizationID: "outage-org", ProjectID: "observatory", EnvironmentID: "capacity", ServiceID: "agent"})
	if err != nil {
		return spoolReport{}, err
	}
	const batches, recordsPerBatch = 72, 100
	for index := 0; index < batches; index++ {
		observed := now.Add(-time.Duration(batches-index) * time.Hour).Add(time.Minute)
		batch := model.Batch{Version: model.BatchVersion, SourceID: "outage-source", StreamID: "logs", Sequence: uint64(index + 1), ObservedAt: observed, Signal: model.SignalLogs, Records: syntheticRecords(recordsPerBatch, model.SignalLogs, observed, &atomic.Uint64{})}
		entry, putErr := queue.Put(batch, observed)
		if putErr != nil {
			return spoolReport{}, putErr
		}
		if err = os.Chtimes(entry.Path, observed, observed); err != nil {
			return spoolReport{}, err
		}
	}
	entries, err := queue.List(now)
	if err != nil || len(entries) != batches {
		return spoolReport{}, errors.New("72-hour spool did not preserve every batch")
	}
	report := spoolReport{Batches: len(entries), Observations: batches * recordsPerBatch, OldestAgeHours: now.Sub(entries[0].ModTime).Hours()}
	for index, entry := range entries {
		batch, readErr := queue.Read(entry)
		if readErr != nil {
			return spoolReport{}, readErr
		}
		ack, ingestErr := store.Ingest(ctx, token, batch, now)
		if ingestErr != nil {
			return spoolReport{}, ingestErr
		}
		expected, _ := batch.Digest()
		if ack.BatchDigest != expected {
			return spoolReport{}, errors.New("outage replay acknowledgement mismatch")
		}
		if index == 0 {
			duplicate, duplicateErr := store.Ingest(ctx, token, batch, now)
			if duplicateErr != nil || !duplicate.Duplicate || duplicate.BatchDigest != expected {
				return spoolReport{}, errors.New("outage replay duplicate was not recognized")
			}
			report.DuplicateRecognized = true
		}
		if err = queue.Acknowledge(entry, entry.Digest); err != nil {
			return spoolReport{}, err
		}
		report.Replayed += int64(len(batch.Records))
	}
	remaining, err := queue.List(now)
	if err != nil {
		return spoolReport{}, err
	}
	report.RemainingAfterAck = len(remaining)
	if report.Replayed != report.Observations || report.RemainingAfterAck != 0 || report.OldestAgeHours < 71.9 {
		return spoolReport{}, errors.New("outage replay evidence is incomplete")
	}
	return report, nil
}

func runRetention(ctx context.Context, root string) (retentionEvidence, error) {
	now := time.Now().UTC()
	store, err := storage.Open(root)
	if err != nil {
		return retentionEvidence{}, err
	}
	defer store.Close()
	token, err := store.CreateSource(ctx, "retention-source", model.Scope{OrganizationID: "retention-org", ProjectID: "observatory", EnvironmentID: "capacity", ServiceID: "server"})
	if err != nil {
		return retentionEvidence{}, err
	}
	tests := []struct {
		signal model.Signal
		age    time.Duration
	}{
		{model.SignalLogs, 31 * 24 * time.Hour},
		{model.SignalTraces, 31 * 24 * time.Hour},
		{model.SignalMetrics, 15 * 24 * time.Hour},
		{model.SignalDeployments, 399 * 24 * time.Hour},
	}
	for index, item := range tests {
		observed := now.Add(-item.age)
		batch := model.Batch{Version: model.BatchVersion, SourceID: "retention-source", StreamID: string(item.signal), Sequence: 1, ObservedAt: now, Signal: item.signal, Records: syntheticRecords(1, item.signal, observed, &atomic.Uint64{})}
		if item.signal == model.SignalDeployments {
			batch.Records[0] = model.Observation{Timestamp: observed, Name: "deployment", Attributes: map[string]string{"outcome": "success"}}
		}
		if _, err = store.Ingest(ctx, token, batch, now); err != nil {
			return retentionEvidence{}, fmt.Errorf("retention fixture %d: %w", index, err)
		}
	}
	if err = store.Recover(ctx); err != nil {
		return retentionEvidence{}, err
	}
	policy := storage.RetentionPolicy{RawLogsDays: 30, RawTracesDays: 30, RawMetricsDays: 14, ColdRawDays: 400, DeleteColdRaw: true, MetricRollupsDays: 400, EvidenceDays: 400}
	report, err := store.ApplyRetention(ctx, policy, now.Add(2*24*time.Hour))
	if err != nil {
		return retentionEvidence{}, err
	}
	ast, err := query.Parse("logs | window 960h | limit 10", 10)
	if err != nil {
		return retentionEvidence{}, err
	}
	result, err := store.Query(ctx, ast, query.Scope{OrganizationID: "retention-org", Sensitive: true}, capacityBudget(10), now.Add(2*24*time.Hour))
	if err != nil {
		return retentionEvidence{}, err
	}
	evidence := retentionEvidence{ArchivedSegments: report.RawSegmentsArchived, ArchivedBytes: report.RawBytesArchived, RemovedSegments: report.RawSegmentsRemoved, RemovedBytes: report.RawBytesRemoved, ProjectionRowsRemoved: report.ProjectedObservationsRemoved, ColdQueryRows: len(result.Rows)}
	if evidence.ArchivedSegments != 4 || evidence.RemovedSegments != 1 || evidence.ProjectionRowsRemoved != 4 || evidence.ColdQueryRows != 1 {
		return retentionEvidence{}, fmt.Errorf("retention lifecycle mismatch: %+v", evidence)
	}
	return evidence, nil
}

func capacityBudget(rows int) query.Budget {
	return query.Budget{MaxDuration: 10 * time.Second, MaxRows: rows, MaxScannedBytes: 64 << 30, MaxMemoryBytes: 1 << 30}
}

func percentile(values []time.Duration, fraction float64) time.Duration {
	copyOfValues := append([]time.Duration(nil), values...)
	sort.Slice(copyOfValues, func(left, right int) bool { return copyOfValues[left] < copyOfValues[right] })
	index := int(math.Ceil(float64(len(copyOfValues))*fraction)) - 1
	if index < 0 {
		index = 0
	}
	return copyOfValues[index]
}

func milliseconds(value time.Duration) float64 { return float64(value) / float64(time.Millisecond) }

func cgroupLimits() (float64, int64, error) {
	cpuBody, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if err != nil {
		return 0, 0, errors.New("read cgroup CPU limit")
	}
	parts := strings.Fields(string(cpuBody))
	if len(parts) != 2 || parts[0] == "max" {
		return 0, 0, errors.New("cgroup CPU quota is not finite")
	}
	quota, quotaErr := strconv.ParseFloat(parts[0], 64)
	period, periodErr := strconv.ParseFloat(parts[1], 64)
	memoryBody, memoryErr := os.ReadFile("/sys/fs/cgroup/memory.max")
	memory, parseMemoryErr := strconv.ParseInt(strings.TrimSpace(string(memoryBody)), 10, 64)
	if quotaErr != nil || periodErr != nil || period <= 0 || memoryErr != nil || parseMemoryErr != nil {
		return 0, 0, errors.New("cgroup resource limit is invalid")
	}
	return quota / period, memory, nil
}

func maximumRSS() int64 {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		return 0
	}
	return usage.Maxrss * 1024
}

func directoryBytes(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("capacity workspace contains a symlink")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("capacity workspace contains a non-regular file")
		}
		if info.Size() > math.MaxInt64-total {
			return errors.New("capacity workspace size overflow")
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func measureStorage(root, primaryOrganizationID string) (storageBreakdown, error) {
	var report storageBreakdown
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("capacity dataset contains a symlink")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("capacity dataset contains a non-regular file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return errors.New("capacity dataset path is invalid")
		}
		class := &report.Other
		switch {
		case relative == "control.sqlite" || strings.HasPrefix(relative, "control.sqlite-"):
			class = &report.Control
		case strings.HasPrefix(relative, "raw"+string(os.PathSeparator)) || strings.HasPrefix(relative, "cold"+string(os.PathSeparator)):
			class = &report.Raw
		case strings.HasPrefix(relative, "organizations"+string(os.PathSeparator)):
			class = &report.Projection
		}
		if info.Size() > math.MaxInt64-class.Bytes || info.Size() > math.MaxInt64-report.Total.Bytes {
			return errors.New("capacity storage class size overflow")
		}
		class.Files++
		class.Bytes += info.Size()
		report.Total.Files++
		report.Total.Bytes += info.Size()
		return nil
	})
	if err != nil {
		return storageBreakdown{}, err
	}
	projectionPath := filepath.Join(root, "organizations", primaryOrganizationID, "projection.sqlite")
	report.SQLiteBytes, report.SQLitePageClasses, err = sqliteObjectBytes(projectionPath)
	if err != nil {
		return storageBreakdown{}, err
	}
	return report, nil
}

func sqliteObjectBytes(path string) (map[string]int64, sqlitePageBreakdown, error) {
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, sqlitePageBreakdown{}, errors.New("open capacity projection diagnostics")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.Query(`SELECT d.name,COALESCE(m.type,'internal'),COALESCE(SUM(d.pgsize),0) FROM dbstat AS d LEFT JOIN sqlite_schema AS m ON m.name=d.name GROUP BY d.name,m.type ORDER BY d.name`)
	if err != nil {
		return nil, sqlitePageBreakdown{}, errors.New("read capacity projection page accounting")
	}
	defer rows.Close()
	report := map[string]int64{}
	var classes sqlitePageBreakdown
	for rows.Next() {
		var name, objectType string
		var bytes int64
		if err = rows.Scan(&name, &objectType, &bytes); err != nil || name == "" || bytes < 0 {
			return nil, sqlitePageBreakdown{}, errors.New("read capacity projection page accounting")
		}
		report[name] = bytes
		if bytes > math.MaxInt64-classes.Total {
			return nil, sqlitePageBreakdown{}, errors.New("capacity projection page accounting overflow")
		}
		classes.Total += bytes
		switch objectType {
		case "table":
			classes.Tables += bytes
		case "index":
			classes.Indexes += bytes
		default:
			classes.Internal += bytes
		}
	}
	if err = rows.Err(); err != nil {
		return nil, sqlitePageBreakdown{}, errors.New("read capacity projection page accounting")
	}
	if len(report) == 0 {
		return nil, sqlitePageBreakdown{}, errors.New("capacity projection page accounting is empty")
	}
	if classes.Total != classes.Tables+classes.Indexes+classes.Internal {
		return nil, sqlitePageBreakdown{}, errors.New("capacity projection page accounting total mismatch")
	}
	return report, classes, nil
}
