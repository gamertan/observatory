// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"errors"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

// queryRawCandidate executes one bounded log query directly from the complete
// retained raw-segment catalogue. It is deliberately not a public Store or
// HTTP surface: the current projection path remains the production oracle
// while differential tests establish the adaptive read path's semantics.
//
// The organization lock prevents in-process retention from moving or deleting
// a selected object during this first proof. A future leased materialization
// needs an explicit catalogue snapshot/high-watermark rather than holding this
// lock across a potentially long historical scan.
func (s *Store) queryRawCandidate(ctx context.Context, ast query.AST, scope query.Scope, budget query.Budget, now time.Time) (query.Result, error) {
	if now.IsZero() {
		return query.Result{}, errors.New("query time is required")
	}
	if ast.Signal != model.SignalLogs {
		return query.Result{}, errors.New("raw query candidate supports logs only")
	}
	lock := s.namedLock("organization:" + scope.OrganizationID)
	lock.Lock()
	defer lock.Unlock()

	registry, _, err := s.ActiveDescriptors(ctx, scope.OrganizationID)
	if err != nil {
		return query.Result{}, err
	}
	segments, estimated, err := s.allRawSegmentsForQuery(ctx, ast, scope, now)
	if err != nil {
		return query.Result{}, err
	}
	explain, err := query.Plan(ast, scope, registry, estimated, budget)
	if err != nil {
		return query.Result{}, err
	}
	for index := range explain.ProjectedSources {
		explain.ProjectedSources[index] += "/raw:catalog"
	}
	columns, err := resultColumns(ast, registry)
	if err != nil {
		return query.Result{}, err
	}
	result := query.Result{Version: query.ResultVersion, Explain: explain, Columns: columns, Rows: []query.Row{}}
	runContext, cancel := context.WithTimeout(ctx, budget.MaxDuration)
	defer cancel()
	started := time.Now()
	records, memoryBytes, err := s.appendRawQuerySegments(runContext, segments, ast, registry, budget, now, &result, nil, 0)
	if err != nil {
		return query.Result{}, err
	}
	sortRawQueryRecords(records)
	return finishQueryResult(result, records, ast, columns, registry, memoryBytes, budget.MaxMemoryBytes, started)
}
