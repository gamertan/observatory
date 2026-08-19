// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/schema"
)

func TestPlanInjectsScopeAndReportsIndexes(t *testing.T) {
	ast, err := Parse(`logs | where service == "eql" | where status >= 500 | window 24h | sort timestamp desc | limit 50`, 1000)
	if err != nil {
		t.Fatal(err)
	}
	explain, err := Plan(ast, Scope{OrganizationID: "personal-cole", ProjectID: "eql", EnvironmentID: "production"}, nil, 10<<20, Budget{MaxDuration: 5 * time.Second, MaxRows: 1000, MaxScannedBytes: 100 << 20, MaxMemoryBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(explain.ProjectedSources) != 1 || explain.ProjectedSources[0] != "organization:personal-cole/signal:logs/project:eql/environment:production" || len(explain.Fields) != 3 {
		t.Fatalf("explain=%+v", explain)
	}
	for _, field := range explain.Fields {
		if !field.Indexed || field.Unknown {
			t.Fatalf("field=%+v", field)
		}
	}
}

func TestPlanRequiresSensitivePermissionForUnknownAndBody(t *testing.T) {
	for _, text := range []string{`logs | where vendor.unknown == "x" | limit 10`, `logs | where body =~ "error" | limit 10`} {
		ast, err := Parse(text, 100)
		if err != nil {
			t.Fatal(err)
		}
		budget := Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 1 << 20, MaxMemoryBytes: 1 << 20}
		if _, err := Plan(ast, Scope{OrganizationID: "org"}, nil, 100, budget); err == nil {
			t.Fatalf("expected sensitive rejection for %q", text)
		}
		explain, err := Plan(ast, Scope{OrganizationID: "org", Sensitive: true}, nil, 100, budget)
		if err != nil {
			t.Fatal(err)
		}
		if len(explain.RequiredPermissions) != 2 || explain.CacheEligible {
			t.Fatalf("explain=%+v", explain)
		}
	}
}

func TestPlanRejectsCrossTenantScopeAndScanBudget(t *testing.T) {
	ast, _ := Parse(`metrics | limit 10`, 100)
	budget := Budget{MaxDuration: time.Second, MaxRows: 100, MaxScannedBytes: 1000, MaxMemoryBytes: 1000}
	if _, err := Plan(ast, Scope{OrganizationID: "../other"}, nil, 10, budget); err == nil {
		t.Fatal("expected scope rejection")
	}
	if _, err := Plan(ast, Scope{OrganizationID: "org"}, nil, 1001, budget); err == nil {
		t.Fatal("expected scan-budget rejection")
	}
}

func TestBuiltinMetricDimensionsAreSignalScopedAndRetentionAware(t *testing.T) {
	state, ok := BuiltinDescriptor(model.SignalMetrics, "state")
	if !ok || state.Retention != schema.RetentionMetric {
		t.Fatalf("metric state descriptor=%+v ok=%t", state, ok)
	}
	if _, ok = BuiltinDescriptor(model.SignalLogs, "state"); ok {
		t.Fatal("metric-only state dimension was exposed to logs")
	}

	metricRoute, ok := BuiltinDescriptor(model.SignalMetrics, "http.route")
	if !ok || metricRoute.Retention != schema.RetentionMetric {
		t.Fatalf("metric route descriptor=%+v ok=%t", metricRoute, ok)
	}
	logRoute, ok := BuiltinDescriptor(model.SignalLogs, "http.route")
	if !ok || logRoute.Retention != schema.RetentionRaw {
		t.Fatalf("log route descriptor=%+v ok=%t", logRoute, ok)
	}
}
