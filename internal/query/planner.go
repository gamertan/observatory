// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/schema"
)

var ErrSensitivePermissionRequired = errors.New("query requires sensitive-field permission")

type Scope struct {
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id,omitempty"`
	EnvironmentID  string `json:"environment_id,omitempty"`
	ServiceID      string `json:"service_id,omitempty"`
	Sensitive      bool   `json:"sensitive"`
}

type Budget struct {
	MaxDuration     time.Duration `json:"-"`
	MaxRows         int           `json:"max_rows"`
	MaxScannedBytes int64         `json:"max_scanned_bytes"`
	MaxMemoryBytes  int64         `json:"max_memory_bytes"`
}

type FieldPlan struct {
	Field      string            `json:"field"`
	Descriptor schema.Descriptor `json:"descriptor"`
	Indexed    bool              `json:"indexed"`
	Unknown    bool              `json:"unknown"`
}

type Explain struct {
	AST                 AST         `json:"ast"`
	ProjectedSources    []string    `json:"projected_sources"`
	Fields              []FieldPlan `json:"fields"`
	EstimatedScanBytes  int64       `json:"estimated_scan_bytes"`
	CacheEligible       bool        `json:"cache_eligible"`
	RequiredPermissions []string    `json:"required_permissions"`
	Budget              Budget      `json:"budget"`
}

type Registry interface {
	Lookup(model.Signal, string) (schema.Descriptor, bool)
}

type MapRegistry map[string]schema.Descriptor

func (registry MapRegistry) Lookup(signal model.Signal, field string) (schema.Descriptor, bool) {
	descriptor, ok := registry[string(signal)+":"+CanonicalField(field)]
	return descriptor, ok
}

func Plan(ast AST, scope Scope, registry Registry, estimatedScanBytes int64, budget Budget) (Explain, error) {
	if err := Validate(ast, budget.MaxRows); err != nil {
		return Explain{}, err
	}
	if !safeScope(scope) {
		return Explain{}, errors.New("query scope is invalid")
	}
	if budget.MaxDuration < time.Millisecond || budget.MaxDuration > time.Minute || budget.MaxRows < 1 || budget.MaxScannedBytes < 1 || budget.MaxMemoryBytes < 1 {
		return Explain{}, errors.New("query budget is invalid")
	}
	if estimatedScanBytes < 0 || estimatedScanBytes > budget.MaxScannedBytes {
		return Explain{}, errors.New("estimated query scan exceeds budget")
	}
	fields := ReferencedFields(ast)
	plans := make([]FieldPlan, 0, len(fields))
	requiresSensitive := false
	cacheEligible := true
	for _, field := range fields {
		canonical := CanonicalField(field)
		descriptor, unknown := ResolveDescriptor(ast.Signal, canonical, registry)
		if err := descriptor.Validate(); err != nil {
			return Explain{}, fmt.Errorf("field %s descriptor: %w", field, err)
		}
		if descriptor.Sensitivity == schema.SensitivitySensitive {
			requiresSensitive = true
			cacheEligible = false
		}
		plans = append(plans, FieldPlan{Field: field, Descriptor: descriptor, Indexed: descriptor.Index != schema.IndexNone, Unknown: unknown})
	}
	if requiresSensitive && !scope.Sensitive {
		return Explain{}, ErrSensitivePermissionRequired
	}
	for _, filter := range ast.Filters {
		if filter.Op == "=~" {
			cacheEligible = false
		}
	}
	permissions := []string{"telemetry:query"}
	if requiresSensitive {
		permissions = append(permissions, "telemetry:sensitive")
	}
	source := "organization:" + scope.OrganizationID + "/signal:" + string(ast.Signal)
	if scope.ProjectID != "" {
		source += "/project:" + scope.ProjectID
	}
	if scope.EnvironmentID != "" {
		source += "/environment:" + scope.EnvironmentID
	}
	if scope.ServiceID != "" {
		source += "/service:" + scope.ServiceID
	}
	return Explain{AST: ast, ProjectedSources: []string{source}, Fields: plans, EstimatedScanBytes: estimatedScanBytes, CacheEligible: cacheEligible, RequiredPermissions: permissions, Budget: budget}, nil
}

func ReferencedFields(ast AST) []string {
	seen := map[string]bool{}
	var fields []string
	add := func(field string) {
		if field != "" && !seen[field] {
			seen[field] = true
			fields = append(fields, field)
		}
	}
	for _, filter := range ast.Filters {
		add(filter.Field)
	}
	if ast.Sort != nil {
		isAggregateAlias := false
		if ast.Summary != nil {
			for _, aggregate := range ast.Summary.Aggregates {
				if aggregate.Alias == ast.Sort.Field {
					isAggregateAlias = true
					break
				}
			}
		}
		if !isAggregateAlias {
			add(ast.Sort.Field)
		}
	}
	if ast.Summary != nil {
		for _, aggregate := range ast.Summary.Aggregates {
			add(aggregate.Field)
		}
		for _, field := range ast.Summary.GroupBy {
			add(field)
		}
	}
	sort.Strings(fields)
	return fields
}

func CanonicalField(field string) string {
	switch field {
	case "service":
		return "service.id"
	case "project":
		return "project.id"
	case "environment":
		return "environment.id"
	case "route":
		return "http.route"
	case "status":
		return "http.status_code"
	case "duration":
		return "duration_ns"
	default:
		return field
	}
}

func ResolveDescriptor(signal model.Signal, field string, registry Registry) (schema.Descriptor, bool) {
	canonical := CanonicalField(field)
	descriptor, ok := BuiltinDescriptor(signal, canonical)
	if !ok && registry != nil {
		descriptor, ok = registry.Lookup(signal, canonical)
	}
	if !ok {
		return schema.Unknown(signal, canonical), true
	}
	return descriptor, false
}

func BuiltinDescriptor(signal model.Signal, field string) (schema.Descriptor, bool) {
	descriptors := map[string]schema.Descriptor{
		"service.id":       descriptor(signal, "service.id", schema.TypeString, "Application service identifier.", schema.SensitivityInternal, schema.CardinalityLow, schema.IndexExact, ""),
		"project.id":       descriptor(signal, "project.id", schema.TypeString, "Application project identifier.", schema.SensitivityInternal, schema.CardinalityLow, schema.IndexExact, ""),
		"environment.id":   descriptor(signal, "environment.id", schema.TypeString, "Deployment environment identifier.", schema.SensitivityInternal, schema.CardinalityLow, schema.IndexExact, ""),
		"timestamp":        descriptor(signal, "timestamp", schema.TypeTime, "Observation timestamp.", schema.SensitivityInternal, schema.CardinalityHigh, schema.IndexRange, "s"),
		"name":             descriptor(signal, "name", schema.TypeString, "Observation name.", schema.SensitivityInternal, schema.CardinalityMedium, schema.IndexExact, ""),
		"severity":         descriptor(signal, "severity", schema.TypeString, "Log severity.", schema.SensitivityInternal, schema.CardinalityLow, schema.IndexExact, ""),
		"value":            descriptor(signal, "value", schema.TypeFloat, "Numeric observation value.", schema.SensitivityInternal, schema.CardinalityHigh, schema.IndexRange, ""),
		"http.route":       descriptor(signal, "http.route", schema.TypeString, "Application-normalized HTTP route.", schema.SensitivityInternal, schema.CardinalityMedium, schema.IndexExact, ""),
		"http.status_code": descriptor(signal, "http.status_code", schema.TypeInteger, "HTTP response status code.", schema.SensitivityPublic, schema.CardinalityLow, schema.IndexExact, ""),
		"duration_ns":      descriptor(signal, "duration_ns", schema.TypeDuration, "Observed duration in nanoseconds.", schema.SensitivityInternal, schema.CardinalityHigh, schema.IndexRange, "ns"),
		"state":            descriptor(signal, "state", schema.TypeString, "Bounded metric state dimension.", schema.SensitivityInternal, schema.CardinalityLow, schema.IndexExact, ""),
		"period":           descriptor(signal, "period", schema.TypeString, "Bounded measurement period dimension.", schema.SensitivityInternal, schema.CardinalityLow, schema.IndexExact, ""),
		"interface":        descriptor(signal, "interface", schema.TypeString, "Configured network interface dimension.", schema.SensitivityInternal, schema.CardinalityMedium, schema.IndexExact, ""),
		"direction":        descriptor(signal, "direction", schema.TypeString, "Bounded input or output direction dimension.", schema.SensitivityInternal, schema.CardinalityLow, schema.IndexExact, ""),
		"filesystem":       descriptor(signal, "filesystem", schema.TypeString, "Configured filesystem dimension.", schema.SensitivityInternal, schema.CardinalityMedium, schema.IndexExact, ""),
		"process":          descriptor(signal, "process", schema.TypeString, "Configured process dimension.", schema.SensitivityInternal, schema.CardinalityMedium, schema.IndexExact, ""),
		"cgroup":           descriptor(signal, "cgroup", schema.TypeString, "Configured cgroup dimension.", schema.SensitivityInternal, schema.CardinalityMedium, schema.IndexExact, ""),
		"unit":             descriptor(signal, "unit", schema.TypeString, "Metric unit supplied by a bounded collector.", schema.SensitivityInternal, schema.CardinalityLow, schema.IndexExact, ""),
		"trace_id":         descriptor(signal, "trace_id", schema.TypeString, "Trace correlation identifier.", schema.SensitivityInternal, schema.CardinalityHigh, schema.IndexRange, ""),
		"span_id":          descriptor(signal, "span_id", schema.TypeString, "Span correlation identifier.", schema.SensitivityInternal, schema.CardinalityHigh, schema.IndexRange, ""),
		"correlation_id":   descriptor(signal, "correlation_id", schema.TypeString, "Cross-signal correlation identifier.", schema.SensitivityInternal, schema.CardinalityHigh, schema.IndexRange, ""),
		"body":             descriptor(signal, "body", schema.TypeString, "Optional retained log text.", schema.SensitivitySensitive, schema.CardinalityHigh, schema.IndexNone, ""),
	}
	descriptor, ok := descriptors[field]
	if ok && signal != model.SignalMetrics {
		switch field {
		case "state", "period", "interface", "direction", "filesystem", "process", "cgroup", "unit":
			return schema.Descriptor{}, false
		}
	}
	if ok && signal == model.SignalMetrics {
		switch field {
		case "http.route", "http.status_code", "state", "period", "interface", "direction", "filesystem", "process", "cgroup", "unit":
			descriptor.Retention = schema.RetentionMetric
		}
	}
	return descriptor, ok
}

func descriptor(signal model.Signal, field string, valueType schema.Type, meaning string, sensitivity schema.Sensitivity, cardinality schema.Cardinality, index schema.IndexPolicy, unit string) schema.Descriptor {
	return schema.Descriptor{Version: schema.DescriptorVersion, Signal: signal, Field: field, Type: valueType, Unit: unit, Meaning: meaning, Sensitivity: sensitivity, Cardinality: cardinality, Index: index, Retention: schema.RetentionRaw, ProjectionVersion: 1}
}

func safeScope(scope Scope) bool {
	values := []string{scope.OrganizationID, scope.ProjectID, scope.EnvironmentID, scope.ServiceID}
	if values[0] == "" {
		return false
	}
	for _, value := range values {
		if value == "" {
			continue
		}
		if len(value) > 128 {
			return false
		}
		for _, r := range value {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
				return false
			}
		}
	}
	return true
}
