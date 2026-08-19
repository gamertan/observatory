// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/schema"
)

type FieldLookup func(field string) (string, bool)

// MatchesFilters applies the query's typed filters to a bounded record value
// lookup. Storage projections and the local agent evaluator share this path so
// edge and central comparisons cannot drift silently.
func MatchesFilters(ast AST, registry Registry, lookup FieldLookup) (bool, error) {
	for _, filter := range ast.Filters {
		field := CanonicalField(filter.Field)
		descriptor, _ := ResolveDescriptor(ast.Signal, field, registry)
		value, present := lookup(field)
		if !present {
			return false, nil
		}
		matched, err := CompareValue(value, filter.Value, filter.Op, descriptor.Type)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

func MatchObservation(observation model.Observation, ast AST, registry Registry) (bool, error) {
	return MatchesFilters(ast, registry, func(field string) (string, bool) {
		switch CanonicalField(field) {
		case "timestamp":
			return observation.Timestamp.UTC().Format(time.RFC3339Nano), !observation.Timestamp.IsZero()
		case "name":
			return observation.Name, observation.Name != ""
		case "severity":
			return observation.Severity, observation.Severity != ""
		case "body":
			return observation.Body, observation.Body != ""
		case "value":
			if observation.Value == nil {
				return "", false
			}
			return strconv.FormatFloat(*observation.Value, 'g', -1, 64), true
		case "trace_id":
			return observation.TraceID, observation.TraceID != ""
		case "span_id":
			return observation.SpanID, observation.SpanID != ""
		case "correlation_id":
			return observation.CorrelationID, observation.CorrelationID != ""
		default:
			value, ok := observation.Attributes[CanonicalField(field)]
			return value, ok
		}
	})
}

func CompareValue(left, right, operator string, valueType schema.Type) (bool, error) {
	if operator == "=~" {
		if valueType != schema.TypeString {
			return false, ErrTypeMismatch
		}
		expression, err := regexp.Compile(right)
		if err != nil {
			return false, ErrTypeMismatch
		}
		return expression.MatchString(left), nil
	}
	var comparison int
	switch valueType {
	case schema.TypeInteger, schema.TypeFloat, schema.TypeDuration:
		rightNumber, rightErr := strconv.ParseFloat(right, 64)
		if rightErr != nil || math.IsNaN(rightNumber) || math.IsInf(rightNumber, 0) {
			return false, ErrTypeMismatch
		}
		leftNumber, leftErr := strconv.ParseFloat(left, 64)
		if leftErr != nil || math.IsNaN(leftNumber) || math.IsInf(leftNumber, 0) {
			return false, nil
		}
		comparison = compareFloat(leftNumber, rightNumber)
	case schema.TypeTime:
		rightTime, rightErr := time.Parse(time.RFC3339Nano, right)
		if rightErr != nil {
			return false, ErrTypeMismatch
		}
		leftTime, leftErr := time.Parse(time.RFC3339Nano, left)
		if leftErr != nil {
			return false, nil
		}
		comparison = leftTime.Compare(rightTime)
	case schema.TypeBoolean:
		rightBool, rightErr := strconv.ParseBool(right)
		if rightErr != nil {
			return false, ErrTypeMismatch
		}
		leftBool, leftErr := strconv.ParseBool(left)
		if leftErr != nil {
			return false, nil
		}
		comparison = compareBool(leftBool, rightBool)
	default:
		comparison = strings.Compare(left, right)
	}
	switch operator {
	case "==":
		return comparison == 0, nil
	case "!=":
		return comparison != 0, nil
	case ">":
		return comparison > 0, nil
	case ">=":
		return comparison >= 0, nil
	case "<":
		return comparison < 0, nil
	case "<=":
		return comparison <= 0, nil
	default:
		return false, ErrTypeMismatch
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

func compareBool(left, right bool) int {
	if left == right {
		return 0
	}
	if !left {
		return -1
	}
	return 1
}
