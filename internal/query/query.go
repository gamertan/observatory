// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gamertan.com/observatory/internal/model"
)

const (
	ASTVersion     = 1
	maxQueryWindow = 3650 * 24 * time.Hour
)

type AST struct {
	Version    int           `json:"version"`
	Signal     model.Signal  `json:"signal"`
	Filters    []Filter      `json:"filters,omitempty"`
	Sort       *Sort         `json:"sort,omitempty"`
	Summary    *Summary      `json:"summary,omitempty"`
	Limit      int           `json:"limit"`
	Window     time.Duration `json:"-"`
	WindowText string        `json:"window,omitempty"`
	Bucket     time.Duration `json:"-"`
	BucketText string        `json:"bucket,omitempty"`
}

type Filter struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

type Sort struct {
	Field      string `json:"field"`
	Descending bool   `json:"descending"`
}

type Summary struct {
	Aggregates []Aggregate `json:"aggregates"`
	GroupBy    []string    `json:"group_by,omitempty"`
}

type Aggregate struct {
	Function string `json:"function"`
	Field    string `json:"field,omitempty"`
	Alias    string `json:"alias"`
}

func Parse(text string, maxLimit int) (AST, error) {
	if len(text) == 0 || len(text) > 16_384 {
		return AST{}, errors.New("query length outside accepted bounds")
	}
	parts := strings.Split(text, "|")
	if len(parts) > 16 {
		return AST{}, errors.New("too many query stages")
	}
	ast := AST{Version: ASTVersion, Signal: model.Signal(strings.TrimSpace(parts[0])), Limit: min(100, maxLimit)}
	if ast.Signal != model.SignalLogs && ast.Signal != model.SignalMetrics && ast.Signal != model.SignalTraces && ast.Signal != model.SignalDeployments {
		return AST{}, errors.New("query must begin with logs, metrics, traces, or deployments")
	}
	for _, raw := range parts[1:] {
		stage := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(stage, "where "):
			filter, err := parseFilter(strings.TrimSpace(strings.TrimPrefix(stage, "where ")))
			if err != nil {
				return AST{}, err
			}
			ast.Filters = append(ast.Filters, filter)
		case strings.HasPrefix(stage, "sort "):
			fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(stage, "sort ")))
			if len(fields) < 1 || len(fields) > 2 || !validField(fields[0]) {
				return AST{}, errors.New("invalid sort stage")
			}
			desc := len(fields) == 2 && fields[1] == "desc"
			if len(fields) == 2 && fields[1] != "asc" && fields[1] != "desc" {
				return AST{}, errors.New("sort direction must be asc or desc")
			}
			ast.Sort = &Sort{Field: fields[0], Descending: desc}
		case strings.HasPrefix(stage, "summarize "):
			if ast.Summary != nil {
				return AST{}, errors.New("query may contain only one summarize stage")
			}
			summary, bucket, bucketText, err := parseSummary(strings.TrimSpace(strings.TrimPrefix(stage, "summarize ")))
			if err != nil {
				return AST{}, err
			}
			ast.Summary = &summary
			if bucket > 0 {
				ast.Bucket, ast.BucketText = bucket, bucketText
			}
		case strings.HasPrefix(stage, "limit "):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(stage, "limit ")))
			if err != nil || n < 1 || n > maxLimit {
				return AST{}, fmt.Errorf("limit must be between 1 and %d", maxLimit)
			}
			ast.Limit = n
		case strings.HasPrefix(stage, "window "):
			windowText := strings.TrimSpace(strings.TrimPrefix(stage, "window "))
			d, err := time.ParseDuration(windowText)
			if err != nil || d < time.Second || d > maxQueryWindow {
				return AST{}, errors.New("window must be between 1s and 87600h")
			}
			ast.Window, ast.WindowText = d, windowText
		default:
			return AST{}, fmt.Errorf("unsupported query stage %q", stage)
		}
	}
	if err := Validate(ast, maxLimit); err != nil {
		return AST{}, err
	}
	return ast, nil
}

func Validate(ast AST, maxLimit int) error {
	if ast.Version != ASTVersion || (ast.Signal != model.SignalLogs && ast.Signal != model.SignalMetrics && ast.Signal != model.SignalTraces && ast.Signal != model.SignalDeployments) {
		return errors.New("query AST identity is invalid")
	}
	if ast.Limit < 1 || ast.Limit > maxLimit {
		return fmt.Errorf("limit must be between 1 and %d", maxLimit)
	}
	if ast.Window < 0 || ast.Window > maxQueryWindow || ast.Window > 0 && ast.Window < time.Second {
		return errors.New("query window is invalid")
	}
	if ast.Bucket < 0 || ast.Bucket > maxQueryWindow || ast.Bucket > 0 && (ast.Bucket < time.Second || ast.Summary == nil) {
		return errors.New("query summary bucket is invalid")
	}
	if len(ast.Filters) > 16 {
		return errors.New("too many query filters")
	}
	for _, filter := range ast.Filters {
		if !validField(filter.Field) || len(filter.Value) > 4096 {
			return errors.New("query filter is invalid")
		}
		switch filter.Op {
		case "!=", ">=", "<=", "==", ">", "<":
		case "=~":
			if len(filter.Value) > 512 {
				return errors.New("regular expression exceeds 512 bytes")
			}
			if _, err := regexp.Compile(filter.Value); err != nil {
				return errors.New("invalid regular expression")
			}
		default:
			return errors.New("query filter operator is invalid")
		}
	}
	if ast.Sort != nil && !validField(ast.Sort.Field) {
		return errors.New("query sort is invalid")
	}
	if ast.Summary != nil {
		if len(ast.Summary.Aggregates) < 1 || len(ast.Summary.Aggregates) > 16 || len(ast.Summary.GroupBy) > 16 {
			return errors.New("query summary is invalid")
		}
		aliases := map[string]bool{}
		for _, aggregate := range ast.Summary.Aggregates {
			switch aggregate.Function {
			case "count":
				if aggregate.Field != "" {
					return errors.New("count accepts no field")
				}
			case "min", "max", "sum", "avg", "p50", "p95", "p99":
				if !validField(aggregate.Field) {
					return errors.New("aggregate field is invalid")
				}
			default:
				return errors.New("aggregate function is unsupported")
			}
			if !validField(aggregate.Alias) || aliases[aggregate.Alias] {
				return errors.New("aggregate alias is invalid or duplicated")
			}
			aliases[aggregate.Alias] = true
		}
		for _, group := range ast.Summary.GroupBy {
			if !validField(group) {
				return errors.New("grouping field is invalid")
			}
			if aliases[group] {
				return errors.New("grouping field conflicts with aggregate alias")
			}
		}
	}
	return nil
}

func parseFilter(expr string) (Filter, error) {
	for _, op := range []string{"!=", ">=", "<=", "==", "=~", ">", "<"} {
		if i := strings.Index(expr, op); i > 0 {
			field := strings.TrimSpace(expr[:i])
			value := strings.TrimSpace(expr[i+len(op):])
			if !validField(field) || value == "" || len(value) > 4096 {
				return Filter{}, errors.New("invalid where stage")
			}
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				unquoted, err := strconv.Unquote(value)
				if err != nil {
					return Filter{}, errors.New("invalid quoted filter value")
				}
				value = unquoted
			}
			if op == "=~" {
				if len(value) > 512 {
					return Filter{}, errors.New("regular expression exceeds 512 bytes")
				}
				if _, err := regexp.Compile(value); err != nil {
					return Filter{}, errors.New("invalid regular expression")
				}
			}
			return Filter{Field: field, Op: op, Value: value}, nil
		}
	}
	return Filter{}, errors.New("where stage requires a comparison")
}

func parseSummary(stage string) (Summary, time.Duration, string, error) {
	aggregateText, groupText, found := strings.Cut(stage, " by ")
	aggregateParts := strings.Split(aggregateText, ",")
	if len(aggregateParts) < 1 || len(aggregateParts) > 16 {
		return Summary{}, 0, "", errors.New("summarize requires between 1 and 16 aggregates")
	}
	summary := Summary{}
	aliases := map[string]bool{}
	for _, raw := range aggregateParts {
		expression := strings.TrimSpace(raw)
		open := strings.IndexByte(expression, '(')
		if open < 1 || !strings.HasSuffix(expression, ")") {
			return Summary{}, 0, "", errors.New("invalid aggregate")
		}
		function := expression[:open]
		field := strings.TrimSpace(expression[open+1 : len(expression)-1])
		switch function {
		case "count":
			if field != "" {
				return Summary{}, 0, "", errors.New("count accepts no field")
			}
		case "min", "max", "sum", "avg", "p50", "p95", "p99":
			if !validField(field) {
				return Summary{}, 0, "", errors.New("aggregate field is invalid")
			}
		default:
			return Summary{}, 0, "", errors.New("aggregate function is unsupported")
		}
		alias := function
		if field != "" {
			alias += "_" + strings.ReplaceAll(field, ".", "_")
		}
		if aliases[alias] {
			return Summary{}, 0, "", errors.New("aggregate alias is duplicated")
		}
		aliases[alias] = true
		summary.Aggregates = append(summary.Aggregates, Aggregate{Function: function, Field: field, Alias: alias})
	}
	var window time.Duration
	var windowText string
	if found {
		groups := strings.Split(groupText, ",")
		if len(groups) > 16 {
			return Summary{}, 0, "", errors.New("too many grouping fields")
		}
		for _, raw := range groups {
			group := strings.TrimSpace(raw)
			if strings.HasPrefix(group, "window(") && strings.HasSuffix(group, ")") {
				if window > 0 {
					return Summary{}, 0, "", errors.New("summary window is duplicated")
				}
				windowText = strings.TrimSpace(group[len("window(") : len(group)-1])
				parsed, err := time.ParseDuration(windowText)
				if err != nil || parsed < time.Second || parsed > maxQueryWindow {
					return Summary{}, 0, "", errors.New("summary window must be between 1s and 87600h")
				}
				window = parsed
				continue
			}
			if !validField(group) {
				return Summary{}, 0, "", errors.New("grouping field is invalid")
			}
			summary.GroupBy = append(summary.GroupBy, group)
		}
	}
	return summary, window, windowText, nil
}

func validField(field string) bool {
	if field == "" || len(field) > 128 {
		return false
	}
	for _, r := range field {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
