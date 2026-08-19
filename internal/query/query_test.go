// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseBoundedQuery(t *testing.T) {
	ast, err := Parse(`logs | where service == "eql" | where status >= 500 | window 24h | sort timestamp desc | limit 50`, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if ast.Limit != 50 || len(ast.Filters) != 2 || ast.WindowText != "24h" || ast.Sort == nil || !ast.Sort.Descending {
		t.Fatalf("unexpected AST: %#v", ast)
	}
}

func TestTextAndVisualBuilderShareValidatedAST(t *testing.T) {
	fromText, err := Parse(`metrics | where service == "eql" | window 1h | limit 25`, 1000)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(fromText)
	if err != nil {
		t.Fatal(err)
	}
	var fromBuilder AST
	if err := json.Unmarshal(b, &fromBuilder); err != nil {
		t.Fatal(err)
	}
	fromBuilder.Window = fromText.Window
	fromBuilder.Bucket = fromText.Bucket
	if err := Validate(fromBuilder, 1000); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromText, fromBuilder) {
		t.Fatalf("text=%+v builder=%+v", fromText, fromBuilder)
	}
	fromBuilder.Filters[0].Op = "SQL"
	if err := Validate(fromBuilder, 1000); err == nil {
		t.Fatal("expected hostile builder AST rejection")
	}
}

func TestParseRejectsSQLAndUnboundedLimit(t *testing.T) {
	for _, input := range []string{"select * from logs", "logs | limit 1001", "logs | where route;drop == x"} {
		if _, err := Parse(input, 1000); err == nil {
			t.Fatalf("expected rejection for %q", input)
		}
	}
}

func TestParseUnifiedSummaryAndSafeRegex(t *testing.T) {
	ast, err := Parse(`logs | where route =~ "^/items/[0-9]+$" | summarize count(), p95(duration) by route, window(5m) | sort count desc | limit 50`, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if ast.Summary == nil || len(ast.Summary.Aggregates) != 2 || len(ast.Summary.GroupBy) != 1 || ast.WindowText != "" || ast.BucketText != "5m" || ast.Summary.Aggregates[1].Alias != "p95_duration" {
		t.Fatalf("ast=%+v", ast)
	}
	if _, err := Parse(`logs | where route =~ "["`, 1000); err == nil {
		t.Fatal("expected invalid regular expression rejection")
	}
}

func TestParseSupportsApprovedTenYearColdLookback(t *testing.T) {
	ast, err := Parse(`logs | window 87600h | limit 10`, 100)
	if err != nil || ast.Window != maxQueryWindow {
		t.Fatalf("ast=%+v err=%v", ast, err)
	}
	if _, err = Parse(`logs | window 87601h | limit 10`, 100); err == nil {
		t.Fatal("lookback beyond retention ceiling was accepted")
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		`logs | where service == "eql" | limit 50`,
		`metrics | summarize count(), p95(duration) by route, window(5m) | limit 50`,
		`traces | where trace_id =~ "^[0-9a-f]{32}$" | window 1h | limit 10`,
		`select * from logs`,
		string([]byte{0, 1, 2, 3}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 20_000 {
			return
		}
		ast, err := Parse(text, 1_000)
		if err != nil {
			return
		}
		if err = Validate(ast, 1_000); err != nil {
			t.Fatalf("parser returned an invalid AST: %v", err)
		}
		if ast.Limit < 1 || ast.Limit > 1_000 || len(ast.Filters) > 16 {
			t.Fatalf("accepted AST violates hard bounds: %+v", ast)
		}
	})
}
