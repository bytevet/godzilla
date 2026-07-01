package analysis

import (
	"strings"
	"testing"

	go_converter "godzilla/converters/go"
	"godzilla/internal/rules/loader"
)

// TestAnalyze_ParameterizedQueryNoFalsePositive is a regression test for the
// sink-argument-position fix: with the built-in rules, the sql_injection sample
// must flag the true positive (a tainted string used AS the query) but must NOT
// flag the parameterized call db.Query("... = ?", userInput), where the tainted
// value is a bound placeholder parameter (a safe argument position).
func TestAnalyze_ParameterizedQueryNoFalsePositive(t *testing.T) {
	prog, err := go_converter.NewConverter().ConvertFile("../../test/go/sql_injection/main.go")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load builtin rules: %v", err)
	}

	findings := NewEngine(rs).Analyze(prog)

	var sqli []Finding
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "go-sql-injection") {
			sqli = append(sqli, f)
		}
	}

	if len(sqli) == 0 {
		t.Fatalf("expected the true-positive SQL injection to still be detected, got none")
	}
	for _, f := range sqli {
		// handler2 is the parameterized query — it must NOT appear.
		if strings.Contains(f.Function, "handler2") {
			t.Errorf("false positive: parameterized query in handler2 was flagged (%s)", f.String())
		}
	}
	// And the real vulnerability (the fmt.Sprintf'd query in the /user handler
	// closure, main$1) must be present.
	foundTP := false
	for _, f := range sqli {
		if strings.Contains(f.Function, "main$1") {
			foundTP = true
		}
	}
	if !foundTP {
		t.Errorf("expected the true-positive SQL injection in main$1 to be detected; findings=%v", sqli)
	}
}
