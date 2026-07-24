package analysis

import (
	"testing"

	go_converter "godzilla/converters/go"
	"godzilla/internal/rules"
)

// TestAnalyze_DeferAndMapFlows is a regression test for two taint blind spots
// that a review found and that were subsequently fixed:
//   - a sink invoked via `defer` (go.defer intrinsic carries the CallCommon), and
//   - taint written into a map and read back out (go.map.update → go.map.lookup).
func TestAnalyze_DeferAndMapFlows(t *testing.T) {
	prog, err := go_converter.NewConverter().ConvertFile("../../test/go/edgecases/main.go")
	if err != nil {
		t.Fatalf("failed to convert edgecases sample: %v", err)
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{
		{
			ID:        "GO-SQLI-DEFER",
			Languages: []string{"go"},
			Severity:  rules.SeverityHigh,
			CWE:       "CWE-89",
			Message:   "tainted query reaches a deferred DB call",
			Sources:   []string{"go:*Request*.FormValue"},
			Sinks:     rules.SinksOf("go:*database/sql*.Query*"),
		},
		{
			ID:        "GO-CMDI-MAP",
			Languages: []string{"go"},
			Severity:  rules.SeverityCritical,
			CWE:       "CWE-78",
			Message:   "tainted value flows through a map into os/exec",
			Sources:   []string{"go:*Request*.FormValue"},
			Sinks:     rules.SinksOf("go:*os/exec.Command*"),
		},
	}}

	findings := NewEngine(rs).Analyze(prog)
	got := map[string]bool{}
	for _, f := range findings {
		got[f.RuleID] = true
	}
	if !got["GO-SQLI-DEFER"] {
		t.Errorf("expected a finding via `defer` (GO-SQLI-DEFER); go.defer call handling regressed. findings=%v", findings)
	}
	if !got["GO-CMDI-MAP"] {
		t.Errorf("expected a finding via map write→read (GO-CMDI-MAP); go.map.update taint regressed. findings=%v", findings)
	}
}
