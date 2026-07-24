package analysis

import (
	"testing"

	go_converter "godzilla/converters/go"
	"godzilla/internal/rules"
	"godzilla/internal/rules/loader"
)

// TestAnalyze_ReturnFlowIsMedium is the ENG-7 regression guard. In
// test/go/return_flow the taint leaves readInput through its RETURN value and
// is sunk by the caller, so the flow is inter-procedural and must be reported
// at Medium confidence (which is the confidence tier the LLM reviewer
// adjudicates). Before the fix, taint arriving via a callee's return summary
// was not recorded as a cross-function origin, so the finding was mislabeled
// High and skipped the reviewer.
func TestAnalyze_ReturnFlowIsMedium(t *testing.T) {
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/return_flow/main.go")
	if err != nil {
		t.Fatalf("failed to convert return_flow sample: %v", err)
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "GO-CMDI-RET",
		Languages: []string{"go"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "untrusted input reaches os/exec via a return value",
		Sources:   []string{"go:*net/url*.Get"},
		Sinks:     rules.SinksOf("go:*os/exec.Command*"),
	}}}

	findings := NewEngine(rs).Analyze(prog)

	var f *Finding
	for i := range findings {
		if findings[i].RuleID == "GO-CMDI-RET" {
			f = &findings[i]
			break
		}
	}
	if f == nil {
		t.Fatalf("expected a return-flow command-injection finding, got %d finding(s)", len(findings))
	}
	if f.Confidence != ConfidenceMedium {
		t.Errorf("expected Medium confidence for a cross-function return flow, got %q", f.Confidence)
	}
}

// TestAnalyze_IntraProcStaysHigh guards against over-downgrading: a purely
// intra-procedural flow (source and sink in the same function) must remain
// High confidence after the ENG-7 change.
func TestAnalyze_IntraProcStaysHigh(t *testing.T) {
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/sql_injection/main.go")
	if err != nil {
		t.Fatalf("failed to convert sql_injection sample: %v", err)
	}

	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load built-in rules: %v", err)
	}

	findings := NewEngine(rs).Analyze(prog)
	sawHigh := false
	for _, f := range findings {
		if f.Confidence == ConfidenceHigh {
			sawHigh = true
		}
	}
	if !sawHigh {
		t.Errorf("expected at least one High-confidence intra-procedural finding in the sql_injection sample, got %d finding(s)", len(findings))
	}
}
