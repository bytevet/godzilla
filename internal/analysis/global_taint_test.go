package analysis

import (
	"testing"

	go_converter "godzilla/converters/go"
	"godzilla/internal/rules"
)

// TestAnalyze_GlobalTaintFlow is the ENG-6(a) regression guard: taint stored
// into a package-level global by one function and read back by another must
// flow through the global to a sink. The flow crosses a function boundary via
// program-wide state, so the finding is Medium confidence (the tier the LLM
// reviewer adjudicates). Before ENG-6 a store to a global dropped the taint
// entirely — a silent false negative for the very common "stash request data
// in a package var" idiom.
func TestAnalyze_GlobalTaintFlow(t *testing.T) {
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/global_taint/main.go")
	if err != nil {
		t.Fatalf("failed to convert global_taint sample: %v", err)
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "GO-CMDI-GLOBAL",
		Languages: []string{"go"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "untrusted input reaches os/exec via a package global",
		Sources:   []string{"go:*net/url*.Get"},
		Sinks:     []string{"go:*os/exec.Command*"},
	}}}

	findings := NewEngine(rs).Analyze(prog)

	var f *Finding
	for i := range findings {
		if findings[i].RuleID == "GO-CMDI-GLOBAL" {
			f = &findings[i]
			break
		}
	}
	if f == nil {
		t.Fatalf("expected a command-injection finding through the package global, got %d finding(s)", len(findings))
	}
	if f.Confidence != ConfidenceMedium {
		t.Errorf("expected Medium confidence for a cross-function flow through a global, got %q", f.Confidence)
	}
}

// TestAnalyze_GlobalTaintSafe is the false-positive control for ENG-6: when the
// global holds only a constant (request data is never stored into it), the sink
// that reads the global must NOT be flagged — the global-taint layer must not
// taint a global that was never written a tainted value.
func TestAnalyze_GlobalTaintSafe(t *testing.T) {
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/global_taint_safe/main.go")
	if err != nil {
		t.Fatalf("failed to convert global_taint_safe sample: %v", err)
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "GO-CMDI-GLOBAL",
		Languages: []string{"go"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "untrusted input reaches os/exec via a package global",
		Sources:   []string{"go:*net/url*.Get"},
		Sinks:     []string{"go:*os/exec.Command*"},
	}}}

	findings := NewEngine(rs).Analyze(prog)
	for _, f := range findings {
		if f.RuleID == "GO-CMDI-GLOBAL" {
			t.Errorf("false positive: flagged a sink reading a constant global (%s at %v)", f.SinkCallee, f.SinkPos)
		}
	}
}
