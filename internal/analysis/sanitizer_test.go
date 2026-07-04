package analysis

import (
	"testing"

	go_converter "godzilla/converters/go"
	"godzilla/internal/rules"
)

// TestAnalyze_SanitizerSuppressesReturnFlow is the ENG-1 regression guard. In
// test/go/sanitizer_bypass the untrusted query param passes through a
// project-local Sanitize helper before reaching os/exec. When the rule set
// registers "go:*Sanitize" as a sanitizer, taint must NOT reach the sink: the
// sanitizer's result is clean and must not be re-tainted by the callee's
// inter-procedural return summary. Before the fix, the sanitizer arm of
// handleCall fell through to the return-summary block and re-tainted the
// result, producing a false positive at High confidence.
func TestAnalyze_SanitizerSuppressesReturnFlow(t *testing.T) {
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/sanitizer_bypass/main.go")
	if err != nil {
		t.Fatalf("failed to convert sanitizer_bypass sample: %v", err)
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:         "GO-CMDI-SANITIZED",
		Languages:  []string{"go"},
		Severity:   rules.SeverityCritical,
		CWE:        "CWE-78",
		Message:    "untrusted input reaches os/exec",
		Sources:    []string{"go:*net/url*.Get"},
		Sinks:      []string{"go:*os/exec.Command*"},
		Sanitizers: []string{"go:*Sanitize"},
	}}}

	findings := NewEngine(rs).Analyze(prog)

	for _, f := range findings {
		if f.RuleID == "GO-CMDI-SANITIZED" {
			t.Fatalf("sanitizer bypassed: got a finding despite go:*Sanitize being a sanitizer "+
				"(source %v -> sink %v, confidence %q)", f.SourcePos, f.SinkPos, f.Confidence)
		}
	}
}

// TestAnalyze_SanitizerFlowFiresWithoutSanitizerRule guards the other
// direction: with the SAME sample but no sanitizer registered, the flow must
// still be detected (so the suppression above is attributable to the sanitizer,
// not to taint being dropped somewhere in Sanitize's body).
func TestAnalyze_SanitizerFlowFiresWithoutSanitizerRule(t *testing.T) {
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/sanitizer_bypass/main.go")
	if err != nil {
		t.Fatalf("failed to convert sanitizer_bypass sample: %v", err)
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "GO-CMDI-NOSAN",
		Languages: []string{"go"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "untrusted input reaches os/exec",
		Sources:   []string{"go:*net/url*.Get"},
		Sinks:     []string{"go:*os/exec.Command*"},
	}}}

	findings := NewEngine(rs).Analyze(prog)

	found := false
	for _, f := range findings {
		if f.RuleID == "GO-CMDI-NOSAN" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the source->Sanitize->exec flow to fire without a sanitizer rule, got %d finding(s)", len(findings))
	}
}
