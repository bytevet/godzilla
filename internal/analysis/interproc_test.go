package analysis

import (
	"testing"

	go_converter "godzilla/converters/go"
	"godzilla/internal/rules"
)

// TestAnalyze_Interprocedural validates that taint is tracked across a function
// boundary: in test/go/interproc the HTTP handler reads an untrusted query
// param and passes it to a separate helper (runCommand) that contains the
// os/exec sink. The flow is only detectable inter-procedurally, and because it
// crosses a call boundary it is reported at Medium confidence.
func TestAnalyze_Interprocedural(t *testing.T) {
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/interproc/main.go")
	if err != nil {
		t.Fatalf("failed to convert interproc sample: %v", err)
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "GO-CMDI-TEST",
		Languages: []string{"go"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "untrusted input reaches os/exec across a function call",
		Sources:   []string{"go:*Values*.Get"},
		Sinks:     rules.SinksOf("go:*os/exec.Command*"),
	}}}

	findings := NewEngine(rs).Analyze(prog)

	var f *Finding
	for i := range findings {
		if findings[i].RuleID == "GO-CMDI-TEST" {
			f = &findings[i]
			break
		}
	}
	if f == nil {
		t.Fatalf("expected an inter-procedural command-injection finding, got %d finding(s): %v", len(findings), findings)
	}
	if f.Confidence != ConfidenceMedium {
		t.Errorf("expected medium confidence for a cross-function flow, got %q", f.Confidence)
	}
	if f.SourcePos == nil || f.SinkPos == nil {
		t.Errorf("finding missing source/sink positions: %+v", *f)
	}
}
