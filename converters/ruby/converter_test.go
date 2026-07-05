package ruby_converter

import (
	"os/exec"
	"strings"
	"testing"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
)

func requireRuby(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ruby"); err != nil {
		t.Skip("ruby not found on PATH; skipping")
	}
}

func cmdiRules() *rules.RuleSet {
	return &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "ruby-cmdi",
		Languages: []string{"ruby"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "command injection",
		Sources:   []string{"ruby:params", "ruby:request.*"},
		Sinks:     []string{"ruby:system#0", "ruby:%x"},
	}}}
}

// TestCommandInjection_ParamsToSystem proves the core taint path: a request
// parameter (params[:x]) concatenated into a single-string system() call fires.
func TestCommandInjection_ParamsToSystem(t *testing.T) {
	requireRuby(t)
	prog, err := NewConverter().ConvertFile("../../test/ruby/command_injection/app.rb")
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}
	findings := analysis.NewEngine(cmdiRules()).Analyze(prog)
	if !hasRule(findings, "ruby-cmdi") {
		t.Fatalf("expected ruby-cmdi finding, got %d: %v", len(findings), findings)
	}
}

// TestBacktick_Interpolation proves a backtick command literal with an
// interpolated tainted value (“ `ping #{host}` “) fires as a shell exec.
func TestBacktick_Interpolation(t *testing.T) {
	requireRuby(t)
	prog, err := NewConverter().ConvertFile("../../test/ruby/backtick_injection/app.rb")
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}
	findings := analysis.NewEngine(cmdiRules()).Analyze(prog)
	if !hasRule(findings, "ruby-cmdi") {
		t.Fatalf("expected ruby-cmdi finding from backtick interpolation, got %d: %v", len(findings), findings)
	}
}

// TestArgListForm_NotFlagged proves the safe multi-arg form system("ls", x) —
// which invokes no shell — does not fire, because the command sink pins arg #0.
func TestArgListForm_NotFlagged(t *testing.T) {
	requireRuby(t)
	prog, err := NewConverter().ConvertFile("../../test/ruby/command_injection_safe/app.rb")
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}
	findings := analysis.NewEngine(cmdiRules()).Analyze(prog)
	if hasRule(findings, "ruby-cmdi") {
		t.Errorf("multi-arg system() must not be flagged (no shell), got: %v", findings)
	}
}

// TestModuleAndCanonicalNames checks the module shape: language tag, a function
// per def, and canonical names carrying the module path.
func TestModuleAndCanonicalNames(t *testing.T) {
	requireRuby(t)
	prog, err := NewConverter().ConvertFile("../../test/ruby/command_injection/app.rb")
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("expected 1 module, got %d", len(prog.Modules))
	}
	mod := prog.Modules[0]
	if mod.Language != "ruby" {
		t.Errorf("Language = %q, want ruby", mod.Language)
	}
	var found bool
	for _, fn := range mod.Functions {
		if fn.ObjectName == "handle" && strings.HasSuffix(fn.CanonicalName, ".handle") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a handle function with a .handle canonical name, got %v", mod.Functions)
	}
}

func hasRule(findings []analysis.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
