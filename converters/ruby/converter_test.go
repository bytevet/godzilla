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
		Sources:   []string{"ruby:params", "ruby:request.*", "ruby:req.*"},
		Sinks:     rules.SinksOf("ruby:system#0", "ruby:%x"),
	}}}
}

// TestCommandInjection exercises the core taint paths for the cmdi rule:
//   - params[:x] concatenated into a single-string system() call fires;
//   - a backtick literal with an interpolated tainted value (`ping #{host}`) fires;
//   - the safe multi-arg form system("ls", x) — no shell — does not, because the
//     sink pins arg #0.
func TestCommandInjection(t *testing.T) {
	requireRuby(t)
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"params-to-system", "../../test/ruby/command_injection/app.rb", true},
		{"backtick-interpolation", "../../test/ruby/backtick_injection/app.rb", true},
		{"arg-list-form-safe", "../../test/ruby/command_injection_safe/app.rb", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := NewConverter().ConvertFile(tc.path)
			if err != nil {
				t.Fatalf("ConvertFile: %v", err)
			}
			findings := analysis.NewEngine(cmdiRules()).Analyze(prog)
			if got := hasRule(findings, "ruby-cmdi"); got != tc.want {
				t.Errorf("ruby-cmdi finding = %v, want %v (findings: %v)", got, tc.want, findings)
			}
		})
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
