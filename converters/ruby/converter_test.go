package ruby_converter

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/testsupport"
)

// requireRuby skips when no ruby is on PATH (the frontend shells out to it for
// the Ripper AST dump).
func requireRuby(t *testing.T) { testsupport.RequireTool(t, "ruby") }

func cmdiRules(t testing.TB) *rules.RuleSet {
	return testsupport.OneRuleSet(t, "ruby-cmdi", "ruby", "CWE-78",
		[]string{"ruby:params", "ruby:request.*", "ruby:req.*"},
		[]string{"ruby:system#0", "ruby:%x"},
		testsupport.Severity(rules.SeverityCritical),
		testsupport.Message("command injection"))
}

// TestCommandInjection exercises the core taint paths for the cmdi rule,
// including that the safe multi-arg form system("ls", x) does NOT fire, because
// the sink pins arg #0.
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
			findings := analysis.NewEngine(cmdiRules(t)).Analyze(prog)
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

// TestConvertCorpusTreeIsFullyModeled converts the whole Ruby corpus and pins
// both halves of "this tree converted completely": nothing skipped, and no
// instruction lowered to a fallback intrinsic.
//
// Neither is visible otherwise. A batch errors only when ZERO files convert, so
// a frontend can drop all but one file and still report Converted; and an
// unmodelled construct costs findings with nothing failing.
func TestConvertCorpusTreeIsFullyModeled(t *testing.T) {
	requireRuby(t)
	c := NewConverter()
	prog, err := c.ConvertFile(filepath.Join("..", "..", "test", "ruby"))
	if err != nil {
		t.Fatalf("ConvertFile(test/ruby): %v", err)
	}
	if c.Skipped() != 0 {
		t.Errorf("Skipped() = %d, want 0", c.Skipped())
	}
	testsupport.RequireNoFallbackIntrinsic(t, prog, "ruby.unsupported", "test/ruby")
}
