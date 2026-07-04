package config

import (
	"os"
	"path/filepath"
	"testing"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

func TestPathMatches(t *testing.T) {
	cases := []struct {
		glob, rel string
		want      bool
	}{
		{"testdata", "pkg/testdata/x.go", true},   // bare name matches a segment
		{"testdata", "pkg/testfoo/x.go", false},   // not a whole segment
		{"*.pb.go", "gen/api.pb.go", true},        // bare glob on basename
		{"*.pb.go", "gen/api.go", false},          //
		{"testdata/**", "testdata/a/b.go", true},  // ** across segments
		{"testdata/**", "src/a.go", false},        //
		{"src/**/gen.go", "src/a/b/gen.go", true}, // ** in the middle
		{"src/*.go", "src/a.go", true},            // * within a segment
		{"src/*.go", "src/a/b.go", false},         // * does not cross '/'
		{"vendor/**", "vendor/x/y.go", true},      //
	}
	for _, c := range cases {
		if got := pathMatches(c.glob, c.rel); got != c.want {
			t.Errorf("pathMatches(%q, %q) = %v, want %v", c.glob, c.rel, got, c.want)
		}
	}
}

func TestApplyRules(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{ID: "a", Severity: rules.SeverityHigh},
		{ID: "b", Severity: rules.SeverityHigh},
		{ID: "c", Severity: rules.SeverityLow},
	}}
	cfg := &Config{Rules: Rules{
		Disable:           []string{"b"},
		SeverityOverrides: map[string]string{"c": "critical", "a": "bogus"}, // bogus ignored
	}}
	out := cfg.ApplyRules(rs)

	if len(out.Rules) != 2 {
		t.Fatalf("expected 2 rules after disabling b, got %d", len(out.Rules))
	}
	byID := map[string]rules.Severity{}
	for _, r := range out.Rules {
		byID[r.ID] = r.Severity
	}
	if _, ok := byID["b"]; ok {
		t.Errorf("rule b should be disabled")
	}
	if byID["c"] != rules.SeverityCritical {
		t.Errorf("rule c severity override not applied, got %q", byID["c"])
	}
	if byID["a"] != rules.SeverityHigh {
		t.Errorf("bogus override on a should be ignored, got %q", byID["a"])
	}
	// Original ruleset must be untouched.
	if rs.Rules[2].Severity != rules.SeverityLow {
		t.Errorf("ApplyRules mutated the input ruleset")
	}
}

func TestFilterFindings(t *testing.T) {
	root := t.TempDir()
	f := func(file string) analysis.Finding {
		return analysis.Finding{
			RuleID:  "r",
			SinkPos: &ir.Position{Filename: filepath.Join(root, file), Line: 1},
		}
	}
	findings := []analysis.Finding{
		f("app/handler.go"),
		f("app/testdata/vuln.go"),
		f("gen/api.pb.go"),
	}
	cfg := &Config{Exclude: []string{"testdata", "*.pb.go"}}
	out, n := cfg.FilterFindings(findings, root)
	if n != 2 {
		t.Fatalf("expected 2 excluded, got %d", n)
	}
	if out[0].Suppressed {
		t.Errorf("app/handler.go should be kept")
	}
	if !out[1].Suppressed || out[1].SuppressedBy != "config-path-filter" {
		t.Errorf("testdata finding should be suppressed by path filter, got %+v", out[1])
	}
	if !out[2].Suppressed {
		t.Errorf("generated .pb.go finding should be excluded")
	}
}

func TestFilterFindings_IncludeAllowlist(t *testing.T) {
	root := t.TempDir()
	f := func(file string) analysis.Finding {
		return analysis.Finding{SinkPos: &ir.Position{Filename: filepath.Join(root, file), Line: 1}}
	}
	// Only findings under src/ are kept; everything else is excluded.
	cfg := &Config{Include: []string{"src/**"}}
	out, n := cfg.FilterFindings([]analysis.Finding{f("src/a.go"), f("lib/b.go")}, root)
	if n != 1 {
		t.Fatalf("expected 1 excluded (outside include), got %d", n)
	}
	if out[0].Suppressed {
		t.Errorf("src/a.go is inside the include allowlist, should be kept")
	}
	if !out[1].Suppressed {
		t.Errorf("lib/b.go is outside the include allowlist, should be excluded")
	}
}

func TestLoad(t *testing.T) {
	root := t.TempDir()
	// No file: not an error, nil config.
	if c, p, err := Load(root); err != nil || c != nil || p != "" {
		t.Fatalf("missing config should be (nil,\"\",nil), got (%v,%q,%v)", c, p, err)
	}
	// A real file parses.
	body := "fail-on: high\nexclude:\n  - testdata\nrules:\n  disable: [x]\n"
	if err := os.WriteFile(filepath.Join(root, ".godzilla.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, p, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c == nil || c.FailOn != "high" || len(c.Exclude) != 1 || len(c.Rules.Disable) != 1 {
		t.Errorf("config not parsed as expected: %+v (from %s)", c, p)
	}
}
