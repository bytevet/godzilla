package corpus

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"godzilla/internal/rules/loader"
	"godzilla/internal/scan"
)

// TestCorpus runs the real scan pipeline over every sample under
// test/{go,python,js} with the built-in rule set, and asserts the result
// matches the sample's expected.yaml: every expected rule fires at least `min`
// times, and NO other rule fires (a false-positive guard). One subtest per
// sample, so failures name the exact sample.
func TestCorpus(t *testing.T) {
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load built-in rules: %v", err)
	}
	dirs, err := sampleDirs()
	if err != nil {
		t.Fatalf("enumerate samples: %v", err)
	}

	_, pyErr := exec.LookPath("python3")
	pythonAvailable := pyErr == nil
	_, javaErr := exec.LookPath("java")
	javaAvailable := javaErr == nil
	_, clangErr := exec.LookPath("clang")
	clangAvailable := clangErr == nil

	for _, dir := range dirs {
		name := filepath.ToSlash(strings.TrimPrefix(dir, "../")) // e.g. "go/sql_injection"
		t.Run(name, func(t *testing.T) {
			exp, err := loadExpectation(filepath.Join(dir, "expected.yaml"))
			if err != nil {
				t.Fatalf("missing/invalid expected.yaml: %v (add one, or run the RegenerateManifests helper)", err)
			}
			if strings.HasPrefix(name, "python/") && !pythonAvailable {
				t.Skip("python3 not on PATH; skipping Python sample")
			}
			if strings.HasPrefix(name, "java/") && !javaAvailable {
				t.Skip("java not on PATH; skipping Java sample")
			}
			if strings.HasPrefix(name, "c/") || strings.HasPrefix(name, "cpp/") {
				if !llvmBuilt {
					t.Skip("built without -tags llvm; the C/C++ frontend is a stub")
				}
				if !clangAvailable {
					t.Skip("clang not on PATH; skipping C/C++ sample")
				}
			}

			res, err := scan.Scan(dir, rs)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			got := countByRule(res.Findings)

			expected := map[string]bool{}
			for _, ef := range exp.Findings {
				min := ef.Min
				if min < 1 {
					min = 1
				}
				expected[ef.Rule] = true
				if got[ef.Rule] < min {
					t.Errorf("rule %q: want >= %d finding(s), got %d", ef.Rule, min, got[ef.Rule])
				}
			}
			for rule, n := range got {
				if !expected[rule] {
					t.Errorf("unexpected finding: rule %q fired %d time(s) but is not in expected.yaml (false positive?)", rule, n)
				}
			}
		})
	}
}
