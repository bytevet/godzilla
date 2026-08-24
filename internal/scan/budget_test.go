package scan

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bytevet/godzilla/internal/rules/loader"
	"github.com/bytevet/godzilla/internal/walkignore"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// installFakeFrontend registers a frontend for the .fake extension that returns
// r verbatim, and removes it when the test ends. It drives a chosen
// convertResult through the real convert/coverage path, which is what lets the
// degraded plumbing be tested without depending on a particular frontend
// deciding to degrade.
func installFakeFrontend(t *testing.T, r convertResult) {
	t.Helper()
	saved := languageFrontends
	languageFrontends = append(slices.Clone(saved), frontend{
		name:    "fake",
		convert: func(string, *walkignore.Inventory, config) (convertResult, error) { return r, nil },
		matches: func(p string) bool { return strings.HasSuffix(p, ".fake") },
	})
	t.Cleanup(func() { languageFrontends = saved })
}

// TestScanCoverageDegraded is the counterpart to TestScanCoverageFrontendFailure:
// a frontend that ran but at reduced dependency depth is recorded as degraded
// and NOT as a failure, so the -strict gate (which keys on Failed) still passes
// on a scan the budget rescued from being OOM-killed.
func TestScanCoverageDegraded(t *testing.T) {
	const note = "2 of 7 dependency packages loaded as signatures only"
	installFakeFrontend(t, convertResult{prog: &ir.Program{}, degraded: true, degradedNote: note})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.fake"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	res, err := Scan(dir, rs, WithDiagnostics())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var cov *LangCoverage
	for i := range res.Coverage {
		if res.Coverage[i].Language == "fake" {
			cov = &res.Coverage[i]
		}
	}
	if cov == nil {
		t.Fatalf("no coverage entry for the degraded frontend: %+v", res.Coverage)
	}
	if !cov.Converted {
		t.Errorf("a degraded scan RAN: want Converted=true, got %+v", *cov)
	}
	if !cov.Degraded || cov.DegradedNote != note {
		t.Errorf("want Degraded=true with the frontend's note, got %+v", *cov)
	}
	if len(res.Failed()) != 0 {
		t.Errorf("degraded must not be a failure (-strict would fail closed), got %+v", res.Failed())
	}
	if !strings.Contains(res.Diag.DegradedNote, note) {
		t.Errorf("the report's diagnostics panel lost the note: %q", res.Diag.DegradedNote)
	}
}

// TestScanDegradedEndToEnd is the same guarantee through the real Go frontend:
// a budget of zero bytes admits no dependency package, so a sample that imports
// one is analyzed against signatures alone — degraded, converted, not failed.
func TestScanDegradedEndToEnd(t *testing.T) {
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	res, err := Scan("../../test/go/dep_transit_safe", rs, WithDepBudget(0))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var cov *LangCoverage
	for i := range res.Coverage {
		if res.Coverage[i].Language == "go" {
			cov = &res.Coverage[i]
		}
	}
	if cov == nil || !cov.Converted {
		t.Fatalf("want go Converted=true, got %+v", res.Coverage)
	}
	if !cov.Degraded || cov.DegradedNote == "" {
		t.Errorf("a zero budget must degrade a sample that imports a dependency, got %+v", *cov)
	}
	if len(res.Failed()) != 0 {
		t.Errorf("degraded must not be a failure, got %+v", res.Failed())
	}
}

// TestWarnDegraded pins the stream: the degraded warning goes to stderr, never
// stdout, which carries the machine-readable output.
func TestWarnDegraded(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	warnDegraded(LangCoverage{Language: "go", Degraded: true, DegradedNote: "trimmed"}, "/repo")
	warnDegraded(LangCoverage{Language: "python"}, "/repo")
	os.Stderr = saved
	_ = w.Close()
	out, _ := io.ReadAll(r)

	got := string(out)
	if !strings.Contains(got, "go frontend degraded under /repo: trimmed") {
		t.Errorf("degraded warning missing from stderr: %q", got)
	}
	if strings.Contains(got, "python") {
		t.Errorf("a frontend that did not degrade must be silent: %q", got)
	}
}

// TestDefaultDepBudget checks the two branches the derivation has: a detectable
// memory bound yields a positive cap, and an undetectable one falls back to
// unlimited so a host memlimit cannot read behaves as it did before the budget.
func TestDefaultDepBudget(t *testing.T) {
	got := DefaultDepBudget()
	if got == 0 {
		t.Fatalf("DefaultDepBudget must be a positive cap or -1 (unlimited), got 0")
	}
	if got > 0 && got < 1<<20 {
		t.Errorf("a derived budget under 1 MiB would drop every dependency: %d", got)
	}
}

// TestWithDepBudget pins the option's default: a scan that does not ask for a
// budget is unlimited, which keeps every existing caller of Scan analyzing the
// whole dependency closure.
func TestWithDepBudget(t *testing.T) {
	if c := newConfig(nil); c.depBudget >= 0 {
		t.Errorf("no option must mean unlimited (negative), got %d", c.depBudget)
	}
	if c := newConfig([]Option{WithDepBudget(4096)}); c.depBudget != 4096 {
		t.Errorf("WithDepBudget(4096) = %d", c.depBudget)
	}
}
