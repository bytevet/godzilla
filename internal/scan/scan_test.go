package scan

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/rules/loader"
	"github.com/bytevet/godzilla/internal/testsupport"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// TestResultFailed checks the coverage predicate that drives the strict gate:
// only Detected-but-not-Converted languages are "failed".
func TestResultFailed(t *testing.T) {
	r := Result{Coverage: []LangCoverage{
		{Language: "go", Detected: true, Converted: true},
		{Language: "python", Detected: true, Converted: false, Err: "syntax error"},
		{Language: "rust", Detected: false},
	}}
	failed := r.Failed()
	if len(failed) != 1 || failed[0].Language != "python" {
		t.Fatalf("expected only python to be failed, got %+v", failed)
	}
}

// TestScanCoverageHappyPath asserts a successful Go directory scan records
// go as detected-and-converted, so a clean scan is provably a clean scan.
func TestScanCoverageHappyPath(t *testing.T) {
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	res, err := Scan("../../test/go/command_injection", rs)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var goCov *LangCoverage
	for i := range res.Coverage {
		if res.Coverage[i].Language == "go" {
			goCov = &res.Coverage[i]
		}
	}
	if goCov == nil || !goCov.Converted {
		t.Fatalf("expected go coverage Converted=true, got %+v", res.Coverage)
	}
	if len(res.Failed()) != 0 {
		t.Errorf("a healthy scan must report no failed coverage, got %+v", res.Failed())
	}
}

// TestScanFiles_ChangedFilesMode covers the CI-9 changed-files entry point:
// several explicit paths are analyzed together in one process, mixing a
// vulnerable source file, a clean one, and a non-source file. The vulnerable
// file must fire, the batch must merge into one result, and the non-source file
// must not abort the run.
func TestScanFiles_ChangedFilesMode(t *testing.T) {
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	res, err := ScanFiles([]string{
		"../../test/js/command_injection/app.js",
		"../../test/python/subprocess_argv_safe/app.py",
		"../../README.md", // non-source: must be skipped, not an error
	}, rs)
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	var sawCmdi bool
	for _, f := range res.Findings {
		if f.RuleID == "js-command-injection" {
			sawCmdi = true
		}
	}
	if !sawCmdi {
		t.Errorf("expected js-command-injection from the batch, got %d finding(s)", len(res.Findings))
	}
}

// TestScanFiles_DocsOnlyIsClean guards the pre-commit UX: a batch with no
// analyzable source (only docs) must NOT error — it returns cleanly so the hook
// does not spuriously fail the commit.
func TestScanFiles_DocsOnlyIsClean(t *testing.T) {
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	res, err := ScanFiles([]string{"../../README.md"}, rs)
	if err != nil {
		t.Fatalf("ScanFiles on docs-only batch should not error, got: %v", err)
	}
	for _, f := range res.Findings {
		if f.RuleID != "" && f.Severity.Rank() >= rules.SeverityMedium.Rank() {
			// A real secret in README would be a legitimate finding; the fixture
			// has none, so any medium+ finding here is unexpected.
			t.Errorf("unexpected finding in docs-only batch: %+v", f)
		}
	}
}

// TestScanCoverageFrontendFailure is the core WS3 guard: a frontend that fails
// to analyze detected source must be recorded as a coverage FAILURE, not
// silently dropped so the scan looks clean. (Before the fix, Scan only warned
// on stderr and returned success with no failure signal.)
func TestScanCoverageFrontendFailure(t *testing.T) {
	testsupport.RequireTool(t, "python3")
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	res, err := Scan("testdata/broken_py", rs)
	if err != nil {
		t.Fatalf("scan should succeed (fail-open) but flag coverage, got error: %v", err)
	}
	failed := res.Failed()
	if len(failed) != 1 || failed[0].Language != "python" {
		t.Fatalf("expected python coverage failure, got failed=%+v coverage=%+v", failed, res.Coverage)
	}
	if failed[0].Err == "" {
		t.Errorf("a coverage failure must carry the frontend error for diagnosis")
	}
}

// TestScan_FindsSecretsInConfigFiles is the COV-1 end-to-end guard: a credential
// in a .env config file (which no frontend parses) is reported by scan.Scan.
// The fixture is written to a temp dir and the secret assembled from fragments,
// so no complete credential is committed (avoids tripping push protection).
func TestScan_FindsSecretsInConfigFiles(t *testing.T) {
	dir := t.TempDir()
	// A trivial Go source file so a frontend runs (Convert needs a language).
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module cfgsec\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("AWS_ACCESS_KEY_ID="+awsKey+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	res, err := Scan(dir, rs)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.RuleID == "secret-aws-access-key" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected scan.Scan to report the .env secret, got %d finding(s)", len(res.Findings))
	}
}

// TestDropCoLocatedDangerous checks the call-site/dataflow dedup: a dangerous-call
// finding is dropped only when the taint engine already reported the SAME call
// (same position AND same callee), so a confirmed injection is reported once with
// its richer dataflow evidence. Everything else survives — most importantly a
// call-site finding with no dataflow twin, which is the entire point of a
// dangerous-call rule.
func TestDropCoLocatedDangerous(t *testing.T) {
	at := func(line int32) *ir.Position { return &ir.Position{Filename: "app.py", Line: line, Column: 5} }
	taint := []analysis.Finding{
		{RuleID: "py-code-injection", SinkPos: at(14), SinkCallee: "py:eval"},
		{RuleID: "py-code-injection", SinkPos: nil, SinkCallee: "py:exec"}, // position-less: keys nothing
	}
	danger := []analysis.Finding{
		{RuleID: "dup", SinkPos: at(14), SinkCallee: "py:eval"},  // exact twin: dropped
		{RuleID: "line", SinkPos: at(15), SinkCallee: "py:eval"}, // other line: kept
		{RuleID: "nest", SinkPos: at(14), SinkCallee: "py:exec"}, // same line, different call: kept
		{RuleID: "nopos", SinkPos: nil, SinkCallee: "py:exec"},   // no position: never deduped
	}
	var got []string
	for _, f := range dropCoLocatedDangerous(danger, taint) {
		got = append(got, f.RuleID)
	}
	want := []string{"line", "nest", "nopos"}
	if !slices.Equal(got, want) {
		t.Errorf("dropCoLocatedDangerous kept %v, want %v", got, want)
	}
}

// TestScanDiagnostics pins that the report's diagnostics panel gets real
// numbers on both entry points. ScanFiles is the one that would silently read
// zero: runAnalyses is handed no scan root and no inventory there, so the file
// list has to be accumulated by ScanFiles itself.
func TestScanDiagnostics(t *testing.T) {
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("loader.Builtin: %v", err)
	}
	dir := filepath.Join("..", "..", "test", "go", "sql_injection")

	for _, tc := range []struct {
		name string
		run  func() (Result, error)
	}{
		{"Scan", func() (Result, error) { return Scan(dir, rs) }},
		{"ScanFiles", func() (Result, error) {
			return ScanFiles([]string{filepath.Join(dir, "main.go")}, rs)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tc.run()
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			d := res.Diag
			if d.Files == 0 || d.Lines == 0 {
				t.Errorf("Files=%d Lines=%d; both must be counted", d.Files, d.Lines)
			}
			if d.Lines < d.Files {
				t.Errorf("Lines=%d < Files=%d; a source file has at least one line", d.Lines, d.Files)
			}
			if d.Packages == 0 || d.Functions == 0 || d.Rules == 0 {
				t.Errorf("Packages=%d Functions=%d Rules=%d; none may be zero", d.Packages, d.Functions, d.Rules)
			}
			if d.SinkSites == 0 {
				t.Error("SinkSites = 0, but this sample calls a sink")
			}
			if d.Wall <= 0 || d.Convert <= 0 || d.Analysis <= 0 {
				t.Errorf("Wall=%v Convert=%v Analysis=%v; all must be timed", d.Wall, d.Convert, d.Analysis)
			}
			// Index/RuleSel/Taint are sub-spans of Analysis, and Convert plus
			// Analysis are sub-spans of Wall. The report's phase bars assume both.
			if sub := d.Index + d.RuleSel + d.Taint; sub > d.Analysis {
				t.Errorf("engine sub-spans %v exceed Analysis %v", sub, d.Analysis)
			}
			if d.Convert+d.Analysis > d.Wall {
				t.Errorf("Convert+Analysis %v exceeds Wall %v", d.Convert+d.Analysis, d.Wall)
			}
			// Memory is deliberately NOT sampled by a scan: ReadMemStats stops
			// the world, and this is a library call. The CLI samples it.
			if d.PeakBytes != 0 {
				t.Errorf("PeakBytes = %d; a scan must not call ReadMemStats", d.PeakBytes)
			}
		})
	}
}
