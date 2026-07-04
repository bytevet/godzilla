package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"godzilla/internal/rules/loader"
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

// TestScanCoverageFrontendFailure is the core WS3 guard: a frontend that fails
// to analyze detected source must be recorded as a coverage FAILURE, not
// silently dropped so the scan looks clean. (Before the fix, Scan only warned
// on stderr and returned success with no failure signal.)
func TestScanCoverageFrontendFailure(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH; skipping frontend-failure coverage test")
	}
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
