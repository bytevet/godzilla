package ruletest

import (
	"os"
	"path/filepath"
	"testing"

	"godzilla/internal/rules/loader"
)

// writeSample lays out a Go sample project (go.mod + main.go + expected.yaml).
func writeSample(t *testing.T, root, name, main, expected string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod":        "module " + name + "\n\ngo 1.21\n",
		"main.go":       main,
		"expected.yaml": expected,
	}
	for fn, body := range files {
		if err := os.WriteFile(filepath.Join(dir, fn), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

const cmdiMain = `package main

import (
	"net/http"
	"os/exec"
)

func h(w http.ResponseWriter, r *http.Request) {
	_ = exec.Command("sh", "-c", r.URL.Query().Get("cmd")).Run()
	_ = w
}

func main() { http.HandleFunc("/x", h); _ = http.ListenAndServe(":0", nil) }
`

func TestRunDir(t *testing.T) {
	root := t.TempDir()
	// A sample that should PASS: the rule is expected and fires.
	writeSample(t, root, "pass", cmdiMain, "findings:\n  - rule: go-command-injection\n    min: 1\n")
	// A sample that should FAIL: it declares no findings but the code is vulnerable.
	writeSample(t, root, "fpfail", cmdiMain, "findings: []\n")
	// A sample that should FAIL: it expects a rule that does not fire.
	writeSample(t, root, "missing", cmdiMain, "findings:\n  - rule: go-sql-injection\n    min: 1\n")

	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	results, err := RunDir(root, rs)
	if err != nil {
		t.Fatalf("RunDir: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 samples, got %d", len(results))
	}
	byName := map[string]Result{}
	for _, r := range results {
		byName[r.Sample] = r
	}
	if !byName["pass"].Pass {
		t.Errorf("pass sample should pass, got failures: %v", byName["pass"].Failures)
	}
	if byName["fpfail"].Pass {
		t.Errorf("fpfail sample should fail (unexpected finding on a findings:[] sample)")
	}
	if byName["missing"].Pass {
		t.Errorf("missing sample should fail (expected rule did not fire)")
	}
}

func TestRunDir_IgnoresNonSamples(t *testing.T) {
	root := t.TempDir()
	// A directory with no expected.yaml is not a sample.
	if err := os.MkdirAll(filepath.Join(root, "notasample"), 0o755); err != nil {
		t.Fatal(err)
	}
	rs, _ := loader.Builtin()
	results, err := RunDir(root, rs)
	if err != nil {
		t.Fatalf("RunDir: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 samples (no expected.yaml), got %d", len(results))
	}
}
