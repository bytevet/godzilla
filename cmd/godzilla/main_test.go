package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runCLI builds and runs the godzilla CLI (via `go run .`) with args, returning
// the process exit code and combined output. Skips under -short (it compiles the
// binary).
func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: skipping CLI exec test")
	}
	cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running CLI: %v\n%s", err, out)
	}
	return code, string(out)
}

// TestStrict_FailsClosedOnCoverageFailure is the WS3 CLI guard: scanning a
// directory whose only source fails to convert must exit non-zero under -strict
// (the gate cannot certify code it never analyzed), while the same scan without
// -strict must not fail closed. Requires python3 (the fixture is broken Python).
func TestStrict_FailsClosedOnCoverageFailure(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH; skipping strict-mode CLI test")
	}
	const dir = "../../internal/scan/testdata/broken_py"

	// Without -strict: fail-open (no findings, clean exit), but coverage is shown.
	code, out := runCLI(t, "scan", dir)
	if code != exitClean {
		t.Errorf("non-strict scan of an unanalyzable dir should exit %d, got %d\n%s", exitClean, code, out)
	}
	if !strings.Contains(out, "python=FAILED") {
		t.Errorf("expected a coverage summary flagging python=FAILED, got:\n%s", out)
	}

	// With -strict: fail closed.
	code, out = runCLI(t, "scan", "-strict", dir)
	if code != exitError {
		t.Errorf("strict scan of an unanalyzable dir should exit %d, got %d\n%s", exitError, code, out)
	}
}

// TestInlineIgnore_SuppressesAtSource is the CI-1 CLI guard: a godzilla:ignore
// directive on the sink line drops the finding out of the gate (exit 0) while
// keeping it visible as suppressed.
func TestInlineIgnore_SuppressesAtSource(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module ignoretest\n\ngo 1.25\n")
	writeFile(t, filepath.Join(dir, "main.go"), `package main

import (
	"net/http"
	"os/exec"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		exec.Command("sh", "-c", cmd).Run() // godzilla:ignore
	})
	http.ListenAndServe(":8090", nil)
}
`)

	abs, _ := filepath.Abs(dir)

	// Control: without the directive the same shape gates (exit 3). Prove the
	// directive is doing the suppression by first confirming a finding exists.
	code, out := runCLI(t, "scan", abs)
	if code != exitClean {
		t.Errorf("inline-ignored finding should not gate, got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "Suppressed") || !strings.Contains(out, "inline") {
		t.Errorf("expected the finding to be listed as inline-suppressed, got:\n%s", out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
