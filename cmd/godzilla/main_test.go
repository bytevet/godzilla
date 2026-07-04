package main

import (
	"os/exec"
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
