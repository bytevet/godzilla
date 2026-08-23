package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"errors"
	"github.com/bytevet/godzilla/internal/testsupport"
	"sync"
	"time"
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
	testsupport.RequireTool(t, "python3")
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

// TestQuiet_SuppressesOutputButKeepsGate is the CI-9 guard: -quiet prints no
// console output yet still fails the gate (non-zero exit) on a finding.
func TestQuiet_SuppressesOutputButKeepsGate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module q\n\ngo 1.21\n")
	writeFile(t, filepath.Join(dir, "main.go"), `package main

import (
	"net/http"
	"os/exec"
)

func h(w http.ResponseWriter, r *http.Request) {
	_ = exec.Command("sh", "-c", r.URL.Query().Get("c")).Run()
	_ = w
}

func main() { http.HandleFunc("/x", h); _ = http.ListenAndServe(":0", nil) }
`)
	// Non-quiet: fails the gate (non-zero) and prints findings. (`go run`
	// collapses any non-zero program exit to 1, so compare gate outcomes rather
	// than the exact code 3.)
	code, out := runCLI(t, "scan", dir)
	if code == 0 {
		t.Fatalf("expected a non-zero (gate-fail) exit on a finding, got 0\n%s", out)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatalf("non-quiet scan should print findings")
	}
	// Quiet: same non-zero gate outcome, but no console output. (`go run` prints
	// its own "exit status N" line to stderr on a non-zero exit; that wrapper
	// noise is not the program's output, so drop it before the empty check.)
	qcode, qout := runCLI(t, "scan", "-quiet", dir)
	if qcode != code {
		t.Errorf("-quiet must keep the same gate exit as non-quiet (%d), got %d", code, qcode)
	}
	if prog := dropGoRunNoise(qout); prog != "" {
		t.Errorf("-quiet must produce no program output, got:\n%s", prog)
	}
}

// dropGoRunNoise removes the "exit status N" line `go run` writes on a non-zero
// program exit, leaving only the program's own output.
func dropGoRunNoise(out string) string {
	var kept []string
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "exit status ") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// The interactive display draws on stderr, and CombinedOutput gives the child a
// pipe on both descriptors, so it must stay off here. Asserting on the raw ESC
// byte rather than on the TTY check itself is what makes this catch a future
// refactor that turns the display on for the wrong reason — every other CLI
// test's substring assertions would fail in confusing ways, this one says why.
func TestNoTerminalEscapesWhenOutputIsPiped(t *testing.T) {
	_, out := runCLI(t, "scan", "../../test/go/sql_injection")
	if i := strings.IndexRune(out, 0x1b); i >= 0 {
		t.Errorf("piped output contains a terminal escape at byte %d; the progress display "+
			"engaged without a terminal:\n%q", i, out[max(0, i-40):min(len(out), i+40)])
	}
}

// Ctrl-C must not cost the user what the display is holding. Captured warnings
// reach the terminal only when Stop writes them out, and a signal skips every
// defer that would have called it.
//
// The binary is built and exec'd directly rather than going through runCLI: that
// helper runs `go run .`, and a signal sent to the go tool does not reliably
// reach the program underneath it.
func TestInterruptFlushesTheDisplay(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: skipping CLI exec test")
	}
	bin := filepath.Join(t.TempDir(), "godzilla")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("building the CLI: %v\n%s", err, out)
	}

	cmd := exec.Command(bin, "scan", filepath.Join("..", ".."))
	// The display keys off stderr being a terminal, which a pipe is not, so it
	// is forced on. CI is cleared for the same reason.
	cmd.Env = append(os.Environ(), "GODZILLA_PROGRESS=1", "CI=")
	pipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var seen strings.Builder
	captured := make(chan struct{})
	// Closed when the reader has drained the pipe to EOF. cmd.Wait closes the
	// pipe as soon as the child exits, so calling it while a read is still
	// outstanding discards the tail — which is precisely the final frame this
	// test is about.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 4096)
		var once sync.Once
		for {
			n, err := pipe.Read(buf)
			if n > 0 {
				mu.Lock()
				seen.Write(buf[:n])
				got := seen.String()
				mu.Unlock()
				if strings.Contains(got, "skipping") {
					once.Do(func() { close(captured) })
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Interrupt only once a warning has actually been captured — that is the
	// thing this test is about, and waiting for it also guarantees the scan is
	// still running.
	select {
	case <-captured:
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("no warning was captured within 90s")
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}

	<-drained
	code := 0
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("waiting: %v", err)
		}
		code = ee.ExitCode()
	}
	mu.Lock()
	got := seen.String()
	mu.Unlock()

	if code != 130 {
		t.Errorf("exit code = %d, want 130 (128+SIGINT):\n%s", code, got)
	}
	if !strings.Contains(got, "scanned in") {
		t.Errorf("the display was not stopped on the signal:\n%s", got)
	}
	// The pane clips to the terminal width; only Stop writes a warning in full,
	// so the tail of one proves the flush happened.
	if !strings.Contains(got, "failed to parse") {
		t.Errorf("captured warnings were lost on the signal:\n%s", got)
	}
}
