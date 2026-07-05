package py_converter

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestParseTimeoutKillsSubprocess is the PERF-4 guard: with a 1ms parse timeout,
// the python3 subprocess is killed before it can finish, so ConvertFile returns
// an error instead of hanging. Proves the subprocess actually runs under the
// context deadline. Skips without python3.
func TestParseTimeoutKillsSubprocess(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "app.py")
	if err := os.WriteFile(src, []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 1ms is shorter than python3 process startup, so the deadline always fires.
	t.Setenv("GODZILLA_PARSE_TIMEOUT", "1ms")

	if _, err := NewConverter().ConvertFile(src); err == nil {
		t.Fatal("expected ConvertFile to fail under a 1ms parse timeout (subprocess should be killed)")
	}
}
