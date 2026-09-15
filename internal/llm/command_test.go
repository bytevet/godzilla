package llm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/memlimit"
	"github.com/bytevet/godzilla/internal/testsupport"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// withFakeRunner substitutes runCmd for the duration of the test, restoring
// the real runSubprocess afterward — the injectable seam so no test here
// spawns a real CLI.
func withFakeRunner(t *testing.T, fn runner) {
	t.Helper()
	old := runCmd
	runCmd = fn
	t.Cleanup(func() { runCmd = old })
}

func alwaysOK(context.Context, []string, string, string) (string, error) { return "", nil }

func TestProvider_Invocation(t *testing.T) {
	cases := []struct {
		name          string
		p             Provider
		model, prompt string
		wantArgv      []string
		wantStdin     string
	}{
		{
			name:      "substitutes {prompt} in argv, stdin stays empty",
			p:         Provider{Command: []string{"x", "{prompt}"}},
			prompt:    "THE PROMPT",
			wantArgv:  []string{"x", "THE PROMPT"},
			wantStdin: "",
		},
		{
			name:      "absent {prompt} goes to stdin, argv unchanged",
			p:         Provider{Command: []string{"x", "y"}},
			prompt:    "THE PROMPT",
			wantArgv:  []string{"x", "y"},
			wantStdin: "THE PROMPT",
		},
		{
			name:     "model flag inserted before {prompt}, default flag name",
			p:        Provider{Command: []string{"x", "{prompt}"}},
			model:    "haiku",
			prompt:   "P",
			wantArgv: []string{"x", "--model", "haiku", "P"},
		},
		{
			name:     "custom ModelFlag honored",
			p:        Provider{Command: []string{"x", "{prompt}"}, ModelFlag: "--llm-model"},
			model:    "haiku",
			prompt:   "P",
			wantArgv: []string{"x", "--llm-model", "haiku", "P"},
		},
		{
			name:     "no model set: flag omitted entirely",
			p:        Provider{Command: []string{"x", "{prompt}"}},
			prompt:   "P",
			wantArgv: []string{"x", "P"},
		},
		{
			name:      "model flag appended at the end in stdin mode",
			p:         Provider{Command: []string{"x", "y"}},
			model:     "haiku",
			prompt:    "P",
			wantArgv:  []string{"x", "y", "--model", "haiku"},
			wantStdin: "P",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argv, stdin := tc.p.invocation(tc.model, tc.prompt)
			if !slices.Equal(argv, tc.wantArgv) {
				t.Errorf("argv = %v, want %v", argv, tc.wantArgv)
			}
			if stdin != tc.wantStdin {
				t.Errorf("stdin = %q, want %q", stdin, tc.wantStdin)
			}
		})
	}
}

// TestProvider_Invocation_DoesNotMutateCommand guards against a slices.Clone
// omission: p.Command is shared across every Review call for that provider, so
// invocation must never write through it.
func TestProvider_Invocation_DoesNotMutateCommand(t *testing.T) {
	p := Provider{Command: []string{"x", "{prompt}"}}
	original := slices.Clone(p.Command)
	p.invocation("", "PROMPT")
	if !slices.Equal(p.Command, original) {
		t.Errorf("Command mutated: got %v, want %v", p.Command, original)
	}
}

func TestCommandOnPath(t *testing.T) {
	if commandOnPath(Provider{Command: []string{missingBinary}}) {
		t.Error("expected false for a nonexistent binary")
	}
	if !commandOnPath(Provider{Command: []string{"go"}}) {
		t.Error("expected true for `go`, which must be on PATH to run `go test`")
	}
}

func TestProbeOK(t *testing.T) {
	t.Run("no probe configured is vacuously OK", func(t *testing.T) {
		if !probeOK(Provider{}, "") {
			t.Error("expected true")
		}
	})
	t.Run("exit 0 with no ProbeContains counts as authenticated", func(t *testing.T) {
		// codex's builtin entry has no ProbeContains: exit 0 alone is all the
		// signal there is, and that must count as a pass, not a punt.
		withFakeRunner(t, alwaysOK)
		if !probeOK(Provider{Probe: []string{"x"}}, "") {
			t.Error("expected true")
		}
	})
	t.Run("exit 0 with matching ProbeContains", func(t *testing.T) {
		withFakeRunner(t, func(context.Context, []string, string, string) (string, error) {
			return `{"loggedIn": true}`, nil
		})
		if !probeOK(Provider{Probe: []string{"x"}, ProbeContains: `"loggedIn": true`}, "") {
			t.Error("expected true")
		}
	})
	t.Run("exit 0 but missing ProbeContains fails", func(t *testing.T) {
		withFakeRunner(t, func(context.Context, []string, string, string) (string, error) {
			return `{"loggedIn": false}`, nil
		})
		if probeOK(Provider{Probe: []string{"x"}, ProbeContains: `"loggedIn": true`}, "") {
			t.Error("expected false")
		}
	})
	t.Run("nonzero exit fails", func(t *testing.T) {
		withFakeRunner(t, func(context.Context, []string, string, string) (string, error) {
			return "", errors.New("exit status 1")
		})
		if probeOK(Provider{Probe: []string{"x"}}, "") {
			t.Error("expected false")
		}
	})
}

func TestCommandReviewer_Review(t *testing.T) {
	var gotArgv []string
	var gotDir, gotStdin string
	withFakeRunner(t, func(_ context.Context, argv []string, dir, stdin string) (string, error) {
		gotArgv, gotDir, gotStdin = argv, dir, stdin
		return "Sure!\n" + `{"verdict": "false_positive", "reason": "constant", "confidence": 0.8}`, nil
	})
	cr := &commandReviewer{p: Provider{Name: "stub", Command: []string{"stub", "{prompt}"}}, dir: "/scan/root"}
	f := analysis.Finding{RuleID: "X", SinkPos: &ir.Position{Filename: "a.go", Line: 1}}

	v, err := cr.Review(context.Background(), f, "-- sink --\n> 1: exec(x)\n")
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if !v.FalsePositive || v.Reason != "constant" {
		t.Errorf("verdict not parsed from the CLI's prose-wrapped reply: %+v", v)
	}
	if gotDir != "/scan/root" {
		t.Errorf("dir = %q, want the scan root", gotDir)
	}
	if gotStdin != "" {
		t.Errorf("stdin = %q, want empty: the prompt substituted into argv", gotStdin)
	}
	if len(gotArgv) == 0 || !strings.Contains(gotArgv[len(gotArgv)-1], "Rule: X") {
		t.Errorf("prompt not substituted into argv: %v", gotArgv)
	}
}

func TestCommandReviewer_Review_WrapsRunnerErrorWithProviderName(t *testing.T) {
	withFakeRunner(t, func(context.Context, []string, string, string) (string, error) {
		return "", errors.New("boom")
	})
	cr := &commandReviewer{p: Provider{Name: "stub", Command: []string{"stub"}}}
	_, err := cr.Review(context.Background(), analysis.Finding{}, "ctx")
	if err == nil || !strings.Contains(err.Error(), "stub") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected an error naming the provider and the underlying failure, got %v", err)
	}
}

func TestCommandReviewer_ReviewConfig(t *testing.T) {
	got := (&commandReviewer{}).ReviewConfig()
	// Concurrency is sized from host memory (see commandConcurrency), so pinning
	// a literal here would assert the test machine's RAM rather than the
	// backend's tuning. commandConcurrency has its own table test for the sizing.
	if want := commandConcurrency(memlimit.Available()); got.Concurrency != want {
		t.Errorf("Concurrency = %d, want the memory-sized %d", got.Concurrency, want)
	}
	// The timeout IS fixed, and is the load-bearing half: DefaultReviewConfig's
	// 30s times most real CLI reviews out, and Filter fails open, so the feature
	// would silently do nothing.
	if got.Timeout != 180*time.Second {
		t.Errorf("Timeout = %v, want 180s", got.Timeout)
	}
}

// requireUnix skips on windows: the tests below use `cat` and a POSIX shell
// stub script to exercise the real subprocess path.
func requireUnix(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("posix-only test")
	}
}

// TestRunSubprocess_ClosesStdinWhenAbsent is the regression test for the
// hang bug: `cat` with no args blocks reading stdin until EOF. If runSubprocess
// left stdin open (or connected to something other than the null device) this
// test would hang until its own context deadline rather than returning
// immediately with no output — exactly the "Reading additional input from
// stdin..." symptom codex showed.
func TestRunSubprocess_ClosesStdinWhenAbsent(t *testing.T) {
	requireUnix(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := runSubprocess(ctx, []string{"cat"}, "", "")
	if err != nil {
		t.Fatalf("runSubprocess: %v", err)
	}
	if out != "" {
		t.Errorf("got %q, want no output from an immediately-EOF'd stdin", out)
	}
}

func TestRunSubprocess_WritesStdinWhenPresent(t *testing.T) {
	requireUnix(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := runSubprocess(ctx, []string{"cat"}, "", "hello\n")
	if err != nil {
		t.Fatalf("runSubprocess: %v", err)
	}
	if out != "hello\n" {
		t.Errorf("got %q, want the stdin echoed back", out)
	}
}

func TestRunSubprocess_ErrorIncludesStderr(t *testing.T) {
	requireUnix(t)
	_, err := runSubprocess(context.Background(), []string{"sh", "-c", "echo boom >&2; exit 1"}, "", "")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected stderr surfaced in the error, got %v", err)
	}
}

// writeStubAgentScript writes a tiny POSIX script standing in for a real agent
// CLI: it exits 0 for a --probe call, and otherwise wraps the JSON verdict in
// prose — proving parseVerdict's tolerance for a CLI's own chatter, which is
// why no provider needs a JSON-output flag.
func writeStubAgentScript(t *testing.T) string {
	t.Helper()
	requireUnix(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "stub-agent.sh")
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$a\" = \"--probe\" ]; then exit 0; fi\n" +
		"done\n" +
		"echo 'Sure, here is my verdict:'\n" +
		"echo '{\"verdict\": \"false_positive\", \"reason\": \"stub says so\", \"confidence\": 0.9}'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestBuiltinProviders_ProbeDoesNotHang runs the REAL claude/codex probe when
// the binary is installed (skipped otherwise, per testsupport.RequireTool), to
// guard the actual failure mode this package exists to avoid: a probe that
// blocks rather than returning quickly is the codex stdin hang all over again,
// and no fake runner can catch that — only the real binary can.
func TestBuiltinProviders_ProbeDoesNotHang(t *testing.T) {
	for _, p := range builtinProviders {
		t.Run(p.Name, func(t *testing.T) {
			testsupport.RequireTool(t, p.Command[0])
			done := make(chan struct{})
			go func() {
				probeOK(p, t.TempDir())
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(probeTimeout + 5*time.Second):
				t.Fatal("probe did not return within its timeout budget — looks like a hang, not a failure")
			}
		})
	}
}
