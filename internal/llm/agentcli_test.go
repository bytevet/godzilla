package llm

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bytevet/godzilla/internal/analysis"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// fakeCLI writes a shell script that stands in for an agent CLI. The reviewer's
// `bin` field is the seam: no test may touch PATH.
func fakeCLI(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-cli")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("writing fake CLI: %v", err)
	}
	return p
}

func cliFinding() analysis.Finding {
	return analysis.Finding{
		RuleID:  "GO-CMDI",
		Message: "command injection",
		SinkPos: &ir.Position{Filename: "a.go", Line: 2},
	}
}

// TestAgentCLIReviewer_Envelope covers the claude profile end to end: the reply
// is unwrapped from the JSON envelope, the fenced JSON inside needs no stripping,
// and the reported cost is banked.
func TestAgentCLIReviewer_Envelope(t *testing.T) {
	bin := fakeCLI(t, `cat <<'JSON'
{"result":"Here is my verdict:\n`+"```"+`json\n{\"verdict\":\"false_positive\",\"confidence\":0.9,\"exploitability\":\"none\",\"reason\":\"argument is a constant\"}\n`+"```"+`","total_cost_usd":0.025,"is_error":false,"num_turns":2}
JSON`)

	claude, _ := profileByName("claude")
	r := &AgentCLIReviewer{profile: claude, bin: bin, dir: t.TempDir()}
	v, err := r.Review(context.Background(), cliFinding(), "-- sink --\n> 2: exec(x)\n")
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if !v.FalsePositive {
		t.Errorf("verdict = %+v, want a false positive", v)
	}
	if v.Confidence != 0.9 || !strings.Contains(v.Reason, "constant") || v.Exploitability != "none" {
		t.Errorf("verdict fields not parsed: %+v", v)
	}
	if got := r.CostUSD(); got != 0.025 {
		t.Errorf("CostUSD() = %v, want 0.025", got)
	}
}

// TestAgentCLIReviewer_PlainText covers a profile with no envelope: stdout is
// the reply, and parseVerdict tolerates the surrounding prose.
func TestAgentCLIReviewer_PlainText(t *testing.T) {
	bin := fakeCLI(t, `echo 'Looking at the flow... {"verdict": "true_positive", "reason": "reaches exec unsanitized"}'`)

	agy, _ := profileByName("agy")
	r := &AgentCLIReviewer{profile: agy, bin: bin, dir: t.TempDir()}
	v, err := r.Review(context.Background(), cliFinding(), "-- sink --\n> 2: exec(x)\n")
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if v.FalsePositive || !strings.Contains(v.Reason, "unsanitized") {
		t.Errorf("verdict = %+v, want a kept finding with a reason", v)
	}
	if got := r.CostUSD(); got != 0 {
		t.Errorf("CostUSD() = %v, want 0 when the CLI reports none", got)
	}
}

// TestAgentCLIReviewer_UnknownEnvelopeFallsBack pins the degradation path: a CLI
// whose envelope does not carry the expected key still adjudicates, because
// parseVerdict scans the raw stdout for the outermost JSON object.
func TestAgentCLIReviewer_UnknownEnvelopeFallsBack(t *testing.T) {
	bin := fakeCLI(t, `echo '{"verdict":"false_positive","reason":"constant"}'`)

	p := cliProfile{name: "probe", printFlag: "-p", promptAsValue: true, envelopeKeys: []string{"result"}}
	r := &AgentCLIReviewer{profile: p, bin: bin, dir: t.TempDir()}
	v, err := r.Review(context.Background(), cliFinding(), "ctx")
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if !v.FalsePositive {
		t.Errorf("verdict = %+v, want the raw stdout to be parsed", v)
	}
}

// TestAgentCLIReviewer_NonZeroExit verifies a failed run is an error carrying the
// CLI's own stderr — never a verdict, since Filter would act on one.
func TestAgentCLIReviewer_NonZeroExit(t *testing.T) {
	bin := fakeCLI(t, "echo 'not logged in: run claude login' >&2\nexit 3")

	claude, _ := profileByName("claude")
	r := &AgentCLIReviewer{profile: claude, bin: bin, dir: t.TempDir()}
	_, err := r.Review(context.Background(), cliFinding(), "ctx")
	if err == nil {
		t.Fatal("expected an error on a non-zero exit")
	}
	if !strings.Contains(err.Error(), "not logged in") {
		t.Errorf("error must carry the CLI's stderr, got %v", err)
	}
}

// TestAgentCLIReviewer_IsError verifies the envelope's own failure flag is an
// error even though the process exited 0.
func TestAgentCLIReviewer_IsError(t *testing.T) {
	bin := fakeCLI(t, `echo '{"result":"Credit balance too low","is_error":true,"total_cost_usd":0}'`)

	claude, _ := profileByName("claude")
	r := &AgentCLIReviewer{profile: claude, bin: bin, dir: t.TempDir()}
	_, err := r.Review(context.Background(), cliFinding(), "ctx")
	if err == nil {
		t.Fatal("expected an error when the envelope reports one")
	}
	if !strings.Contains(err.Error(), "Credit balance") {
		t.Errorf("error must carry the envelope, got %v", err)
	}
}

// TestAgentCLIReviewer_ContextCanceled verifies the per-review deadline Filter
// sets kills the subprocess and surfaces as an error (fail open).
func TestAgentCLIReviewer_ContextCanceled(t *testing.T) {
	bin := fakeCLI(t, "sleep 30")

	claude, _ := profileByName("claude")
	r := &AgentCLIReviewer{profile: claude, bin: bin, dir: t.TempDir()}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := r.Review(ctx, cliFinding(), "ctx")
	if err == nil {
		t.Fatal("expected an error when the review deadline expires")
	}
	if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("error should name the deadline, got %v", err)
	}
}

// TestAgentCLIReviewer_Argv pins the safety-relevant command line: the tools
// claude is granted are read-only, the scan root is the working directory, and
// no blanket-approval flag is ever passed.
func TestAgentCLIReviewer_Argv(t *testing.T) {
	root := t.TempDir()
	dir := t.TempDir()
	out, pwd := filepath.Join(dir, "argv"), filepath.Join(dir, "pwd")
	bin := fakeCLI(t, `printf '%s\0' "$@" > `+out+`
pwd > `+pwd+`
echo '{"result":"{\"verdict\":\"true_positive\"}"}'`)

	claude, _ := profileByName("claude")
	r := &AgentCLIReviewer{profile: claude, bin: bin, dir: root, model: "opus"}
	if _, err := r.Review(context.Background(), cliFinding(), "ctx"); err != nil {
		t.Fatalf("Review: %v", err)
	}
	argv := readArgv(t, out)
	cwd := strings.TrimSpace(readFile(t, pwd))

	for _, want := range [][]string{{"-p"}, {"--output-format", "json"}, {"--allowedTools", "Read,Grep"}, {"--max-turns", "6"}, {"--model", "opus"}} {
		if !containsSeq(argv, want) {
			t.Errorf("argv %q missing %q", argv, want)
		}
	}
	for _, banned := range []string{"--dangerously-skip-permissions", "-f", "--force"} {
		if slices.Contains(argv, banned) {
			t.Errorf("argv must never grant blanket approval, got %q", banned)
		}
	}
	if i := slices.Index(argv, "-p"); i < 0 || !strings.Contains(argv[i+1], "Rule: GO-CMDI") {
		t.Errorf("the prompt must be -p's value, got argv %q", argv)
	}
	// A tool-using reviewer resolves relative paths against its cwd, so the scan
	// root must be it, not godzilla's own directory.
	if resolved, _ := filepath.EvalSymlinks(root); cwd != resolved && cwd != root {
		t.Errorf("cwd = %q, want the scan root %q", cwd, root)
	}

	// Unpinned, the flag is omitted entirely so the CLI keeps its own model.
	unpinned := &AgentCLIReviewer{profile: claude, bin: bin, dir: root}
	if _, err := unpinned.Review(context.Background(), cliFinding(), "ctx"); err != nil {
		t.Fatalf("Review: %v", err)
	}
	if slices.Contains(readArgv(t, out), "--model") {
		t.Error("no model pinned, so --model must not be passed")
	}
}

// TestAgentCLIReviewer_CustomCommand covers the GODZILLA_LLM_CLI_CMD escape
// hatch: the template's argv is preserved and {{prompt}} substituted in place.
func TestAgentCLIReviewer_CustomCommand(t *testing.T) {
	out := filepath.Join(t.TempDir(), "argv")
	bin := fakeCLI(t, `printf '%s\0' "$@" > `+out+`
echo '{"verdict":"false_positive","reason":"template ran"}'`)

	r := newCommandReviewer([]string{bin, "--quiet", "--ask", promptPlaceholder}, t.TempDir())
	v, err := r.Review(context.Background(), cliFinding(), "ctx")
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if !v.FalsePositive {
		t.Errorf("verdict = %+v, want stdout parsed as the reply", v)
	}
	argv := readArgv(t, out)
	if len(argv) != 3 || argv[0] != "--quiet" || argv[1] != "--ask" {
		t.Fatalf("template argv not preserved: %q", argv)
	}
	if !strings.Contains(argv[2], "Rule: GO-CMDI") {
		t.Errorf("{{prompt}} was not substituted: %q", argv[2])
	}
}

func TestSplitArgs(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`codex exec {{prompt}}`, []string{"codex", "exec", "{{prompt}}"}},
		{`  my-cli   --system "be terse"  {{prompt}} `, []string{"my-cli", "--system", "be terse", "{{prompt}}"}},
		{`cli --x 'a b' "c d"`, []string{"cli", "--x", "a b", "c d"}},
		{`cli ""`, []string{"cli", ""}},
		{``, nil},
	}
	for _, c := range cases {
		if got := splitArgs(c.in); !slices.Equal(got, c.want) {
			t.Errorf("splitArgs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

// readArgv reads back a NUL-separated argv dump. A prompt spans many lines, so
// newline-separated capture would split one argument into dozens.
func readArgv(t *testing.T, path string) []string {
	t.Helper()
	return strings.Split(strings.TrimSuffix(readFile(t, path), "\x00"), "\x00")
}

// containsSeq reports whether want appears as a contiguous run in argv.
func containsSeq(argv, want []string) bool {
	for i := 0; i+len(want) <= len(argv); i++ {
		if slices.Equal(argv[i:i+len(want)], want) {
			return true
		}
	}
	return false
}
