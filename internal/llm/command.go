package llm

// command.go is the one generic backend that drives ANY already-authenticated
// agent CLI (claude, codex, or a user's own script) as a Reviewer, for a
// machine that has no API key but does have a logged-in CLI. Reviewer is a
// one-method interface, so one type (commandReviewer) plus a data table
// (providers.go) covers every vendor — there is no per-CLI Go type.
//
// SECURITY: the agentic Anthropic-SDK path (anthropic.go) confines every file
// read to the scan root (tools.go's FileToolBox.confine) and caps a single
// tool result at maxToolOutput. Delegating review to an external CLI gives up
// BOTH guarantees: the CLI reads and writes with its own tool access, at its
// own output limits, and the process's own sandbox flag (builtinProviders'
// --allowedTools / --sandbox read-only) is the only boundary this package can
// still offer. A user who overrides Command controls their own risk from there.

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/memlimit"
)

// Provider describes how to drive an external CLI. Every field is DATA: adding
// a provider is a config entry, never a code change.
type Provider struct {
	Name    string   // shown to the user; also the selector in Options.Provider
	Command []string // argv; "{prompt}" anywhere is replaced by the prompt

	// Stdin sends the prompt on stdin instead of in argv. Required for a CLI
	// whose flags are variadic, where a trailing prompt argument is swallowed as
	// another flag value (the builtin claude entry is exactly that). Stating it
	// beats inferring it from a missing "{prompt}": a user writing a provider in
	// .godzilla.yaml gets no compiler or test to catch the omission, and an
	// absent token reads as forgotten rather than as chosen.
	Stdin bool

	Probe         []string // cheap auth check; exit 0 == authenticated
	ProbeContains string   // optional: also require this substring in probe output
	ModelFlag     string   // default "--model"; appended only when a model is set
}

// runner runs one subprocess and returns its stdout (or an error carrying
// stderr). It is the seam that keeps every test in this package from spawning
// a real CLI: runCmd is a package var so a test can substitute a fake one.
type runner func(ctx context.Context, argv []string, dir, stdin string) (string, error)

// runCmd is the runner commandReviewer and the provider probe use. Tests
// reassign it (and restore it via t.Cleanup); production code never does.
var runCmd runner = runSubprocess

// runSubprocess is the real runner: run argv[0] with the rest as arguments,
// under dir, feeding stdin (if non-empty) and returning stdout. Matches
// internal/proc.RunBatchScript's error style — attribute stderr into the error
// rather than discard it, since a CLI's failure reason usually lands there.
func runSubprocess(ctx context.Context, argv []string, dir, stdin string) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("empty command")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	// stdin == "": leave cmd.Stdin nil. exec.Cmd connects a nil Stdin to the
	// null device, i.e. already-closed/EOF — load-bearing for codex, whose
	// `exec` subcommand checks whether stdin has data pending and, if so,
	// prints "Reading additional input from stdin..." and blocks for it. That
	// is a hang, not an error, so this is not optional cleanup.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%v (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// invocation substitutes prompt into p.Command wherever "{prompt}" appears and
// inserts the model flag immediately before it (only when model is non-empty —
// an absent flag is how the CLI falls back to ITS OWN configured default,
// which this package must not second-guess by reading a provider's own config
// file). When Command has no "{prompt}" placeholder, prompt is returned as
// stdin instead and the model flag is appended at the end.
//
// A command WITH "{prompt}" in argv gets an empty stdin: see runSubprocess for
// why that must stay empty rather than merely unused.
func (p Provider) invocation(model, prompt string) (argv []string, stdin string) {
	argv = slices.Clone(p.Command)
	var modelArgs []string
	if model != "" {
		modelArgs = []string{cmp.Or(p.ModelFlag, "--model"), model}
	}
	idx := slices.Index(argv, "{prompt}")
	// Stdin is authoritative; a missing placeholder still falls back to stdin so
	// a provider written without either remains usable rather than silently
	// invoking the CLI with no prompt at all.
	if p.Stdin || idx < 0 {
		if idx >= 0 {
			argv = slices.Delete(argv, idx, idx+1)
		}
		return append(argv, modelArgs...), prompt
	}
	argv[idx] = prompt
	argv = slices.Insert(argv, idx, modelArgs...)
	return argv, ""
}

// commandOnPath reports whether p's binary can be found: exec.LookPath, which
// also accepts (and does not PATH-search) an absolute or relative path
// containing a slash — how a user's own local script can be a Provider without
// installing it anywhere.
func commandOnPath(p Provider) bool {
	_, err := exec.LookPath(p.Command[0])
	return err == nil
}

// probeTimeout bounds the cheap auth-status probe run against every configured
// provider on the auto ladder — it must stay well under a human's patience
// since it can run once per scan, unlike the review calls it gates.
const probeTimeout = 15 * time.Second

// probeOK reports whether p looks authenticated: no Probe configured is
// vacuously OK (the caller already confirmed the binary is on PATH), otherwise
// Probe must exit 0 and, if set, ProbeContains must appear in its output.
func probeOK(p Provider, root string) bool {
	if len(p.Probe) == 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	out, err := runCmd(ctx, p.Probe, root, "")
	if err != nil {
		return false
	}
	return p.ProbeContains == "" || strings.Contains(out, p.ProbeContains)
}

// commandReviewConfig is what a subprocess-driven review needs. Measured on
// the reference machine: `claude -p` took 5.3s and `codex exec` 10.2s for a
// TRIVIAL prompt with no code context — the floor, not the ceiling, for a real
// review. DefaultReviewConfig's 30s timeout would time most of these out, and
// because Filter fails open on a timeout that reads as "N reviewed, 0
// suppressed, N errors" — indistinguishable from a broken credential, the
// feature silently doing nothing.
func commandReviewConfig() ReviewConfig {
	return ReviewConfig{Concurrency: commandConcurrency(memlimit.Available()), Timeout: 180 * time.Second}
}

// commandBytesPerReview is what one in-flight CLI review costs in RSS. An agent
// CLI is a Node runtime plus its children, not an HTTP request: measured at
// ~1 GiB per invocation across an 8-wide run (7.8 GiB peak for 8 concurrent
// `claude -p` reviews).
const commandBytesPerReview = 1 << 30

// commandConcurrency sizes the worker pool against MEMORY, because memory is
// what actually bounds it. Measured on one 17-finding scan: 4-wide took 3m15s,
// 8-wide 1m33s, and 16-wide was SLOWER again (2m53s) because 16 x ~1 GiB
// exceeded the 24 GiB host and it swapped. A fixed default cannot be right for
// both a laptop and a 2-core CI container, and guessing high is worse than
// guessing low — thrashing costs more than the concurrency buys.
//
// avail is memlimit.Available(), which is already the smaller of host RAM and
// any cgroup limit, so a container gets sized to its limit rather than to the
// host it happens to run on. It returns 0 when memory cannot be detected; that
// falls back to the conservative fixed value rather than assuming headroom.
func commandConcurrency(avail int64) int {
	const (
		fallback = 4
		minConc  = 2
		maxConc  = 8 // past this the vendor's own rate limit dominates anyway
		budget   = 0.35
	)
	if avail <= 0 {
		return fallback
	}
	return min(max(int(float64(avail)*budget)/commandBytesPerReview, minConc), maxConc)
}

// commandReviewer is the one Reviewer implementation for every Provider.
type commandReviewer struct {
	p     Provider
	dir   string
	model string
}

// ReviewConfig is the optional interface Selected.Config type-asserts for
// (see reviewer.go) so the one-method Reviewer interface stays one method.
func (c *commandReviewer) ReviewConfig() ReviewConfig { return commandReviewConfig() }

// Review adjudicates one finding by running the provider's CLI once. It reuses
// the agentic prompt (buildAgenticPrompt) — the same one the Anthropic tool-use
// loop opens with — since a CLI agent has its own file/grep tools and needs the
// same "investigate before deciding" framing, and parseVerdict, which scans for
// the outermost {...} object, so a CLI's prose wrapper around the JSON is
// harmless and no provider needs a JSON-output flag.
func (c *commandReviewer) Review(ctx context.Context, f analysis.Finding, codeContext string) (Verdict, error) {
	argv, stdin := c.p.invocation(c.model, buildAgenticPrompt(f, codeContext))
	out, err := runCmd(ctx, argv, c.dir, stdin)
	if err != nil {
		return Verdict{}, fmt.Errorf("%s: %w", c.p.Name, err)
	}
	return parseVerdict(out)
}
