package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bytevet/godzilla/internal/analysis"
)

// AgentCLIReviewer is a Reviewer backed by a coding-agent CLI already installed
// and logged in on the machine (LLM-10): it turns an existing Claude Code or
// Antigravity subscription into the review credential, so the FP-backstop works
// with no ANTHROPIC_API_KEY. One process per finding, the verdict read back off
// stdout.
type AgentCLIReviewer struct {
	profile cliProfile
	bin     string // command to exec; the profile name unless a test or template overrides it
	dir     string // scan root: the tree the reviewer may read
	model   string

	mu   sync.Mutex
	cost float64
}

// cliProfile is how one agent CLI is driven non-interactively.
type cliProfile struct {
	name          string
	printFlag     string
	promptAsValue bool     // prompt is printFlag's value, not a trailing positional
	extra         []string // structured output and tool grants
	dirFlag       string
	modelFlag     string
	envelopeKeys  []string // reply keys to try in a structured-output envelope; none => stdout is the reply
	agentic       bool
	template      []string // set only for GODZILLA_LLM_CLI_CMD: a full argv with {{prompt}} placeholders
}

// cliProfiles is the supported set, most preferred first — the order the picker
// offers them in.
//
// A CLI earns a profile only if it can be held READ-ONLY, because a reviewer
// that can write is a reviewer that can edit the repository it is auditing.
// claude can (--allowedTools Read,Grep), so it alone runs agentic; agy cannot
// grant tools selectively, so it runs toolless and must never be handed
// --dangerously-skip-permissions. cursor-agent is deliberately absent: its print
// mode documents write and bash access with no flag that withholds them.
// GODZILLA_LLM_CLI_CMD is where a user accepts a risk like that explicitly.
var cliProfiles = []cliProfile{
	{
		name:          "claude",
		printFlag:     "-p",
		promptAsValue: true,
		extra:         []string{"--output-format", "json", "--allowedTools", "Read,Grep", "--max-turns", "6"},
		modelFlag:     "--model",
		envelopeKeys:  []string{"result"},
		agentic:       true,
	},
	{
		name:          "agy",
		printFlag:     "-p",
		promptAsValue: true,
		dirFlag:       "--add-dir",
	},
}

func profileByName(name string) (cliProfile, bool) {
	for _, p := range cliProfiles {
		if p.name == name {
			return p, true
		}
	}
	return cliProfile{}, false
}

func profileNames() []string {
	out := make([]string, 0, len(cliProfiles))
	for _, p := range cliProfiles {
		out = append(out, p.name)
	}
	return out
}

// argv renders the command line after the binary.
func (p cliProfile) argv(prompt, dir, model string) []string {
	if p.template != nil {
		out := make([]string, 0, len(p.template)-1)
		for _, tok := range p.template[1:] {
			out = append(out, strings.ReplaceAll(tok, promptPlaceholder, prompt))
		}
		return out
	}
	var a []string
	a = append(a, p.printFlag)
	if p.promptAsValue {
		a = append(a, prompt)
	}
	a = append(a, p.extra...)
	if p.dirFlag != "" && dir != "" {
		a = append(a, p.dirFlag, dir)
	}
	if p.modelFlag != "" && model != "" {
		a = append(a, p.modelFlag, model)
	}
	if !p.promptAsValue {
		a = append(a, prompt)
	}
	return a
}

// newAgentCLIReviewer leaves the model unset unless GODZILLA_LLM_MODEL pins one,
// so the CLI answers on whatever model its own session is configured for.
func newAgentCLIReviewer(p cliProfile, scanRoot string) *AgentCLIReviewer {
	return &AgentCLIReviewer{
		profile: p,
		bin:     p.name,
		dir:     scanRoot,
		model:   os.Getenv("GODZILLA_LLM_MODEL"),
	}
}

// newCommandReviewer builds the escape-hatch reviewer for a CLI with no profile:
// argv is the template with {{prompt}} substituted, and stdout is the reply.
func newCommandReviewer(template []string, scanRoot string) *AgentCLIReviewer {
	return &AgentCLIReviewer{
		profile: cliProfile{name: template[0], template: template},
		bin:     template[0],
		dir:     scanRoot,
	}
}

// Review adjudicates one finding by running the CLI once. Any failure returns an
// error rather than a verdict, which Filter treats as fail-open (finding kept).
func (a *AgentCLIReviewer) Review(ctx context.Context, f analysis.Finding, codeContext string) (Verdict, error) {
	prompt := buildPrompt(f, codeContext)
	if a.profile.agentic {
		prompt = buildAgenticPrompt(f, codeContext)
	}

	// This is the one place the repo's two timeout regimes meet: the deadline is
	// the per-review one FilterWithConfig put on ctx, NOT internal/proc's
	// process-global toolchain budget, which exists for frontend parses.
	cmd := exec.CommandContext(ctx, a.bin, a.profile.argv(prompt, a.dir, a.model)...)
	cmd.Dir = a.dir
	// Killing the CLI on deadline does not reap the tools it spawned, and Wait
	// blocks while any of them still holds the output pipe — without this the
	// per-review timeout would not bound the review.
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return Verdict{}, fmt.Errorf("%s: %w", a.profile.name, cerr)
		}
		return Verdict{}, fmt.Errorf("%s: %w: %s", a.profile.name, err, bytes.TrimSpace(tail(stderr.Bytes(), 2000)))
	}

	reply, err := a.unwrap(stdout.Bytes())
	if err != nil {
		return Verdict{}, err
	}
	return parseVerdict(reply)
}

// CostUSD is what the CLI has reported spending so far, 0 when it reports none.
func (a *AgentCLIReviewer) CostUSD() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cost
}

// unwrap pulls the reply out of a structured-output envelope and banks the cost
// the run reported. An envelope that does not match the profile degrades to the
// raw stdout: parseVerdict scans for the outermost JSON object, so a CLI that
// changed its shape still adjudicates instead of failing every finding.
func (a *AgentCLIReviewer) unwrap(out []byte) (string, error) {
	if len(a.profile.envelopeKeys) == 0 {
		return string(out), nil
	}
	var env map[string]json.RawMessage
	if json.Unmarshal(out, &env) != nil {
		return string(out), nil
	}
	var cost float64
	if json.Unmarshal(env["total_cost_usd"], &cost) == nil && cost > 0 {
		a.mu.Lock()
		a.cost += cost
		a.mu.Unlock()
	}
	var failed bool
	if json.Unmarshal(env["is_error"], &failed) == nil && failed {
		return "", fmt.Errorf("%s reported an error: %s", a.profile.name, bytes.TrimSpace(tail(out, 2000)))
	}
	for _, k := range a.profile.envelopeKeys {
		var s string
		if json.Unmarshal(env[k], &s) == nil && s != "" {
			return s, nil
		}
	}
	return string(out), nil
}

const promptPlaceholder = "{{prompt}}"

// splitArgs splits a command template into an argv the way a shell would quote
// it, but WITHOUT a shell. The prompt carries lines of the scanned source, so
// handing the substituted string to `sh -c` would make a backtick in any audited
// file a command; substituting into argv elements cannot escape.
func splitArgs(s string) []string {
	var args []string
	var cur strings.Builder
	var quote rune
	started := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, started = r, true
		case unicode.IsSpace(r):
			if started {
				args = append(args, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if started {
		args = append(args, cur.String())
	}
	return args
}

// tail returns the last n bytes of b, for truncating CLI output in an error.
func tail(b []byte, n int) []byte {
	return b[max(0, len(b)-n):]
}
