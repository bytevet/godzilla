package llm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/bytevet/godzilla/internal/analysis"
)

// ChoiceKind is which backend adjudicates findings.
type ChoiceKind int

const (
	Anthropic ChoiceKind = iota
	OpenAI
	CLI
)

// Choice is a resolved backend, settled BEFORE the scan runs so a missing
// credential fails in the first second rather than after the analysis.
type Choice struct {
	Kind    ChoiceKind
	Profile string // Kind == CLI: a cliProfiles name, or customProfile
}

// customProfile marks the GODZILLA_LLM_CLI_CMD escape hatch. It is not a
// cliProfiles name, so it can never collide with a real one.
const customProfile = "custom"

// isTTY and lookPath are variables so Resolve's composition is testable without
// a terminal or the binaries installed (the trick in internal/tui/tty.go).
var (
	isTTY    = func(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
	lookPath = exec.LookPath
)

// pick is the interactive selection, swapped out in tests; readChoice is the
// logic it wraps.
var pick = func(names []string) (string, error) { return readChoice(os.Stdin, os.Stderr, names) }

// Resolve settles which reviewer backend to use, first match wins:
//
//  1. GODZILLA_LLM_PROVIDER=openai
//  2. GODZILLA_LLM_CLI_CMD  — a {{prompt}} command template
//  3. GODZILLA_LLM_CLI      — a named agent-CLI profile
//  4. ANTHROPIC_API_KEY
//  5. an interactive pick among the agent CLIs on PATH
//
// There is deliberately no auto-detection: silently driving a CLI spends a
// subscription quota the user never approved, so a non-interactive run with
// nothing pinned is an error that names every way out.
func Resolve(quiet bool) (Choice, error) {
	if strings.EqualFold(os.Getenv("GODZILLA_LLM_PROVIDER"), "openai") {
		return Choice{Kind: OpenAI}, nil
	}

	if tmpl := strings.TrimSpace(os.Getenv("GODZILLA_LLM_CLI_CMD")); tmpl != "" {
		argv := splitArgs(tmpl)
		if len(argv) == 0 {
			return Choice{}, fmt.Errorf("GODZILLA_LLM_CLI_CMD is empty")
		}
		if !strings.Contains(tmpl, promptPlaceholder) {
			return Choice{}, fmt.Errorf("GODZILLA_LLM_CLI_CMD must contain %s, the placeholder the finding's prompt is substituted for", promptPlaceholder)
		}
		return Choice{Kind: CLI, Profile: customProfile}, nil
	}

	if name := os.Getenv("GODZILLA_LLM_CLI"); name != "" {
		if _, ok := profileByName(name); !ok {
			return Choice{}, fmt.Errorf("GODZILLA_LLM_CLI=%q is not a known agent CLI; use one of %s, or GODZILLA_LLM_CLI_CMD for anything else%s",
				name, strings.Join(profileNames(), ", "), onPATH())
		}
		if _, err := lookPath(name); err != nil {
			return Choice{}, fmt.Errorf("GODZILLA_LLM_CLI=%q but %s is not on PATH%s", name, name, onPATH())
		}
		return Choice{Kind: CLI, Profile: name}, nil
	}

	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return Choice{Kind: Anthropic}, nil
	}

	found := installedProfiles()
	if len(found) == 0 || !interactive(quiet) {
		return Choice{}, fmt.Errorf("--llm-review needs a reviewer backend: set ANTHROPIC_API_KEY, or set GODZILLA_LLM_CLI to a logged-in agent CLI (%s), or set GODZILLA_LLM_CLI_CMD to a {{prompt}} command template%s",
			strings.Join(profileNames(), ", "), onPATH())
	}
	name, err := pick(found)
	if err != nil {
		return Choice{}, err
	}
	return Choice{Kind: CLI, Profile: name}, nil
}

// New builds the reviewer this choice names. scanRoot bounds what a CLI reviewer
// may read; tb is the in-process tool set, which only the Anthropic backend uses
// (an agent CLI brings its own tools).
func (c Choice) New(scanRoot string, tb ToolBox) Reviewer {
	switch {
	case c.Kind == OpenAI:
		return NewOpenAIReviewer()
	case c.Kind != CLI:
	case c.Profile == customProfile:
		if argv := splitArgs(os.Getenv("GODZILLA_LLM_CLI_CMD")); len(argv) > 0 {
			return newCommandReviewer(argv, scanRoot)
		}
	default:
		if p, ok := profileByName(c.Profile); ok {
			return newAgentCLIReviewer(p, scanRoot)
		}
	}
	// A CLI choice Resolve validated has returned by here; the environment it
	// named is gone, so fall back rather than panic on it.
	return NewAnthropicReviewer().WithTools(tb)
}

// ProviderName labels a choice for the scan's own output.
func ProviderName(c Choice) string {
	switch c.Kind {
	case OpenAI:
		return "OpenAI-compatible API"
	case CLI:
		if c.Profile == customProfile {
			return "custom CLI"
		}
		return c.Profile + " CLI"
	default:
		return "Anthropic API"
	}
}

// CountReviewable is how many findings a review pass would actually send to the
// reviewer — what a cost or confirmation prompt has to quote.
func CountReviewable(fs []analysis.Finding, reviewUpTo analysis.Confidence) int {
	n := 0
	for i := range fs {
		if shouldReview(fs[i].Confidence, reviewUpTo) {
			n++
		}
	}
	return n
}

// installedProfiles are the known agent CLIs present on PATH, most preferred first.
func installedProfiles() []string {
	var found []string
	for _, p := range cliProfiles {
		if _, err := lookPath(p.name); err == nil {
			found = append(found, p.name)
		}
	}
	return found
}

// onPATH is the trailing hint naming which CLIs are actually installed, so an
// error says what the user can pick rather than only what they cannot.
func onPATH() string {
	found := installedProfiles()
	if len(found) == 0 {
		return " (none of them are on PATH)"
	}
	return " (on PATH: " + strings.Join(found, ", ") + ")"
}

// interactive reports whether there is a human to answer the picker. It mirrors
// tui.Enabled's composition, asked of both streams: the menu is drawn on stderr
// and the answer is read from stdin, so either being redirected means no picker.
func interactive(quiet bool) bool {
	return !quiet && os.Getenv("CI") == "" && isTTY(os.Stdin) && isTTY(os.Stderr)
}

// readChoice prints a numbered menu and reads one line back. It draws on stderr
// so stdout stays byte for byte the findings, and it is plain line input — no
// raw mode, no arrow keys — so a terminal it cannot fully drive still works.
func readChoice(in io.Reader, out io.Writer, names []string) (string, error) {
	fmt.Fprintln(out, "No ANTHROPIC_API_KEY set. Review findings with a logged-in agent CLI:")
	for i, n := range names {
		fmt.Fprintf(out, "  %d) %s\n", i+1, n)
	}
	fmt.Fprintf(out, "Choice [1-%d]: ", len(names))
	line, err := bufio.NewReader(in).ReadString('\n')
	if line == "" && err != nil {
		return "", fmt.Errorf("reading the reviewer choice: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(names) {
		return "", fmt.Errorf("%q is not one of 1-%d", strings.TrimSpace(line), len(names))
	}
	return names[n-1], nil
}
