package llm

import (
	"slices"
	"testing"
)

// TestBuiltinProviders_ArgvPinned pins every builtin's exact argv shape. This
// is the regression guard for the claude incident: --allowedTools is VARIADIC
// (`--allowedTools <tools...>`), so a Command ending "--allowedTools
// Read,Grep,Glob {prompt}" silently fed the substituted prompt to claude as
// one more tool name — claude answered `Ignoring --allowedTools rule "<the
// prompt>"` and exited 1, failing every review, and nothing caught it because
// invocation()/parseVerdict/runSubprocess all behaved exactly as designed on
// a syntactically well-formed argv. Nothing in this package can know which of
// an arbitrary CLI's flags are variadic — Command is opaque argv by design
// (see Provider's doc comment) — so the practical guard is this: any change to
// a builtin's argv is a deliberate, reviewed edit to the table below, not an
// incidental diff that slips through Provider_Invocation's generic tests.
func TestBuiltinProviders_ArgvPinned(t *testing.T) {
	want := map[string][]string{
		"claude": {"claude", "-p", "--allowedTools", "Read,Grep,Glob"},
		"codex":  {"codex", "exec", "--sandbox", "read-only", "--skip-git-repo-check", "{prompt}"},
	}
	if len(want) != len(builtinProviders) {
		t.Fatalf("builtinProviders has %d entries, this test pins %d — keep them in sync", len(builtinProviders), len(want))
	}
	for _, p := range builtinProviders {
		w, ok := want[p.Name]
		if !ok {
			t.Fatalf("builtin provider %q has no pinned expectation in this test — add one", p.Name)
		}
		if !slices.Equal(p.Command, w) {
			t.Errorf("%s: Command = %v, want %v", p.Name, p.Command, w)
		}
	}
}

// TestBuiltinProviders_ClaudeNeverPlacesPromptInArgv is the narrowest possible
// pin for the actual incident: claude's Command must never contain "{prompt}"
// at all, because --allowedTools is variadic and there is no flag position
// that would be safe to put it after. The prompt belongs on stdin for this
// provider, unconditionally.
func TestBuiltinProviders_PromptDeliveryIsExplicit(t *testing.T) {
	for _, p := range builtinProviders {
		hasToken := slices.Contains(p.Command, "{prompt}")
		if !p.Stdin && !hasToken {
			t.Errorf("provider %q delivers the prompt neither in argv nor on stdin; "+
				"set Stdin or add a {prompt} token", p.Name)
		}
		if p.Stdin && hasToken {
			t.Errorf("provider %q sets Stdin AND carries a {prompt} token; pick one", p.Name)
		}
	}
}
