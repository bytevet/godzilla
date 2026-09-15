package llm

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/testsupport"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what it
// wrote — the same technique internal/scan/budget_test.go uses to assert a
// warning's exact text without threading a writer through just for tests.

// missingBinary names a binary that cannot exist on any test machine's PATH,
// used throughout to make commandOnPath deterministically fail without
// depending on what happens to be installed.
const missingBinary = "godzilla-test-definitely-not-a-real-binary-xyz"

// withBuiltinProviders substitutes the builtin command-provider table for the
// duration of the test. Any Select test that exercises the auto ladder (rung
// 3) without an explicit Options.Provider must use this: the REAL builtins are
// claude and codex, and on a machine that has them installed and logged in
// (this repo's own dev machines, typically) rung 3 would pick one of THEM
// before ever reaching a test's fake provider — an environment-dependent test
// result is exactly what this seam exists to prevent.
func withBuiltinProviders(t *testing.T, providers []Provider) {
	t.Helper()
	old := builtinProviders
	builtinProviders = providers
	t.Cleanup(func() { builtinProviders = old })
}

func TestOptionsFromEnv(t *testing.T) {
	t.Run("env overrides config-supplied base", func(t *testing.T) {
		t.Setenv("GODZILLA_LLM_PROVIDER", "cmd")
		t.Setenv("GODZILLA_LLM_MODEL", "env-model")
		t.Setenv("GODZILLA_LLM_CMD", "")
		got := OptionsFromEnv(Options{Provider: "anthropic", Model: "config-model"})
		if got.Provider != "cmd" || got.Model != "env-model" {
			t.Errorf("env should win, got %+v", got)
		}
	})
	t.Run("unset env leaves the config-supplied base alone", func(t *testing.T) {
		t.Setenv("GODZILLA_LLM_PROVIDER", "")
		t.Setenv("GODZILLA_LLM_MODEL", "")
		t.Setenv("GODZILLA_LLM_CMD", "")
		got := OptionsFromEnv(Options{Provider: "anthropic", Model: "config-model"})
		if got.Provider != "anthropic" || got.Model != "config-model" {
			t.Errorf("empty env must not clobber a config value, got %+v", got)
		}
	})
	t.Run("Providers is untouched unless GODZILLA_LLM_CMD is set", func(t *testing.T) {
		t.Setenv("GODZILLA_LLM_CMD", "")
		base := Options{Providers: []Provider{{Name: "x"}}}
		got := OptionsFromEnv(base)
		if len(got.Providers) != 1 || got.Providers[0].Name != "x" {
			t.Errorf("OptionsFromEnv must pass Providers through untouched, got %+v", got.Providers)
		}
	})
	t.Run("GODZILLA_LLM_CMD registers an ad hoc provider and selects it, overriding GODZILLA_LLM_PROVIDER", func(t *testing.T) {
		t.Setenv("GODZILLA_LLM_PROVIDER", "openai")
		t.Setenv("GODZILLA_LLM_CMD", "  /path/to/fakeprovider   review  {prompt}  ") // extra whitespace, deliberately
		got := OptionsFromEnv(Options{Providers: []Provider{{Name: "x"}}})
		if got.Provider != envCmdProviderName {
			t.Errorf("Provider = %q, want %q (must override GODZILLA_LLM_PROVIDER)", got.Provider, envCmdProviderName)
		}
		if len(got.Providers) != 2 {
			t.Fatalf("expected the ad hoc provider appended to the existing base.Providers, got %+v", got.Providers)
		}
		want := []string{"/path/to/fakeprovider", "review", "{prompt}"}
		if !slices.Equal(got.Providers[1].Command, want) {
			t.Errorf("Command = %v, want %v (whitespace-tokenized, no shell quoting)", got.Providers[1].Command, want)
		}
	})
	t.Run("GODZILLA_LLM_CMD does not mutate the caller's Providers slice", func(t *testing.T) {
		t.Setenv("GODZILLA_LLM_CMD", "fakeprovider {prompt}")
		base := Options{Providers: []Provider{{Name: "x"}}}
		OptionsFromEnv(base)
		if len(base.Providers) != 1 || base.Providers[0].Name != "x" {
			t.Errorf("base.Providers mutated: got %+v", base.Providers)
		}
	})
	t.Run("GODZILLA_LLM_CONCURRENCY and GODZILLA_LLM_MAX_REVIEWS override the config-supplied base", func(t *testing.T) {
		t.Setenv("GODZILLA_LLM_CONCURRENCY", "16")
		t.Setenv("GODZILLA_LLM_MAX_REVIEWS", "50")
		got := OptionsFromEnv(Options{Concurrency: 4, MaxReviews: 10})
		if got.Concurrency != 16 || got.MaxReviews != 50 {
			t.Errorf("env should win, got %+v", got)
		}
	})
	t.Run("unset GODZILLA_LLM_CONCURRENCY/MAX_REVIEWS leaves the config-supplied base alone", func(t *testing.T) {
		t.Setenv("GODZILLA_LLM_CONCURRENCY", "")
		t.Setenv("GODZILLA_LLM_MAX_REVIEWS", "")
		got := OptionsFromEnv(Options{Concurrency: 4, MaxReviews: 10})
		if got.Concurrency != 4 || got.MaxReviews != 10 {
			t.Errorf("empty env must not clobber a config value, got %+v", got)
		}
	})
	t.Run("a non-numeric GODZILLA_LLM_CONCURRENCY warns and keeps the base value", func(t *testing.T) {
		t.Setenv("GODZILLA_LLM_CONCURRENCY", "lots")
		var got Options
		stderr := testsupport.CaptureStderr(t, func() { got = OptionsFromEnv(Options{Concurrency: 4}) })
		if got.Concurrency != 4 {
			t.Errorf("an invalid env value must not override, got Concurrency=%d", got.Concurrency)
		}
		if !strings.Contains(stderr, "GODZILLA_LLM_CONCURRENCY") || !strings.Contains(stderr, `"lots"`) {
			t.Errorf("warning should name the var and the bad value, got %q", stderr)
		}
	})
	t.Run("a GODZILLA_LLM_MAX_REVIEWS below 1 warns and keeps the base value", func(t *testing.T) {
		t.Setenv("GODZILLA_LLM_MAX_REVIEWS", "0")
		var got Options
		stderr := testsupport.CaptureStderr(t, func() { got = OptionsFromEnv(Options{MaxReviews: 10}) })
		if got.MaxReviews != 10 {
			t.Errorf("a <1 env value must not override, got MaxReviews=%d", got.MaxReviews)
		}
		if !strings.Contains(stderr, "GODZILLA_LLM_MAX_REVIEWS") {
			t.Errorf("warning should name the var, got %q", stderr)
		}
	})
}

// TestSelect_NamedProviderBeatsAuto is rung 1's defining behavior: naming a
// provider verbatim skips the LookPath/probe gate rung 3 would otherwise apply
// — the binary here does not exist, and it is still selected.
func TestSelect_NamedProviderBeatsAuto(t *testing.T) {
	opts := Options{
		Provider:  "stub",
		Providers: []Provider{{Name: "stub", Command: []string{missingBinary, "{prompt}"}}},
	}
	sel := Select(opts, nil)
	if sel.Provider != "stub" {
		t.Fatalf("Provider = %q, want stub (tried: %v)", sel.Provider, sel.Tried)
	}
	if _, ok := sel.Reviewer.(*commandReviewer); !ok {
		t.Errorf("Reviewer = %T, want *commandReviewer", sel.Reviewer)
	}
}

// TestSelect_EnvCmdWinsOverAnInstalledAndAuthenticatedBuiltin reproduces, and
// pins the fix for, the exact regression a live run turned up: with
// GODZILLA_LLM_CMD set, an installed-and-authenticated builtin (here faked via
// withBuiltinProviders + a runner that always probes OK) must NOT be picked
// over the ad hoc command — rung 1 (verbatim) must win outright, not merely
// enter rung 3's search alongside claude/codex.
func TestSelect_EnvCmdWinsOverAnInstalledAndAuthenticatedBuiltin(t *testing.T) {
	withBuiltinProviders(t, []Provider{{Name: "claude", Command: []string{"go"}, Probe: []string{"go"}}})
	withFakeRunner(t, alwaysOK)
	t.Setenv("GODZILLA_LLM_CMD", "/path/to/fakeprovider {prompt}")
	opts := OptionsFromEnv(Options{})

	sel := Select(opts, nil)
	if sel.Provider != envCmdProviderName {
		t.Fatalf("Provider = %q, want %q — claude must not win just because it's installed and authenticated", sel.Provider, envCmdProviderName)
	}
	cr, ok := sel.Reviewer.(*commandReviewer)
	if !ok {
		t.Fatalf("Reviewer = %T, want *commandReviewer", sel.Reviewer)
	}
	if cr.p.Command[0] != "/path/to/fakeprovider" {
		t.Errorf("Command = %v, want the GODZILLA_LLM_CMD binary first", cr.p.Command)
	}
}

// TestSelect_UnknownNamedProviderDoesNotFallBack: an explicit but unrecognized
// Options.Provider is a config typo, not license to silently pick something
// else the user didn't ask for.
func TestSelect_UnknownNamedProviderDoesNotFallBack(t *testing.T) {
	sel := Select(Options{Provider: "gemini"}, nil)
	if sel.Reviewer != nil {
		t.Errorf("unknown provider name should select nothing, got %T", sel.Reviewer)
	}
	if len(sel.Tried) == 0 {
		t.Error("Tried should explain the unrecognized name")
	}
}

// TestSelect_ProviderNameIsCaseInsensitive matches findProvider/the special
// tokens the same way.
func TestSelect_ProviderNameIsCaseInsensitive(t *testing.T) {
	sel := Select(Options{Provider: "ANTHROPIC"}, nil)
	if sel.Provider != "anthropic" {
		t.Errorf("Provider = %q, want anthropic", sel.Provider)
	}
}

// TestSelect_HTTPCredentials verifies rung 2: Anthropic before OpenAI, and
// OpenAI only once Anthropic is confirmed absent.
func TestSelect_HTTPCredentials(t *testing.T) {
	t.Run("anthropic preferred when both look present", func(t *testing.T) {
		clearAnthropicEnv(t)
		clearOpenAIEnv(t)
		t.Setenv("ANTHROPIC_API_KEY", "sk-test")
		t.Setenv("OPENAI_API_KEY", "sk-test")
		sel := Select(Options{Model: "claude-opus-4"}, nil)
		if sel.Provider != "anthropic" {
			t.Errorf("Provider = %q, want anthropic", sel.Provider)
		}
		ar, ok := sel.Reviewer.(*AnthropicReviewer)
		if !ok {
			t.Fatalf("Reviewer = %T, want *AnthropicReviewer", sel.Reviewer)
		}
		// A config-file-supplied Options.Model must reach the backend even
		// though it never went through GODZILLA_LLM_MODEL, the env var
		// NewAnthropicReviewer reads on its own.
		if string(ar.model) != "claude-opus-4" {
			t.Errorf("model = %q, want claude-opus-4 (Options.Model must reach the HTTP backend)", ar.model)
		}
	})
	t.Run("openai used once anthropic is absent", func(t *testing.T) {
		clearAnthropicEnv(t)
		clearOpenAIEnv(t)
		t.Setenv("OPENAI_API_KEY", "sk-test")
		sel := Select(Options{Model: "gpt-4o"}, nil)
		if sel.Provider != "openai" {
			t.Errorf("Provider = %q, want openai", sel.Provider)
		}
		or, ok := sel.Reviewer.(*OpenAIReviewer)
		if !ok {
			t.Fatalf("Reviewer = %T, want *OpenAIReviewer", sel.Reviewer)
		}
		if or.model != "gpt-4o" {
			t.Errorf("model = %q, want gpt-4o", or.model)
		}
	})
}

// TestSelect_CmdSkipsStraightToCommandLadder: "cmd" is the escape hatch for
// preferring the CLI ladder even on a machine WITH working HTTP credentials.
func TestSelect_CmdSkipsStraightToCommandLadder(t *testing.T) {
	clearAnthropicEnv(t)
	clearOpenAIEnv(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-test") // would win rung 2 if reached
	withBuiltinProviders(t, nil)
	withFakeRunner(t, alwaysOK)
	opts := Options{
		Provider:  "cmd",
		Providers: []Provider{{Name: "stub", Command: []string{"go", "{prompt}"}, Probe: []string{"go", "probe"}}},
	}
	sel := Select(opts, nil)
	if sel.Provider != "stub" {
		t.Fatalf("Provider = %q, want stub — rung 2 must not have been consulted", sel.Provider)
	}
}

// TestSelect_FallsThroughToCommandLadder covers the whole ladder end to end:
// no HTTP credentials, so rung 3 runs, skips an uninstalled provider, and picks
// the next one once its probe passes.
func TestSelect_FallsThroughToCommandLadder(t *testing.T) {
	clearAnthropicEnv(t)
	clearOpenAIEnv(t)
	withBuiltinProviders(t, nil)
	withFakeRunner(t, alwaysOK)
	opts := Options{Providers: []Provider{
		{Name: "gone", Command: []string{missingBinary}},
		{Name: "here", Command: []string{"go", "{prompt}"}, Probe: []string{"go", "probe"}},
	}}
	sel := Select(opts, nil)
	if sel.Provider != "here" {
		t.Fatalf("Provider = %q, want here (tried: %v)", sel.Provider, sel.Tried)
	}
	foundGone := false
	for _, tr := range sel.Tried {
		if strings.Contains(tr, "gone") {
			foundGone = true
		}
	}
	if !foundGone {
		t.Errorf("Tried should record why the uninstalled provider was skipped, got %v", sel.Tried)
	}
}

// TestSelect_NothingAvailable is rung 4: every rung explained in Tried, nil
// Reviewer, no error (Select never errors).
func TestSelect_NothingAvailable(t *testing.T) {
	clearAnthropicEnv(t)
	clearOpenAIEnv(t)
	withBuiltinProviders(t, nil)
	opts := Options{Providers: []Provider{{Name: "gone", Command: []string{missingBinary}}}}
	sel := Select(opts, nil)
	if sel.Reviewer != nil {
		t.Errorf("expected no reviewer, got %T", sel.Reviewer)
	}
	if sel.Provider != "" {
		t.Errorf("Provider = %q, want empty", sel.Provider)
	}
	if len(sel.Tried) < 3 { // anthropic, openai, gone
		t.Errorf("Tried should cover every rung, got %v", sel.Tried)
	}
}

func TestSelectedConfig(t *testing.T) {
	if got := (Selected{}).Config(); got != DefaultReviewConfig() {
		t.Errorf("a nil Reviewer should get the default config, got %+v", got)
	}
	if got := (Selected{Reviewer: &AnthropicReviewer{}}).Config(); got != DefaultReviewConfig() {
		t.Errorf("an HTTP backend implementing no ReviewConfig() should get the default, got %+v", got)
	}
	cr := &commandReviewer{}
	if got := (Selected{Reviewer: cr}).Config(); got != commandReviewConfig() {
		t.Errorf("a command backend should get commandReviewConfig, got %+v", got)
	}
}

// TestSelectedConfig_ConcurrencyMaxReviewsOverride pins Config()'s override
// layering: set values replace the backend's own default, an unset (0) value
// leaves it exactly as today, and the override never touches the fields it
// didn't ask about (Timeout).
func TestSelectedConfig_ConcurrencyMaxReviewsOverride(t *testing.T) {
	cr := &commandReviewer{}
	got := (Selected{Reviewer: cr, Concurrency: 16, MaxReviews: 50}).Config()
	if got.Concurrency != 16 || got.MaxReviews != 50 {
		t.Errorf("override not applied over the command backend's default: %+v", got)
	}
	if got.Timeout != commandReviewConfig().Timeout {
		t.Errorf("Timeout must stay the backend's own default, got %+v", got)
	}
	if got := (Selected{Reviewer: cr}).Config(); got != commandReviewConfig() {
		t.Errorf("a zero (unset) override must reproduce the backend default exactly, got %+v", got)
	}
}

// TestSelect_ConcurrencyMaxReviewsOverride exercises the override end to end
// through Select, which is the "point of use" that validates a value from ANY
// source (.godzilla.yaml carries it unvalidated; a bad env value is already
// caught earlier in OptionsFromEnv, but a caller can also build Options by
// hand) rather than trusting it blindly into a worker pool.
func TestSelect_ConcurrencyMaxReviewsOverride(t *testing.T) {
	t.Run("a positive override reaches Config() regardless of which rung selects the backend", func(t *testing.T) {
		clearAnthropicEnv(t)
		clearOpenAIEnv(t)
		t.Setenv("ANTHROPIC_API_KEY", "sk-test")
		sel := Select(Options{Concurrency: 16, MaxReviews: 50}, nil)
		if got := sel.Config(); got.Concurrency != 16 || got.MaxReviews != 50 {
			t.Errorf("override did not reach Config(), got %+v", got)
		}
	})
	t.Run("zero (unset) leaves the backend's own default alone", func(t *testing.T) {
		clearAnthropicEnv(t)
		clearOpenAIEnv(t)
		t.Setenv("ANTHROPIC_API_KEY", "sk-test")
		sel := Select(Options{}, nil)
		if got := sel.Config(); got != DefaultReviewConfig() {
			t.Errorf("unset override must not change the default, got %+v", got)
		}
	})
	t.Run("a negative value is invalid, warned about, and treated as unset", func(t *testing.T) {
		clearAnthropicEnv(t)
		clearOpenAIEnv(t)
		t.Setenv("ANTHROPIC_API_KEY", "sk-test")
		var sel Selected
		stderr := testsupport.CaptureStderr(t, func() { sel = Select(Options{Concurrency: -3, MaxReviews: -1}, nil) })
		if sel.Concurrency != 0 || sel.MaxReviews != 0 {
			t.Errorf("a negative override should reset to 0 (unset), got %+v", sel)
		}
		if got := sel.Config(); got != DefaultReviewConfig() {
			t.Errorf("a negative override must fall back to the default, got %+v", got)
		}
		if !strings.Contains(stderr, "-3") || !strings.Contains(stderr, "-1") {
			t.Errorf("both invalid values should be reported, got %q", stderr)
		}
	})
}

func TestMergeProviders(t *testing.T) {
	t.Run("overrides a builtin by name, in place", func(t *testing.T) {
		out := mergeProviders([]Provider{{Name: "claude", ModelFlag: "--custom-model-flag"}})
		if len(out) != len(builtinProviders) {
			t.Fatalf("an override must not change the count, got %d want %d", len(out), len(builtinProviders))
		}
		if out[0].Name != "claude" || out[0].ModelFlag != "--custom-model-flag" {
			t.Errorf("claude not overridden in place: %+v", out[0])
		}
		if out[0].Command != nil {
			t.Errorf("override replaces the whole entry, not merges fields: got Command=%v", out[0].Command)
		}
	})
	t.Run("extends with a new name", func(t *testing.T) {
		out := mergeProviders([]Provider{{Name: "gemini", Command: []string{"gemini"}}})
		if len(out) != len(builtinProviders)+1 {
			t.Fatalf("expected one extra provider, got %d", len(out))
		}
		if out[len(out)-1].Name != "gemini" {
			t.Errorf("new provider not appended: %+v", out)
		}
	})
}

func TestFindProvider(t *testing.T) {
	providers := mergeProviders(nil)
	if _, ok := findProvider(providers, "CODEX"); !ok {
		t.Error("findProvider should match case-insensitively")
	}
	if _, ok := findProvider(providers, "nope"); ok {
		t.Error("findProvider should report false for an unknown name")
	}
}

// TestSelect_DataOnlyProviderDrivesRealReview is the extensibility proof: a
// provider that exists ONLY as data (Options.Providers, a stub script standing
// in for a real agent CLI) is discovered, selected, and produces a verdict —
// with no Go code naming it anywhere. This is what "adding a provider is a
// config entry" means, demonstrated rather than asserted.
func TestSelect_DataOnlyProviderDrivesRealReview(t *testing.T) {
	script := writeStubAgentScript(t)
	clearAnthropicEnv(t)
	clearOpenAIEnv(t)
	withBuiltinProviders(t, nil)
	opts := Options{Providers: []Provider{{
		Name:    "gemini",
		Command: []string{script, "{prompt}"},
		Probe:   []string{script, "--probe"},
	}}}

	sel := Select(opts, nil)
	if sel.Provider != "gemini" {
		t.Fatalf("Provider = %q, want gemini (tried: %v)", sel.Provider, sel.Tried)
	}

	f := analysis.Finding{RuleID: "GO-CMDI", SinkPos: &ir.Position{Filename: "a.go", Line: 1}}
	v, err := sel.Reviewer.Review(context.Background(), f, "-- sink --\n> 1: exec(x)\n")
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if !v.FalsePositive || v.Reason != "stub says so" {
		t.Errorf("verdict not read back from the data-only provider's CLI: %+v", v)
	}
}

// Building a FileToolBox indexes every lowered function in the program, and
// only the Anthropic rungs use one. The CLI ladder is now the common path, so a
// regression here would make that build pure waste on every scan that uses it —
// and would hold the index alive through the review phase.
func TestSelect_ToolBoxIsBuiltOnlyWhenAnthropicWins(t *testing.T) {
	// "go" is on PATH wherever these tests run, and `go probe` exits non-zero —
	// but rung 1 names the provider explicitly, so no probe is consulted.
	stub := Provider{Name: "stub", Command: []string{"go", "{prompt}"}, Probe: []string{"go", "probe"}}

	for _, c := range []struct {
		name  string
		opts  Options
		build bool
	}{
		{"cli backend does not need one", Options{Providers: []Provider{stub}, Provider: stub.Name}, false},
		{"no backend at all does not need one", Options{Provider: "definitely-not-a-provider"}, false},
		{"anthropic does", Options{Provider: "anthropic"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			built := false
			Select(c.opts, func() ToolBox { built = true; return nil })
			if built != c.build {
				t.Errorf("toolbox built = %v, want %v", built, c.build)
			}
		})
	}
}
