package llm

// reviewer.go is where "which backend runs this scan's review pass" gets
// decided — the ladder used to be scattered (an unconditional Anthropic client
// in NewReviewer, a provider check in openai.go); it is now one function so
// the four rungs are visible together and a fifth is one case, not a hunt.

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Options configures backend selection. Every field is optional; the zero
// value means "figure it out" (Select's rungs 2-4).
type Options struct {
	Provider  string     // "", "auto", "anthropic", "openai", "cmd", or a Provider.Name
	Model     string     // empty = inherit the backend's own default
	Providers []Provider // extends/overrides the builtins, matched by Name
	Root      string     // scan root; cwd for command providers

	// Concurrency overrides the selected backend's worker-pool width (default
	// 8 HTTP, memory-sized for CLI — DefaultReviewConfig / commandReviewConfig). 0 is "not
	// set": the backend's own default stands. This is an override knob, not a
	// new default, so raising it never changes what a caller gets by default.
	Concurrency int
	// MaxReviews overrides the selected backend's per-scan review cap (default
	// 200 HTTP / unlimited CLI). 0 is "not set", same as Concurrency.
	MaxReviews int
}

// envCmdProviderName is the synthetic Provider.Name a GODZILLA_LLM_CMD command
// is registered under. It is deliberately not "cmd" — that string is already
// Select's rung-3-escape-hatch token (search the table), and GODZILLA_LLM_CMD
// needs the opposite: rung-1 VERBATIM selection, so it wins even over an
// installed-and-authenticated claude or codex rather than merely joining their
// search.
const envCmdProviderName = "env"

// OptionsFromEnv layers the GODZILLA_LLM_* environment over base (env wins) —
// the same "flags/env override config file" precedence every other Godzilla
// setting follows. GODZILLA_LLM_PROVIDER and GODZILLA_LLM_MODEL are the two
// knobs a shell one-liner should need to override; Providers is structured
// data with no sane env encoding, so it stays config-file (or code) only —
// EXCEPT for GODZILLA_LLM_CMD, a full argv (e.g. "codex exec {prompt}"),
// tokenized on whitespace only. That is a deliberate limitation, not an
// oversight: an argument needing a quoted space belongs in a .godzilla.yaml
// `llm.providers` entry, where it is a real YAML list element rather than a
// string this package would have to re-parse. Setting it registers an ad hoc
// Provider (overwriting any base.Providers entry already named "env") and
// selects it outright — even overriding GODZILLA_LLM_PROVIDER, since naming
// an exact command is a stronger instruction than naming a provider category.
func OptionsFromEnv(base Options) Options {
	if v := os.Getenv("GODZILLA_LLM_PROVIDER"); v != "" {
		base.Provider = v
	}
	if v := os.Getenv("GODZILLA_LLM_MODEL"); v != "" {
		base.Model = v
	}
	if v := os.Getenv("GODZILLA_LLM_CMD"); v != "" {
		if argv := strings.Fields(v); len(argv) > 0 {
			base.Providers = append(slices.Clone(base.Providers), Provider{Name: envCmdProviderName, Command: argv})
			base.Provider = envCmdProviderName
		}
	}
	if v := os.Getenv("GODZILLA_LLM_CONCURRENCY"); v != "" {
		base.Concurrency = envPositiveInt("GODZILLA_LLM_CONCURRENCY", v, base.Concurrency)
	}
	if v := os.Getenv("GODZILLA_LLM_MAX_REVIEWS"); v != "" {
		base.MaxReviews = envPositiveInt("GODZILLA_LLM_MAX_REVIEWS", v, base.MaxReviews)
	}
	return base
}

// envPositiveInt parses an env var that must be a positive integer (a worker
// count or a review cap — nothing sensible is <1). A present-but-invalid value
// is a typo, not a request for 1-wide or unlimited by accident, so it is
// reported and the previous value (base's config-file value, or "unset") is
// kept rather than silently guessed at.
func envPositiveInt(name, v string, keep int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 1 {
		return n
	}
	fmt.Fprintf(os.Stderr, "warning: %s=%q is invalid (want a positive integer); ignoring\n", name, v)
	return keep
}

// validatedOverride is Select's final check on a Concurrency/MaxReviews value
// gathered from ANY source (a .godzilla.yaml int field is unvalidated data —
// config.go deliberately carries no logic — and a bad env value already
// warned in OptionsFromEnv but a caller can also build Options by hand). 0 is
// the ordinary "not set" case and passes silently; a negative number cannot be
// anyone's intent, so it is reported once, here, where the value is actually
// about to size a worker pool or a cap, and reset to "not set".
func validatedOverride(name string, n int) int {
	if n < 0 {
		fmt.Fprintf(os.Stderr, "warning: %s = %d is invalid (must be positive); using the default\n", name, n)
		return 0
	}
	return n
}

// Selected is the resolved backend.
type Selected struct {
	Reviewer Reviewer // nil when nothing is available
	Provider string   // "anthropic" | "openai" | a Provider.Name | "" when nil
	Tried    []string // human-readable, for the "nothing available" message

	// Concurrency and MaxReviews are Options.Concurrency/MaxReviews, validated
	// (see Select): 0 means no override, so Config() leaves the backend's own
	// default untouched.
	Concurrency int
	MaxReviews  int
}

// Config returns the ReviewConfig s.Reviewer needs: the backend's own default
// (command backends need a longer timeout and lower concurrency than an HTTP
// one — see command.go — advertised through the optional ReviewConfig()
// method rather than a field on Reviewer, so the one-method Reviewer interface
// stays one method, the same duck-typed-extras pattern
// internal/scan/scan.go:697-700 uses for Skipped() int; a reviewer that
// implements nothing, both HTTP backends, gets DefaultReviewConfig), with
// s.Concurrency/MaxReviews layered on top where set — an override, not a new
// default, so an unset knob reproduces today's behavior exactly.
func (s Selected) Config() ReviewConfig {
	cfg := DefaultReviewConfig()
	if rc, ok := s.Reviewer.(interface{ ReviewConfig() ReviewConfig }); ok {
		cfg = rc.ReviewConfig()
	}
	if s.Concurrency > 0 {
		cfg.Concurrency = s.Concurrency
	}
	if s.MaxReviews > 0 {
		cfg.MaxReviews = s.MaxReviews
	}
	return cfg
}

// Select resolves opts to a backend. It never returns an error: no backend
// available is a documented pass-through (like a nil Reviewer already is to
// Filter), and Tried says what was attempted so the caller can tell a user
// "nothing available" from "picked X".
//
// Four rungs, tried in order:
//  1. opts.Provider names something → use it verbatim (the escape hatch): the
//     two HTTP backends or a specific Provider.Name run unconditionally, with
//     no LookPath/probe/credential check — exactly like today's unconditional
//     Anthropic client, whose real failure (missing key, missing binary) still
//     surfaces per-review and Filter still fails open on it. "cmd" is the
//     partial escape hatch: skip straight to rung 3 (so a machine WITH an API
//     key can still be told "prefer the CLI"), but it is not itself one
//     provider, so it still has to search the table.
//  2. An HTTP backend whose credentials are plausibly present (credentials.go)
//     — Anthropic checked before OpenAI, preserving today's default.
//  3. The first configured Provider that is both on PATH and passes its Probe.
//  4. Nothing: Selected{Reviewer: nil}, Tried explaining every rung 2-3 miss.
//
// Options.Concurrency/MaxReviews ride along regardless of which rung picks the
// backend: the deferred validation below runs on every return path (a named
// return + defer, rather than repeating the check at each of the rungs'
// returns) and rejects a negative value — the one case config.go's "data
// only, no logic" load cannot itself catch — with a warning rather than
// letting it reach FilterWithConfig's worker pool.
// Each backend is built in exactly one place. The ladder reaches two of them
// from two rungs each — an explicit provider name and the credential/probe
// fallback — and a backend whose construction drifts between those two call
// sites is precisely the bug having one Select was meant to rule out.

func selectAnthropic(toolbox func() ToolBox, model string) Selected {
	var tb ToolBox
	if toolbox != nil {
		tb = toolbox()
	}
	return Selected{Reviewer: NewAnthropicReviewer().WithTools(tb).WithModel(model), Provider: "anthropic"}
}

func selectOpenAI(model string) Selected {
	return Selected{Reviewer: NewOpenAIReviewer().WithModel(model), Provider: "openai"}
}

func selectProvider(p Provider, opts Options, tried []string) Selected {
	return Selected{Reviewer: &commandReviewer{p: p, dir: opts.Root, model: opts.Model}, Provider: p.Name, Tried: tried}
}

// toolbox is a THUNK, not a ToolBox: only the two Anthropic rungs use one, and
// building it walks every lowered function in the program to index it by
// canonical name. The common path now ends at a CLI backend that never touches
// it, so constructing it eagerly would be pure waste — and would hold those
// maps alive through the review phase, where each concurrent CLI subprocess
// already costs ~1 GiB. nil is allowed and yields a nil ToolBox.
func Select(opts Options, toolbox func() ToolBox) (sel Selected) {
	defer func() {
		sel.Concurrency = validatedOverride("llm.concurrency / GODZILLA_LLM_CONCURRENCY", opts.Concurrency)
		sel.MaxReviews = validatedOverride("llm.max-reviews / GODZILLA_LLM_MAX_REVIEWS", opts.MaxReviews)
	}()
	providers := mergeProviders(opts.Providers)

	switch strings.ToLower(strings.TrimSpace(opts.Provider)) {
	case "", "auto":
		// Fall through to rungs 2-4 below.
	case "anthropic":
		return selectAnthropic(toolbox, opts.Model)
	case "openai":
		return selectOpenAI(opts.Model)
	case "cmd":
		return selectCommand(providers, opts)
	default:
		if p, ok := findProvider(providers, opts.Provider); ok {
			return selectProvider(p, opts, nil)
		}
		// An explicitly named provider that doesn't exist is a config typo, not
		// an invitation to silently pick a different backend.
		return Selected{Tried: []string{fmt.Sprintf("%s: not a configured provider", opts.Provider)}}
	}

	var tried []string
	if anthropicCredentialsLikely() {
		return selectAnthropic(toolbox, opts.Model)
	}
	tried = append(tried, "anthropic (no credentials found)")
	if openaiCredentialsLikely() {
		return selectOpenAI(opts.Model)
	}
	tried = append(tried, "openai (no credentials found)")

	sel = selectCommand(providers, opts)
	sel.Tried = append(tried, sel.Tried...)
	return sel
}

// selectCommand is rung 3: the first provider that is both on PATH and passes
// its Probe. It also backs the "cmd" escape hatch, which enters here directly.
func selectCommand(providers []Provider, opts Options) Selected {
	var tried []string
	for _, p := range providers {
		if len(p.Command) == 0 {
			continue // a Name-only override with nothing to run
		}
		if !commandOnPath(p) {
			tried = append(tried, fmt.Sprintf("%s (not installed: %q not on PATH)", p.Name, p.Command[0]))
			continue
		}
		if !probeOK(p, opts.Root) {
			tried = append(tried, fmt.Sprintf("%s (not authenticated)", p.Name))
			continue
		}
		return selectProvider(p, opts, tried)
	}
	return Selected{Tried: tried}
}

// findProvider looks up name in providers, case-insensitively.
func findProvider(providers []Provider, name string) (Provider, bool) {
	i := slices.IndexFunc(providers, func(p Provider) bool { return strings.EqualFold(p.Name, name) })
	if i < 0 {
		return Provider{}, false
	}
	return providers[i], true
}

// mergeProviders overlays extra onto builtinProviders, matched by Name: a
// Name shared with a builtin replaces it IN PLACE (so a user can, say, change
// only claude's ModelFlag without repeating the rest of its Command), and a
// new Name is appended after the builtins. Order is what the auto ladder tries
// first, so a builtin's position — claude before codex — never moves.
func mergeProviders(extra []Provider) []Provider {
	out := slices.Clone(builtinProviders)
	for _, p := range extra {
		if i := slices.IndexFunc(out, func(b Provider) bool { return strings.EqualFold(b.Name, p.Name) }); i >= 0 {
			out[i] = p
		} else {
			out = append(out, p)
		}
	}
	return out
}
