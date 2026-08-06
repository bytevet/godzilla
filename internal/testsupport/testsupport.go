// Package testsupport holds the small helpers shared by test packages across the
// repo: the toolchain-presence skip (RequireTool) and the one-rule RuleSet
// builder (OneRuleSet).
//
// It lives outside internal/rules on purpose: OneRuleSet must fill
// RuleSet.DefaultPropagators from the shipped `_default-propagators.yaml`
// fragment, which only internal/rules/loader can read — and loader imports
// rules, so the builder cannot live in rules without a cycle.
package testsupport

import (
	"os/exec"
	"testing"

	"godzilla/internal/rules"
	"godzilla/internal/rules/loader"
)

// RequireTool skips the test when the named executable (python3, ruby, java,
// rustc, ...) is not on PATH — the standard guard for converter tests whose
// frontend shells out to an external toolchain.
func RequireTool(t testing.TB, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not found on PATH; skipping", name)
	}
}

// DefaultPropagators returns the shipped `_default-propagators.yaml` list. A
// test that builds its own RuleSet must set RuleSet.DefaultPropagators from
// this to behave like a real scan: the defaults are loader-supplied data, so a
// bare RuleSet literal legitimately has none and taint dies at the first
// stdlib transform (fmt.Sprintf, strings.ToLower, ...).
func DefaultPropagators(t testing.TB) []string {
	t.Helper()
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("loader.Builtin: %v", err)
	}
	if len(rs.DefaultPropagators) == 0 {
		t.Fatal("no DefaultPropagators loaded from _default-propagators.yaml")
	}
	return rs.DefaultPropagators
}

// RuleOpt adjusts the rule OneRuleSet builds.
type RuleOpt func(*rules.Rule)

// Severity overrides the rule's severity (OneRuleSet defaults to High).
func Severity(s rules.Severity) RuleOpt { return func(r *rules.Rule) { r.Severity = s } }

// Message overrides the rule's finding message (OneRuleSet defaults to the
// rule id).
func Message(msg string) RuleOpt { return func(r *rules.Rule) { r.Message = msg } }

// Propagators sets the rule's own propagator globs (on top of the set-wide
// defaults OneRuleSet always carries).
func Propagators(globs ...string) RuleOpt { return func(r *rules.Rule) { r.Propagators = globs } }

// Validators sets the rule's guard/barrier validator globs.
func Validators(globs ...string) RuleOpt { return func(r *rules.Rule) { r.Validators = globs } }

// Sinks replaces the sink list built from OneRuleSet's bare patterns — for a
// rule whose sinks need a dynamic `when:` guard (e.g. `not hostFixed()`).
func Sinks(sinks ...rules.Sink) RuleOpt { return func(r *rules.Rule) { r.Sinks = sinks } }

// OneRuleSet builds a single-rule RuleSet — the shape almost every engine and
// converter test wants — with RuleSet.DefaultPropagators always populated (see
// DefaultPropagators). Sink patterns may carry the usual "#idx" suffix.
func OneRuleSet(t testing.TB, id, lang, cwe string, sources, sinks []string, opts ...RuleOpt) *rules.RuleSet {
	t.Helper()
	r := rules.Rule{
		ID:        id,
		Languages: []string{lang},
		Severity:  rules.SeverityHigh,
		CWE:       cwe,
		Message:   id,
		Sources:   sources,
		Sinks:     rules.SinksOf(sinks...),
	}
	for _, o := range opts {
		o(&r)
	}
	return &rules.RuleSet{DefaultPropagators: DefaultPropagators(t), Rules: []rules.Rule{r}}
}
