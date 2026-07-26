package analysis

import (
	"testing"

	"godzilla/internal/rules"
	"godzilla/internal/rules/loader"
)

// builtinRuleSet returns the shipped rule set, compiled. Tests that need what
// actually ships — the secret detectors, the default propagators — go through
// this rather than hand-rolling a RuleSet, which would prove nothing about the
// rulepacks.
func builtinRuleSet(t testing.TB) *rules.RuleSet {
	t.Helper()
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("loader.Builtin: %v", err)
	}
	if err := rs.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return rs
}

// shippedDefaultPropagators is the `_default-propagators.yaml` list. A test that
// builds its own RuleSet must set RuleSet.DefaultPropagators from this to behave
// like a real scan: the defaults are loader-supplied data, so a bare RuleSet
// literal legitimately has none and taint dies at the first stdlib transform
// (fmt.Sprintf, strings.ToLower, ...).
func shippedDefaultPropagators(t testing.TB) []string {
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

// secretDets returns the compiled `kind: secret` detectors from the shipped packs.
func secretDets(t testing.TB) []secretDetector {
	t.Helper()
	ds := secretDetectorsOf(builtinRuleSet(t))
	if len(ds) == 0 {
		t.Fatal("no kind: secret rules found in the builtin rulepacks")
	}
	return ds
}
