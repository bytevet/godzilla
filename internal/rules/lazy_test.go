package rules

import "testing"

// TestLazyCompileEquivalence pins the ensure() contract: a hand-built Rule that
// is matched without an explicit Compile behaves IDENTICALLY to its compiled
// twin — same matches, same "#idx" pinning, same fail-closed degradation for
// entries that cannot compile. This is what replaced the old uncompiled
// fallback paths, whose duplicate matching logic could drift silently.
func TestLazyCompileEquivalence(t *testing.T) {
	newRule := func() *Rule {
		return &Rule{
			ID:         "lazy",
			Sources:    []string{"go:net/http.*"},
			Sinks:      []Sink{{Pattern: "go:*database/sql*.Query#0"}},
			Sanitizers: []string{"go:*.EscapeString"},
			Validators: []string{"go:*.IsValid"},
		}
	}

	lazy, eager := newRule(), newRule()
	if err := eager.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}

	for _, callee := range []string{
		"go:net/http.HandleFunc", "go:database/sql.DB.Query",
		"go:html.EscapeString", "go:pkg.IsValid", "go:unrelated.Fn",
	} {
		if lazy.IsSource(callee) != eager.IsSource(callee) {
			t.Errorf("IsSource(%q): lazy != eager", callee)
		}
		if lazy.IsSanitizer(callee) != eager.IsSanitizer(callee) {
			t.Errorf("IsSanitizer(%q): lazy != eager", callee)
		}
		if lazy.IsValidator(callee) != eager.IsValidator(callee) {
			t.Errorf("IsValidator(%q): lazy != eager", callee)
		}
		la, _, lok := lazy.MatchSink(callee)
		ea, _, eok := eager.MatchSink(callee)
		if lok != eok || len(la) != len(ea) {
			t.Errorf("MatchSink(%q): lazy (args=%v ok=%v) != eager (args=%v ok=%v)",
				callee, la, lok, ea, eok)
		}
	}

	// "#0" pinning survives the lazy path.
	if args, _, ok := lazy.MatchSink("go:database/sql.DB.Query"); !ok || len(args) != 1 || args[0] != 0 {
		t.Errorf("lazy MatchSink pinning: args=%v ok=%v, want [0] true", args, ok)
	}

	// A guard that cannot compile still fails closed on the lazy path.
	bad := &Rule{ID: "bad", Sinks: []Sink{{Pattern: "go:pkg.Sink", When: "not a guard ("}}}
	if _, g, ok := bad.MatchSink("go:pkg.Sink"); !ok || g != DenyGuard {
		t.Errorf("lazy uncompilable guard = %v (ok=%v), want DenyGuard", g, ok)
	}

	// An invalid detector regexp still means "matches nothing", not a panic.
	badRe := &Rule{ID: "re", Kind: "secret", Matches: "("}
	if re := badRe.MatchesRe(); re != nil {
		t.Errorf("lazy MatchesRe on invalid regexp = %v, want nil", re)
	}
}
