package rules

import "testing"

// FuzzMatchGlob fuzzes the canonical-name glob matcher (patterns come from YAML
// rule packs, callees from lowered code): it classifies each pattern by shape
// (classifyGlob) rather than compiling a regexp, and must never panic on any
// pattern/subject pair — including invalid UTF-8, which classifyGlob maps to
// globNever to preserve the behaviour of the old regexp path this fuzzer
// originally broke.
func FuzzMatchGlob(f *testing.F) {
	f.Add("go:*os/exec.Command", "go:os/exec.Command")
	f.Add("**", "anything")
	f.Add("py:*.execute#0", "py:cur.execute")
	f.Fuzz(func(t *testing.T, pattern, s string) {
		_ = matchGlob(pattern, s)
	})
}
