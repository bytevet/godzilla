package rules

import "testing"

// FuzzMatchGlob fuzzes the canonical-name glob matcher (patterns come from YAML
// rule packs, callees from lowered code); it compiles a regexp internally and
// must never panic on any pattern/subject pair.
func FuzzMatchGlob(f *testing.F) {
	f.Add("go:*os/exec.Command", "go:os/exec.Command")
	f.Add("**", "anything")
	f.Add("py:*.execute#0", "py:cur.execute")
	f.Fuzz(func(t *testing.T, pattern, s string) {
		_ = MatchGlob(pattern, s)
	})
}
