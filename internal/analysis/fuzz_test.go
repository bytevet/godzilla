package analysis

import "testing"

// FuzzScanText fuzzes the secret-pattern matcher, which runs over untrusted
// source and config-file lines; it must never panic.
func FuzzScanText(f *testing.F) {
	f.Add("AKIA0000000000000000")
	f.Add("password = \"\"")
	f.Add("postgres://u:p@h/db")
	f.Add("")
	// The rule set is immutable and expensive to compile, so it is built once --
	// but the scan carries per-run state (seen, findings), so a shared instance
	// would accumulate across every fuzz input, growing without bound and slowing
	// its own map lookups. One scan per input.
	rs := builtinRuleSet(f)
	f.Fuzz(func(t *testing.T, s string) {
		newSecretScan(rs).text(s, nil, "", "")
	})
}
