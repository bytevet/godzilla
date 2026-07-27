package analysis

import "testing"

// FuzzScanText fuzzes the secret-pattern matcher, which runs over untrusted
// source and config-file lines; it must never panic.
func FuzzScanText(f *testing.F) {
	f.Add("AKIA0000000000000000")
	f.Add("password = \"\"")
	f.Add("postgres://u:p@h/db")
	f.Add("")
	sc := newSecretScan(builtinRuleSet(f))
	f.Fuzz(func(t *testing.T, s string) {
		sc.text(s, nil, "", "")
	})
}
