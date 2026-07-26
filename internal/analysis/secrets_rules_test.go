package analysis

import "testing"

// TestSecretRulesShipComplete guards the move of these detectors from a Go table
// into rulepacks/secrets.yaml: a `kind: secret` rule whose `matches` is missing
// or uncompilable silently scans nothing, which reads exactly like a clean repo.
// The loader rejects both, so this asserts the shipped set is non-empty and that
// each rule carries the metadata a finding needs.
func TestSecretRulesShipComplete(t *testing.T) {
	for _, d := range secretDets(t) {
		if d.rule.CWE == "" {
			t.Errorf("secret rule %q has no cwe", d.rule.ID)
		}
		if d.rule.Message == "" {
			t.Errorf("secret rule %q has no message", d.rule.ID)
		}
		if d.rule.Severity.Rank() == 0 {
			t.Errorf("secret rule %q has no usable severity", d.rule.ID)
		}
	}
}
