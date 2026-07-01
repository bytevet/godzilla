package analysis

import (
	"testing"

	ir "godzilla/pkg/ir/v1"
)

// progWithConstant builds a minimal gIR program with a single call instruction
// whose argument is the given string constant, so ScanSecrets has something to
// walk.
func progWithConstant(val string) *ir.Program {
	arg := &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: val}}}}
	inst := &ir.Instruction{
		Op:  ir.OpCode_OP_CODE_CALL,
		Pos: &ir.Position{Filename: "config.go", Line: 10, Column: 5},
		Call: &ir.CallCommon{
			Callee: "go:fmt.Println",
			Args:   []*ir.Value{arg},
		},
	}
	return &ir.Program{
		Modules: []*ir.Module{{
			Language: "go",
			Functions: []*ir.Function{{
				CanonicalName: "go:main.main",
				Blocks:        []*ir.BasicBlock{{Instrs: []*ir.Instruction{inst}}},
			}},
		}},
	}
}

func TestScanSecrets_Detects(t *testing.T) {
	cases := []struct {
		name   string
		value  string
		ruleID string
	}{
		{"aws access key", `AKIAIOSFODNN7EXAMPLE`, "secret-aws-access-key"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIabc...", "secret-private-key"},
		{"github token", "ghp_0123456789abcdefABCDEF0123456789abcd", "secret-github-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := ScanSecrets(progWithConstant(tc.value))
			var got *Finding
			for i := range findings {
				if findings[i].RuleID == tc.ruleID {
					got = &findings[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("expected finding %s for %q, got %v", tc.ruleID, tc.value, findings)
			}
			if got.CWE != secretCWE {
				t.Errorf("expected CWE %s, got %s", secretCWE, got.CWE)
			}
			if got.SinkPos == nil {
				t.Error("expected a non-nil position")
			}
		})
	}
}

func TestScanSecrets_NoFalsePositive(t *testing.T) {
	// An ordinary string must not be flagged.
	findings := ScanSecrets(progWithConstant("SELECT name FROM users WHERE id = ?"))
	if len(findings) != 0 {
		t.Errorf("expected no findings for a benign string, got %v", findings)
	}
}
