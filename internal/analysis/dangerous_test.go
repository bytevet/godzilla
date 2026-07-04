package analysis

import (
	"testing"

	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// callInstAt builds a CALL instruction to callee with the given constant-string
// arguments, at a position.
func callInstAt(callee string, line int32, constArgs ...string) *ir.Instruction {
	var args []*ir.Value
	for _, s := range constArgs {
		args = append(args, &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: s}}}})
	}
	return &ir.Instruction{
		Op:   ir.OpCode_OP_CODE_CALL,
		Pos:  &ir.Position{Filename: "a.go", Line: line},
		Call: &ir.CallCommon{Callee: callee, Args: args},
	}
}

func progWith(lang string, insts ...*ir.Instruction) *ir.Program {
	return &ir.Program{Modules: []*ir.Module{{
		Language: lang,
		Functions: []*ir.Function{{
			CanonicalName: lang + ":m.f",
			Blocks:        []*ir.BasicBlock{{Instrs: insts}},
		}},
	}}}
}

// TestDangerousCall_PlainCallee: a callee-glob match with no const_arg fires.
func TestDangerousCall_PlainCallee(t *testing.T) {
	prog := progWith("go",
		callInstAt("go:crypto/md5.New", 10),
		callInstAt("go:crypto/sha256.New", 11), // strong; must NOT fire
	)
	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID: "GO-WEAK-HASH", Kind: "dangerous-call", Languages: []string{"go"},
		Severity: rules.SeverityMedium, CWE: "CWE-327", Message: "weak hash",
		Callees: []string{"go:crypto/md5.*", "go:crypto/sha1.*"},
	}}}

	findings := ScanDangerousCalls(prog, rs)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (md5 only), got %d", len(findings))
	}
	if findings[0].Confidence != ConfidenceHigh {
		t.Errorf("dangerous-call findings should be High confidence, got %q", findings[0].Confidence)
	}
	if findings[0].SinkPos.GetLine() != 10 {
		t.Errorf("finding at wrong line: %d", findings[0].SinkPos.GetLine())
	}
}

// TestDangerousCall_ConstArg: only the call whose constant argument matches the
// regexp fires (MessageDigest.getInstance("MD5") but not ("SHA-256")).
func TestDangerousCall_ConstArg(t *testing.T) {
	prog := progWith("java",
		callInstAt("java:java/security/MessageDigest.getInstance", 5, "MD5"),
		callInstAt("java:java/security/MessageDigest.getInstance", 6, "SHA-256"),
	)
	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID: "JAVA-WEAK-HASH", Kind: "dangerous-call", Languages: []string{"java"},
		Severity: rules.SeverityMedium, CWE: "CWE-327", Message: "weak digest",
		Callees:  []string{"java:*MessageDigest.getInstance"},
		ConstArg: &rules.ConstArg{Index: 0, Matches: "(?i)^(MD5|SHA-?1)$"},
	}}}

	findings := ScanDangerousCalls(prog, rs)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (MD5 only), got %d", len(findings))
	}
	if findings[0].SinkPos.GetLine() != 5 {
		t.Errorf("expected the MD5 call at line 5, got line %d", findings[0].SinkPos.GetLine())
	}
}

// TestDangerousCall_LanguageScoped: a rule only fires for its declared language.
func TestDangerousCall_LanguageScoped(t *testing.T) {
	prog := progWith("python", callInstAt("go:crypto/md5.New", 1))
	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID: "GO-WEAK-HASH", Kind: "dangerous-call", Languages: []string{"go"},
		Severity: rules.SeverityMedium, Callees: []string{"go:crypto/md5.*"},
	}}}
	if f := ScanDangerousCalls(prog, rs); len(f) != 0 {
		t.Errorf("a go rule must not fire on a python module, got %d finding(s)", len(f))
	}
}

// TestDangerousCall_IgnoresTaintRules: a normal taint rule is not evaluated by
// the dangerous-call pass.
func TestDangerousCall_IgnoresTaintRules(t *testing.T) {
	prog := progWith("go", callInstAt("go:os/exec.Command", 1, "sh"))
	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID: "GO-CMDI", Languages: []string{"go"}, Severity: rules.SeverityCritical,
		Sinks: []string{"go:os/exec.Command"},
	}}}
	if f := ScanDangerousCalls(prog, rs); len(f) != 0 {
		t.Errorf("taint rule must not be evaluated as a dangerous-call, got %d", len(f))
	}
}
