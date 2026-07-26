package analysis

import (
	"regexp"

	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// ScanDangerousCalls evaluates every `kind: dangerous-call` rule (COV-4)
// syntactically over the program: any call whose callee matches a rule's
// Callees glob is a finding, optionally gated on a constant string argument
// (e.g. MessageDigest.getInstance("MD5")). This is a non-dataflow pass — no
// taint tracking — for the zero-noise categories (weak crypto/ciphers, insecure
// randomness) the taint engine cannot express. Findings are High confidence BY
// DEFAULT (call-site-deterministic); a rule that is heuristic rather than
// deterministic may declare `confidence:` to lower that, which is what makes its
// findings eligible for LLM triage. Findings are deduped per (rule, position).
func ScanDangerousCalls(prog *ir.Program, rs *rules.RuleSet) []Finding {
	if prog == nil || rs == nil {
		return nil
	}

	// Precompile the dangerous-call rules and their optional const-arg regexps.
	// A rule with a const_arg whose regexp cannot compile is dropped (its intent
	// is unknowable), rather than silently matching everything.
	// The rule's declared confidence is resolved ONCE here rather than per finding,
	// so the per-call-site loop stays free of string normalization.
	type compiled struct {
		rule *rules.Rule
		re   *regexp.Regexp
		conf Confidence
	}
	var dcs []compiled
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if !r.IsDangerousCall() || len(r.Callees) == 0 {
			continue
		}
		_ = r.Compile() // precompile callee globs so the per-call match is lock-free
		c := compiled{rule: r, conf: ParseConfidence(r.Confidence, ConfidenceHigh)}
		if r.ConstArg != nil && r.ConstArg.Matches != "" {
			re, err := regexp.Compile(r.ConstArg.Matches)
			if err != nil {
				continue
			}
			c.re = re
		}
		dcs = append(dcs, c)
	}
	if len(dcs) == 0 {
		return nil
	}

	var findings []Finding
	seen := map[string]bool{}
	for _, mod := range prog.Modules {
		if mod == nil {
			continue
		}
		lang := mod.GetLanguage()
		for _, fn := range mod.Functions {
			if fn == nil {
				continue
			}
			// Built once per function and shared by every rule's guard below. A
			// dangerous-call argument is usually a literal, but it may be a keyword
			// marker (builtin.kwarg) or a constant folded through a register, and
			// neither resolves without the def map — a guard reading `.Name` to tell
			// `shell=True` from `check=True` would otherwise never see a name.
			defs := buildDefs(fn)
			for _, blk := range fn.Blocks {
				if blk == nil {
					continue
				}
				for _, inst := range blk.Instrs {
					if inst == nil || inst.Call == nil {
						continue
					}
					callee := inst.Call.GetCallee()
					for _, d := range dcs {
						if !d.rule.AppliesTo(lang) {
							continue // cheap language gate before the glob walk
						}
						guard, matched := d.rule.MatchDangerousCallee(callee)
						if !matched || !constArgMatches(d.rule, d.re, inst.Call, defs) {
							continue
						}
						// Dynamic callee guard (`when:`): suppress unless it confirms
						// against the call's argument values, reconstructed through the
						// function's def map so a keyword marker resolves to its name and
						// a register-held constant to its text.
						// Built lazily: no reconstruction for the common unguarded rule.
						if guard != nil && !guard.Eval(argVals(inst.Call, defs)) {
							continue
						}
						key := d.rule.ID + "@" + posKey(inst.GetPos())
						if seen[key] {
							continue
						}
						seen[key] = true
						findings = append(findings, Finding{
							RuleID:     d.rule.ID,
							Severity:   d.rule.Severity,
							Confidence: d.conf,
							CWE:        d.rule.CWE,
							Message:    d.rule.Message,
							Language:   lang,
							Function:   fn.GetCanonicalName(),
							Package:    fn.GetPackageName(),
							SinkPos:    inst.GetPos(),
							SinkCallee: callee,
						})
					}
				}
			}
		}
	}
	return findings
}

// constArgMatches reports whether a call satisfies a dangerous-call rule's
// optional constant-argument condition. With no ConstArg the call always
// matches. With one, the constant string at the logical index must match the
// regexp; a non-constant or out-of-range argument does not match (the rule
// author asked for a specific literal).
func constArgMatches(rule *rules.Rule, re *regexp.Regexp, cc *ir.CallCommon, defs map[string]*ir.Instruction) bool {
	if rule.ConstArg == nil {
		return true
	}
	if re == nil {
		return false // a const_arg was declared but its regexp was invalid
	}
	la := logicalArgs(cc)
	idx := rule.ConstArg.Index
	if idx < 0 || idx >= len(la) {
		return false
	}
	// Unwrap a keyword marker so a const_arg still reads the VALUE a named
	// argument carries (Cipher.getInstance(algorithm="DES")).
	_, v := unwrapKwarg(la[idx], defs)
	return re.MatchString(v.GetConstant().GetStringVal())
}
