package analysis

import (
	"godzilla/internal/irwalk"
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

	// Precompile the dangerous-call rules. Compile also compiles the rule's
	// optional const_arg regexp (Rule.ConstArgRe): a rule with a const_arg whose
	// regexp cannot compile has no usable regexp, so constArgMatches rejects every
	// call for it (its intent is unknowable) rather than silently matching
	// everything.
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
		dcs = append(dcs, compiled{rule: r, re: r.ConstArgRe(), conf: ParseConfidence(r.Confidence, ConfidenceHigh)})
	}
	if len(dcs) == 0 {
		return nil
	}

	// Resolve the language filter ONCE per language rather than per (call site ×
	// rule). AppliesTo is a slice scan with a case-insensitive compare, and it was
	// running on the innermost loop of the whole pass; a program has a handful of
	// languages, so memoizing the filtered slice makes it a single map lookup per
	// function instead.
	byLang := map[string][]compiled{}
	forLang := func(lang string) []compiled {
		if ds, ok := byLang[lang]; ok {
			return ds
		}
		var ds []compiled
		for _, d := range dcs {
			if d.rule.AppliesTo(lang) {
				ds = append(ds, d)
			}
		}
		byLang[lang] = ds
		return ds
	}

	var findings []Finding
	seen := map[string]bool{}
	for mod, fn := range irwalk.Funcs(prog) {
		lang := mod.GetLanguage()
		langDcs := forLang(lang)
		if len(langDcs) == 0 {
			continue // no dangerous-call rule targets this module's language
		}
		// Built on first use and then shared by every rule's guard below. A
		// dangerous-call argument is usually a literal, but it may be a keyword
		// marker (builtin.kwarg) or a constant folded through a register, and
		// neither resolves without the def map — a guard reading `.Name` to tell
		// `shell=True` from `check=True` would otherwise never see a name.
		// Lazy because the overwhelming majority of functions in a scan (the whole
		// lowered dependency closure included) contain no call a dangerous-call
		// rule matches, and only a const_arg or a `when:` guard ever needs the map.
		var defs map[string]*ir.Instruction
		getDefs := func() map[string]*ir.Instruction {
			if defs == nil {
				defs = buildDefs(fn)
			}
			return defs
		}
		for inst := range irwalk.Instrs(fn) {
			if inst.Call == nil {
				continue
			}
			callee := inst.Call.GetCallee()
			for _, d := range langDcs {
				guard, matched := d.rule.MatchDangerousCallee(callee)
				if !matched || !constArgMatches(d.rule, d.re, inst.Call, getDefs) {
					continue
				}
				// Dynamic callee guard (`when:`): suppress unless it confirms against
				// the call's reconstructed argument values (required-confirmation).
				if guard != nil && !guard.Eval(argVals(inst.Call, getDefs(), nil, guard.NeedsStructure())) {
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
	return findings
}

// constArgMatches reports whether a call satisfies a dangerous-call rule's
// optional constant-argument condition. With no ConstArg the call always
// matches. With one, the constant string at the logical index must match the
// regexp; a non-constant or out-of-range argument does not match (the rule
// author asked for a specific literal).
//
// getDefs is called only after the no-ConstArg early exit, so the common
// (const_arg-less) rule never forces the function's def map to be built.
func constArgMatches(rule *rules.Rule, re *regexp.Regexp, cc *ir.CallCommon, getDefs func() map[string]*ir.Instruction) bool {
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
	_, v := unwrapKwarg(la[idx], getDefs())
	return re.MatchString(v.GetConstant().GetStringVal())
}
