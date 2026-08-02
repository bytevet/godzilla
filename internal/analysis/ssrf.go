package analysis

import (
	"strings"

	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// SSRF (CWE-918) false-positive reduction.
//
// An SSRF sink fires whenever untrusted input reaches a request URL, but SSRF is
// only exploitable when the attacker can control the URL's HOST/authority — if
// the taint is confined to the path (after the first "/") or query (after "?"),
// the destination host is fixed and the request cannot be redirected to an
// attacker-chosen host. urlHostControllable reconstructs how the tainted URL
// string was built (concatenation or a format string) and reports whether the
// taint can reach the host. It is deliberately conservative: it reports the host
// as fixed only when it can PROVE it is a constant prefix; the decision to
// suppress is the RULE's, via `when: 'not hostFixed()'` (see rules.EvalHostFixed);
// otherwise true (keep the finding), so no real SSRF is dropped.

// formatIntrinsic is the language-neutral marker a frontend sets on a
// printf-style formatter call (Go fmt.Sprint*, Java String.format/valueOf, Rust
// fmt::Arguments::new). The literal template is the call's Args[0]. The engine
// reads this marker instead of matching any language's format-callee name.
const formatIntrinsic = "builtin.format"

// identityIntrinsic is the language-neutral marker a frontend sets on a value
// that forwards its operand's text unchanged (a string conversion, or a value
// standing in for its argument's text such as Rust's Command::new)
// (to_string/as_str/clone/into/deref and the format! result wrappers). The
// engine follows Args[0] one hop deeper to find the URL construction, without
// matching any language's conversion-callee name.
const identityIntrinsic = "builtin.identity"

// compareIntrinsic is the language-neutral marker a frontend sets on a
// COMPARISON. Its result is a bool -- influence, not content -- so it must not
// propagate operand taint, which it achieves by being an intrinsic absent from
// intrinsicPropagators rather than a BIN_OP (every BIN_OP propagates).
//
// It is a CROSS-FRONTEND contract: Go, JavaScript, Python and Ruby all emit it.
// The engine still has to FOLLOW it when tracing a branch condition back to a
// validator (see guards.go), which is the one place a comparison's operands
// matter even though its taint does not.
const compareIntrinsic = "builtin.compare"

// memberReadIntrinsic marks a synthesized member read (`obj.field` lowered as a
// CALL so its name can match a source glob) whose base the frontend kept in
// Call.Value. The engine carries that base's taint to the result: reading a
// property off a tainted object yields tainted data, which no rule models because
// it is not a transform.
//
// It is a CROSS-FRONTEND contract, not a JS detail: any frontend that lowers a
// member read as a synthetic call should set it rather than inventing another
// mechanism (Python currently merges an extra INDEX through a BIN_OP_OR for the
// same purpose — see converters/python/lower.go — and can retire onto this).
const memberReadIntrinsic = "builtin.member_read"

// kwargIntrinsic tags a named-argument marker a frontend emits to keep a keyword
// argument's NAME available to rule guards: Args[0] is the name (a string
// constant), Args[1] the value it wraps. gIR's CallCommon carries only positional
// args, and a call site may pass keywords in any order, so without this marker
// `shell=True` is indistinguishable from `check=True` once lowered. Modeling it
// as an intrinsic keeps the frozen gIR schema untouched.
//
// Frontends wrap only CONSTANT values, so the marker never hides taint: it is
// deliberately absent from intrinsicPropagators, and everything that reads an
// argument's constant unwraps it first (see unwrapKwarg).
const kwargIntrinsic = "builtin.kwarg"

// unwrapKwarg resolves v through a kwargIntrinsic marker, returning the keyword
// name and the value it wraps. For anything else it returns ("", v), so callers
// can apply it unconditionally. defs may be nil, in which case a marker cannot be
// resolved and v is returned unchanged.
func unwrapKwarg(v *ir.Value, defs map[string]*ir.Instruction) (string, *ir.Value) {
	if v == nil || defs == nil {
		return "", v
	}
	def, ok := defs[v.GetRegName()]
	if !ok || def.GetIntrinsic() != kwargIntrinsic || def.Call == nil {
		return "", v
	}
	args := def.Call.GetArgs()
	if len(args) != 2 {
		return "", v
	}
	name, ok := constStr(args[0])
	if !ok {
		return "", v
	}
	return name, args[1]
}

// urlHostControllable reports whether any tainted injection-point argument can
// influence the request URL's host. Returns true (keep the SSRF finding) unless
// EVERY tainted argument is provably confined to the path/query of a fixed host.
func urlHostControllable(injectable []*ir.Value, tainted taintState, defs map[string]*ir.Instruction) bool {
	for _, v := range injectable {
		if _, ok := isTainted(tainted, v); !ok {
			continue
		}
		// The skeleton's text before its first DynMarker IS the constant prefix, so
		// one reconstruction answers this -- no separate prefix walk. An opaque or
		// unrecoverable construction reconstructs to DynMarker alone, leaving an
		// empty prefix that cannot match, so it stays controllable and keeps firing.
		skeleton, _ := constSkeleton(v, defs, map[string]bool{})
		if rules.ArgHostFixed(rules.Arg{String: skeleton}) {
			continue // this tainted value lands only in the path/query — safe
		}
		return true // taint can reach the host (or the construction is opaque)
	}
	return false
}

// constSkeleton reconstructs v's string construction as a skeleton for a dynamic
// guard: constant runs verbatim, rules.DynMarker for each dynamic (non-constant)
// run. It returns the skeleton and whether the WHOLE value is constant. It does
// not stop at the first dynamic leaf — it emits a marker and continues — so a guard can inspect constant pieces anywhere in the argument.
func constSkeleton(v *ir.Value, defs map[string]*ir.Instruction, seen map[string]bool) (string, bool) {
	if s, ok := constStr(v); ok {
		return s, true
	}
	def, ok := resolveDef(v, defs, seen)
	if !ok {
		return rules.DynMarker, false
	}
	// resolveDef guarantees a non-empty, unseen register here. Mark it for the
	// recursive calls below and unmark on return (backtracking): the cycle guard
	// is per-PATH, and mutating one map beats copying it at every level.
	reg := v.GetRegName()
	seen[reg] = true
	defer delete(seen, reg)

	switch {
	case def.Op == ir.OpCode_OP_CODE_BIN_OP && def.GetBinOp() == ir.BinOpKind_BIN_OP_ADD:
		var b strings.Builder
		complete := true
		for _, op := range def.GetOperands() {
			s, c := constSkeleton(op, defs, seen)
			b.WriteString(s)
			complete = complete && c
		}
		return b.String(), complete
	case def.Op == ir.OpCode_OP_CODE_BIN_OP && def.GetBinOp() == ir.BinOpKind_BIN_OP_REM:
		// Python `"tmpl" % value`.
		if ops := def.GetOperands(); len(ops) >= 1 {
			if tmpl, ok := constStr(ops[0]); ok {
				return templateSkeleton(tmpl), false
			}
		}
	case def.Op == ir.OpCode_OP_CODE_CALL || def.Op == ir.OpCode_OP_CODE_INVOKE:
		switch {
		case def.GetIntrinsic() == formatIntrinsic:
			if args := def.Call.GetArgs(); len(args) >= 1 {
				if tmpl, ok := constStr(args[0]); ok {
					return templateSkeleton(tmpl), false
				}
			}
		case def.GetIntrinsic() == identityIntrinsic:
			if args := def.Call.GetArgs(); len(args) >= 1 {
				return constSkeleton(args[0], defs, seen)
			}
		case def.GetIntrinsic() == kwargIntrinsic:
			// A named-argument marker is pure annotation: reconstruct the value it
			// wraps, so wrapping a keyword argument never makes a string it
			// contributes to look dynamic (which would, in the SSRF host analysis,
			// lose a constant run).
			if args := def.Call.GetArgs(); len(args) == 2 {
				return constSkeleton(args[1], defs, seen)
			}
		}
	case def.Op == ir.OpCode_OP_CODE_CONVERT || def.Op == ir.OpCode_OP_CODE_LOAD:
		if ops := def.GetOperands(); len(ops) >= 1 {
			return constSkeleton(ops[0], defs, seen)
		}
	}
	return rules.DynMarker, false
}

// resolveDef returns the instruction defining v's register, or (nil,false) for a
// constant/global/unknown operand or a cycle.
func resolveDef(v *ir.Value, defs map[string]*ir.Instruction, seen map[string]bool) (*ir.Instruction, bool) {
	reg := v.GetRegName()
	if reg == "" || seen[reg] {
		return nil, false
	}
	def := defs[reg]
	return def, def != nil
}

// constStr reads an operand's literal string value verbatim — every frontend
// stores the raw literal. Returns ok=false for a register or non-string operand,
// which cleanly distinguishes a constant piece from a tainted/dynamic one.
func constStr(v *ir.Value) (string, bool) {
	c := v.GetConstant()
	if c == nil {
		return "", false
	}
	if _, ok := c.Value.(*ir.Constant_StringVal); !ok {
		return "", false
	}
	return c.GetStringVal(), true
}

// templateSkeleton renders a printf/brace format template as a skeleton: literal
// text verbatim, each interpolation placeholder replaced by rules.DynMarker — so
// constant runs AFTER the first placeholder survive ("q=%s&safe=1" ->
// "q=<DYN>&safe=1"), which a prefix-only view would drop.
func templateSkeleton(tmpl string) string {
	var b strings.Builder
	for i := 0; i < len(tmpl); {
		switch c := tmpl[i]; c {
		case '%':
			if i+1 < len(tmpl) && tmpl[i+1] == '%' {
				b.WriteByte('%') // escaped %%
				i += 2
				continue
			}
			b.WriteString(rules.DynMarker)
			for i++; i < len(tmpl) && !isVerbLetter(tmpl[i]); i++ { // flags/width/precision
			}
			i++ // the verb letter
		case '{':
			if i+1 < len(tmpl) && tmpl[i+1] == '{' {
				b.WriteByte('{') // escaped {{
				i += 2
				continue
			}
			b.WriteString(rules.DynMarker)
			for ; i < len(tmpl) && tmpl[i] != '}'; i++ {
			}
			i++ // the closing brace
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

func isVerbLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
