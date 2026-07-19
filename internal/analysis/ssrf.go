package analysis

import (
	"regexp"
	"strings"

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
// taint can reach the host. It is deliberately conservative: it returns false
// (suppress the finding) only when it can PROVE the host is a constant prefix;
// otherwise true (keep the finding), so no real SSRF is dropped.

// hostFixedRe matches a constant prefix that already pins a complete
// scheme://authority followed by a path/query/fragment separator — i.e. the
// authority is fully specified by the constant, so any following taint lands in
// the path or query. Examples that match: "https://example.com/", "http://h:8080?".
// Examples that do NOT: "https://" (no host yet), "https://example.com" (taint
// could extend the host), "//host/" (no scheme).
var hostFixedRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/?#\\]+[/?#\\]`)

// formatCallees identifies printf-style format functions whose first argument is
// the literal template (the interpolated values follow, packed into a slice/array).
// Rust `format!` lowers to `fmt::Arguments::new(<template>, args)`, and the Rust
// frontend decodes the packed template into a `{}`-placeholder string in that
// same argument-0 slot, so it fits the same shape.
func isFormatCallee(callee string) bool {
	return strings.Contains(callee, "Sprintf") ||
		strings.Contains(callee, "Sprintln") ||
		strings.HasSuffix(callee, "Sprint") ||
		strings.Contains(callee, "String.format") ||
		strings.Contains(callee, "String.valueOf") ||
		strings.Contains(callee, "Arguments::new")
}

// isPassthroughCallee identifies string-valued conversions that forward their
// operand's text unchanged (so the URL construction is found one hop deeper).
func isPassthroughCallee(callee string) bool {
	for _, suffix := range []string{
		"to_string", "to_owned", "as_str", "as_ref", "into", "clone", "deref",
		"String.toString", "String::from", "borrow",
		// Rust `format!` result chain: format(Arguments) -> String, wrapped in
		// must_use; each forwards its argument-0 so the URL construction is found
		// at the underlying fmt::Arguments::new.
		"must_use", "format",
	} {
		if strings.HasSuffix(callee, suffix) {
			return true
		}
	}
	return false
}

// urlHostControllable reports whether any tainted injection-point argument can
// influence the request URL's host. Returns true (keep the SSRF finding) unless
// EVERY tainted argument is provably confined to the path/query of a fixed host.
func urlHostControllable(injectable []*ir.Value, tainted taintState, defs map[string]*ir.Instruction) bool {
	for _, v := range injectable {
		if _, ok := isTainted(tainted, v); !ok {
			continue
		}
		prefix, recovered := urlConstPrefix(v, defs, map[string]bool{})
		if recovered && hostFixedRe.MatchString(prefix) {
			continue // this tainted value lands only in the path/query — safe
		}
		return true // taint can reach the host (or the construction is opaque)
	}
	return false
}

// urlConstPrefix returns the constant text that precedes the first tainted/dynamic
// segment of the URL value v, and whether the construction was recognized well
// enough to trust that prefix. A concatenation/format whose leading segments are
// constant yields (thePrefix, true); an opaque construction (e.g. Java `+`, or
// a direct source value) yields ("", false).
func urlConstPrefix(v *ir.Value, defs map[string]*ir.Instruction, seen map[string]bool) (string, bool) {
	def, ok := resolveDef(v, defs, seen)
	if !ok {
		return "", false
	}

	switch {
	case def.Op == ir.OpCode_OP_CODE_BIN_OP && def.GetBinOp() == ir.BinOpKind_BIN_OP_ADD:
		// String concatenation (Go/Python/JS `+`, Python f-strings, JS template
		// literals). The leading constant run is the fixed prefix.
		text, _ := leadingConst(v, defs, seen)
		return text, true

	case def.Op == ir.OpCode_OP_CODE_BIN_OP && def.GetBinOp() == ir.BinOpKind_BIN_OP_REM:
		// Python `"tmpl" % value` — operand 0 is the template.
		ops := def.GetOperands()
		if len(ops) >= 1 {
			if tmpl, isConst := constStr(ops[0]); isConst {
				return prefixBeforePlaceholder(tmpl), true
			}
		}
		return "", false

	case def.Op == ir.OpCode_OP_CODE_CALL || def.Op == ir.OpCode_OP_CODE_INVOKE:
		callee := def.Call.GetCallee()
		args := def.Call.GetArgs()
		switch {
		case isFormatCallee(callee):
			if len(args) >= 1 {
				if tmpl, isConst := constStr(args[0]); isConst {
					return prefixBeforePlaceholder(tmpl), true
				}
			}
			return "", false
		case isPassthroughCallee(callee) && len(args) >= 1:
			return urlConstPrefix(args[0], defs, seen)
		}
		return "", false

	case def.Op == ir.OpCode_OP_CODE_CONVERT || def.Op == ir.OpCode_OP_CODE_LOAD:
		if ops := def.GetOperands(); len(ops) >= 1 {
			return urlConstPrefix(ops[0], defs, seen)
		}
		return "", false
	}
	return "", false
}

// leadingConst returns the longest run of constant text at the START of the value
// v's string construction, and whether the ENTIRE construction is constant
// (complete). It flattens BIN_OP_ADD concatenation trees (every language lowers
// `+` string concatenation to BIN_OP_ADD, Rust included) and follows passthrough
// conversions, stopping at the first non-constant leaf.
func leadingConst(v *ir.Value, defs map[string]*ir.Instruction, seen map[string]bool) (text string, complete bool) {
	if s, isConst := constStr(v); isConst {
		return s, true
	}
	def, ok := resolveDef(v, defs, seen)
	if !ok {
		return "", false
	}
	next := markSeen(seen, v)

	switch {
	case def.Op == ir.OpCode_OP_CODE_BIN_OP && def.GetBinOp() == ir.BinOpKind_BIN_OP_ADD:
		return leadingConstSeq(def.GetOperands(), defs, next)
	case (def.Op == ir.OpCode_OP_CODE_CALL || def.Op == ir.OpCode_OP_CODE_INVOKE):
		if isPassthroughCallee(def.Call.GetCallee()) {
			if args := def.Call.GetArgs(); len(args) >= 1 {
				return leadingConst(args[0], defs, next)
			}
		}
	case def.Op == ir.OpCode_OP_CODE_CONVERT || def.Op == ir.OpCode_OP_CODE_LOAD:
		if ops := def.GetOperands(); len(ops) >= 1 {
			return leadingConst(ops[0], defs, next)
		}
	}
	return "", false
}

// leadingConstSeq concatenates the leading constant text across an ordered list of
// operands (left to right), stopping at the first operand that is not wholly
// constant.
func leadingConstSeq(operands []*ir.Value, defs map[string]*ir.Instruction, seen map[string]bool) (string, bool) {
	var b strings.Builder
	for _, op := range operands {
		t, c := leadingConst(op, defs, seen)
		b.WriteString(t)
		if !c {
			return b.String(), false
		}
	}
	return b.String(), true
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

func markSeen(seen map[string]bool, v *ir.Value) map[string]bool {
	next := make(map[string]bool, len(seen)+1)
	for k := range seen {
		next[k] = true
	}
	if reg := v.GetRegName(); reg != "" {
		next[reg] = true
	}
	return next
}

// constStr reads an operand's literal string value. Go lowers string constants
// via go/constant's quoted Stringer, so surrounding double quotes are stripped;
// other frontends store the raw literal (a no-op strip). Returns ok=false for a
// register or non-string operand, which cleanly distinguishes a constant piece
// from a tainted/dynamic one.
func constStr(v *ir.Value) (string, bool) {
	c := v.GetConstant()
	if c == nil {
		return "", false
	}
	if _, ok := c.Value.(*ir.Constant_StringVal); !ok {
		return "", false
	}
	s := c.GetStringVal()
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return s, true
}

// prefixBeforePlaceholder returns the literal text of a format template that
// precedes its first interpolation point — a printf verb (`%s`, `%v`, … but not
// the escaped `%%`) or a brace placeholder (`{`, but not the escaped `{{`).
func prefixBeforePlaceholder(tmpl string) string {
	for i := 0; i < len(tmpl); i++ {
		switch tmpl[i] {
		case '%':
			if i+1 < len(tmpl) && tmpl[i+1] == '%' {
				i++ // escaped %%
				continue
			}
			return tmpl[:i]
		case '{':
			if i+1 < len(tmpl) && tmpl[i+1] == '{' {
				i++ // escaped {{
				continue
			}
			return tmpl[:i]
		}
	}
	return tmpl
}
