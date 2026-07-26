package analysis

import (
	"testing"

	ir "godzilla/pkg/ir/v1"
)

// --- constructors ------------------------------------------------------------

func regV(name string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_RegName{RegName: name}}
}

func cstV(s string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: s}}}}
}

// boolV / intV build non-string constants, which reach a guard as literal text
// via constScalar (constSkeleton is string-only by design).
func boolV(b bool) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_BoolVal{BoolVal: b}}}}
}

func intV(n int64) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_IntVal{IntVal: n}}}}
}

func binOp(name string, kind ir.BinOpKind, ops ...*ir.Value) *ir.Instruction {
	return &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_BIN_OP, BinOp: kind, Operands: ops}
}

func callInst(name, callee string, args ...*ir.Value) *ir.Instruction {
	return &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_CALL, Call: &ir.CallCommon{Callee: callee, Args: args}}
}

// fmtInst builds a printf-style formatter call tagged with the language-neutral
// builtin.format marker (template in Args[0]), as the frontends now emit. The
// callee is retained for readability but the engine reads only the marker.
func fmtInst(name, callee string, args ...*ir.Value) *ir.Instruction {
	in := callInst(name, callee, args...)
	in.Intrinsic = "builtin.format"
	return in
}

// idInst builds an identity string-conversion call tagged with the
// builtin.identity marker (forwards Args[0]), as the frontends now emit.
func idInst(name, callee string, args ...*ir.Value) *ir.Instruction {
	in := callInst(name, callee, args...)
	in.Intrinsic = "builtin.identity"
	return in
}

func defsOf(insts ...*ir.Instruction) map[string]*ir.Instruction {
	m := map[string]*ir.Instruction{}
	for _, in := range insts {
		m[in.Name] = in
	}
	return m
}

func taintedSet(names ...string) map[string]*ir.Position {
	m := map[string]*ir.Position{}
	for _, n := range names {
		m[n] = &ir.Position{}
	}
	return m
}

// --- hostFixedRe: does the constant prefix pin a complete scheme://host/… ? ---

// --- prefixBeforePlaceholder: literal text before the first interpolation ----

// --- constStr: reads a string constant, stripping Go's surrounding quotes -----

func TestConstStr(t *testing.T) {
	if s, ok := constStr(cstV(`"https://h/"`)); !ok || s != "https://h/" {
		t.Errorf("constStr(quoted) = %q,%v; want %q,true", s, ok, "https://h/")
	}
	if s, ok := constStr(cstV("https://h/")); !ok || s != "https://h/" {
		t.Errorf("constStr(unquoted) = %q,%v; want %q,true", s, ok, "https://h/")
	}
	if _, ok := constStr(regV("t0")); ok {
		t.Errorf("constStr(register) = ok; want not ok")
	}
}

// --- urlHostControllable: the suppression decision across construction shapes -

func TestURLHostControllable(t *testing.T) {
	tests := []struct {
		name    string
		defs    map[string]*ir.Instruction
		tainted taintState
		// controllable == true  -> keep the finding (taint can reach the host)
		// controllable == false -> suppress (taint confined to a fixed host's path/query)
		want bool
	}{
		{
			name:    "concat path-confined (Go/JS +)",
			defs:    defsOf(binOp("u", ir.BinOpKind_BIN_OP_ADD, cstV("https://api.example.com/v1/"), regV("t"))),
			tainted: taintedSet("u", "t"),
			want:    false,
		},
		{
			name:    "concat host-controlled",
			defs:    defsOf(binOp("u", ir.BinOpKind_BIN_OP_ADD, cstV("https://"), regV("t"))),
			tainted: taintedSet("u", "t"),
			want:    true,
		},
		{
			name:    "direct source, no construction (client.get(taint))",
			defs:    defsOf(), // "u" has no def: opaque
			tainted: taintedSet("u"),
			want:    true,
		},
		{
			name:    "Sprintf path-confined",
			defs:    defsOf(fmtInst("u", "go:fmt.Sprintf", cstV("https://api.example.com/items/%s"), regV("t"))),
			tainted: taintedSet("u", "t"),
			want:    false,
		},
		{
			name:    "Sprintf host taint",
			defs:    defsOf(fmtInst("u", "go:fmt.Sprintf", cstV("https://%s.example.com/"), regV("t"))),
			tainted: taintedSet("u", "t"),
			want:    true,
		},
		{
			name:    "Python % path-confined",
			defs:    defsOf(binOp("u", ir.BinOpKind_BIN_OP_REM, cstV("https://api.example.com/%s"), regV("t"))),
			tainted: taintedSet("u", "t"),
			want:    false,
		},
		{
			// Rust `String + &str` concat lowers to BIN_OP_ADD (the frontend no
			// longer emits a rust:add call), so reconstruction is the shared path.
			name: "Rust concat path-confined (to_owned(const) + deref(taint))",
			defs: defsOf(
				idInst("c", "rust:to_owned", cstV("https://api.example.com/v1/")),
				idInst("d", "rust:deref", regV("t")),
				binOp("u", ir.BinOpKind_BIN_OP_ADD, regV("c"), regV("d")),
			),
			tainted: taintedSet("u", "d", "t"),
			want:    false,
		},
		{
			name: "Rust concat host-controlled",
			defs: defsOf(
				idInst("c", "rust:to_owned", cstV("https://")),
				idInst("d", "rust:deref", regV("t")),
				binOp("u", ir.BinOpKind_BIN_OP_ADD, regV("c"), regV("d")),
			),
			tainted: taintedSet("u", "d", "t"),
			want:    true,
		},
		{
			name: "Rust format! path-confined (deref->must_use->format->Arguments::new)",
			defs: defsOf(
				fmtInst("t", "rust:Arguments::new", cstV("https://api.example.com/v1/{}"), regV("args")),
				idInst("f", "rust:format", regV("t")),
				idInst("m", "rust:must_use", regV("f")),
				idInst("u", "rust:deref", regV("m")),
			),
			tainted: taintedSet("u", "m", "f", "t"),
			want:    false,
		},
		{
			name: "Rust format! host-controlled",
			defs: defsOf(
				fmtInst("t", "rust:Arguments::new", cstV("https://{}.example.com/v1/"), regV("args")),
				idInst("f", "rust:format", regV("t")),
				idInst("m", "rust:must_use", regV("f")),
				idInst("u", "rust:deref", regV("m")),
			),
			tainted: taintedSet("u", "m", "f", "t"),
			want:    true,
		},
		{
			name: "passthrough (deref) over a path-confined concat",
			defs: defsOf(
				binOp("a", ir.BinOpKind_BIN_OP_ADD, cstV("https://h/v1/"), regV("t")),
				idInst("u", "rust:deref", regV("a")),
			),
			tainted: taintedSet("u", "a", "t"),
			want:    false,
		},
		{
			name:    "untainted injectable is ignored (no finding to suppress)",
			defs:    defsOf(binOp("u", ir.BinOpKind_BIN_OP_ADD, cstV("https://h/"), regV("t"))),
			tainted: taintedSet(), // nothing tainted
			want:    false,        // no tainted arg -> not controllable
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := urlHostControllable([]*ir.Value{regV("u")}, tt.tainted, tt.defs)
			if got != tt.want {
				t.Errorf("urlHostControllable = %v, want %v", got, tt.want)
			}
		})
	}
}
