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

func binOp(name string, kind ir.BinOpKind, ops ...*ir.Value) *ir.Instruction {
	return &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_BIN_OP, BinOp: kind, Operands: ops}
}

func callInst(name, callee string, args ...*ir.Value) *ir.Instruction {
	return &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_CALL, Call: &ir.CallCommon{Callee: callee, Args: args}}
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

func TestHostFixedRe(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"https://example.com/", true},      // host + path separator
		{"https://example.com/v1/", true},   // deeper path
		{"http://h:8080/", true},            // port
		{"http://h:8080?", true},            // query separator
		{"https://example.com#frag", true},  // fragment separator
		{"ftp://host/x", true},              // any scheme
		{"https://", false},                 // scheme only, no host yet
		{"https://example.com", false},      // no separator: taint could extend the host
		{"https://example.com:8080", false}, // still inside the authority
		{"//host/", false},                  // scheme-relative, no scheme
		{"", false},                         // empty
		{"/relative/path", false},           // path only
		{"api.example.com/", false},         // no scheme
		{"https://sub.", false},             // taint continues the authority
	}
	for _, c := range cases {
		if got := hostFixedRe.MatchString(c.in); got != c.want {
			t.Errorf("hostFixedRe(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// --- prefixBeforePlaceholder: literal text before the first interpolation ----

func TestPrefixBeforePlaceholder(t *testing.T) {
	cases := []struct{ tmpl, want string }{
		{"https://h/%s", "https://h/"},
		{"https://h/v1/%d", "https://h/v1/"},
		{"https://h/{}", "https://h/"},           // Rust/py brace placeholder
		{"https://h/{0}", "https://h/"},          // indexed brace
		{"https://h/static", "https://h/static"}, // no placeholder
		{"https://%s.h/", "https://"},            // taint starts in the host
		{"100%%-off://%s", "100%%-off://"},       // escaped %% is not a placeholder
		{"a{{b}}://{x}", "a{{b}}://"},            // escaped {{ is not a placeholder
	}
	for _, c := range cases {
		if got := prefixBeforePlaceholder(c.tmpl); got != c.want {
			t.Errorf("prefixBeforePlaceholder(%q) = %q, want %q", c.tmpl, got, c.want)
		}
	}
}

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
		tainted map[string]*ir.Position
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
			defs:    defsOf(callInst("u", "go:fmt.Sprintf", cstV("https://api.example.com/items/%s"), regV("t"))),
			tainted: taintedSet("u", "t"),
			want:    false,
		},
		{
			name:    "Sprintf host taint",
			defs:    defsOf(callInst("u", "go:fmt.Sprintf", cstV("https://%s.example.com/"), regV("t"))),
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
			name: "Rust add path-confined (to_owned(const) + deref(taint))",
			defs: defsOf(
				callInst("c", "rust:to_owned", cstV("https://api.example.com/v1/")),
				callInst("d", "rust:deref", regV("t")),
				callInst("u", "rust:add", regV("c"), regV("d")),
			),
			tainted: taintedSet("u", "d", "t"),
			want:    false,
		},
		{
			name: "Rust add host-controlled",
			defs: defsOf(
				callInst("c", "rust:to_owned", cstV("https://")),
				callInst("d", "rust:deref", regV("t")),
				callInst("u", "rust:add", regV("c"), regV("d")),
			),
			tainted: taintedSet("u", "d", "t"),
			want:    true,
		},
		{
			name: "Rust format! path-confined (deref->must_use->format->Arguments::new)",
			defs: defsOf(
				callInst("t", "rust:Arguments::new", cstV("https://api.example.com/v1/{}"), regV("args")),
				callInst("f", "rust:format", regV("t")),
				callInst("m", "rust:must_use", regV("f")),
				callInst("u", "rust:deref", regV("m")),
			),
			tainted: taintedSet("u", "m", "f", "t"),
			want:    false,
		},
		{
			name: "Rust format! host-controlled",
			defs: defsOf(
				callInst("t", "rust:Arguments::new", cstV("https://{}.example.com/v1/"), regV("args")),
				callInst("f", "rust:format", regV("t")),
				callInst("m", "rust:must_use", regV("f")),
				callInst("u", "rust:deref", regV("m")),
			),
			tainted: taintedSet("u", "m", "f", "t"),
			want:    true,
		},
		{
			name: "passthrough (deref) over a path-confined concat",
			defs: defsOf(
				binOp("a", ir.BinOpKind_BIN_OP_ADD, cstV("https://h/v1/"), regV("t")),
				callInst("u", "rust:deref", regV("a")),
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

// urlConstPrefix reconstructs the fixed prefix and reports whether the build was
// recognized well enough to trust it.
func TestURLConstPrefix(t *testing.T) {
	tests := []struct {
		name          string
		defs          map[string]*ir.Instruction
		wantPrefix    string
		wantRecovered bool
	}{
		{
			name:          "concat",
			defs:          defsOf(binOp("u", ir.BinOpKind_BIN_OP_ADD, cstV("https://h/v1/"), regV("t"))),
			wantPrefix:    "https://h/v1/",
			wantRecovered: true,
		},
		{
			name:          "sprintf",
			defs:          defsOf(callInst("u", "go:fmt.Sprintf", cstV("https://h/%s"), regV("t"))),
			wantPrefix:    "https://h/",
			wantRecovered: true,
		},
		{
			name:          "opaque (no def)",
			defs:          defsOf(),
			wantPrefix:    "",
			wantRecovered: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, recovered := urlConstPrefix(regV("u"), tt.defs, map[string]bool{})
			if prefix != tt.wantPrefix || recovered != tt.wantRecovered {
				t.Errorf("urlConstPrefix = %q,%v; want %q,%v", prefix, recovered, tt.wantPrefix, tt.wantRecovered)
			}
		})
	}
}
