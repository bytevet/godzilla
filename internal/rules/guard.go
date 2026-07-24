package rules

import (
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// DynMarker is the placeholder Arg.String uses for a run of the argument that is
// not a compile-time constant (a tainted/dynamic segment): `"cmd:" + x`
// reconstructs to "cmd:<DYN>", a fully dynamic argument to "<DYN>". This encodes
// incompleteness into the string, so `arg[0].String startsWith "cmd:"` holds for
// a partial constant while `arg[0].String == "cmd:"` does not.
const DynMarker = "<DYN>"

// Arg is a call argument as a guard sees it: String is the argument's statically
// reconstructed value (constant runs verbatim, DynMarker for dynamic runs),
// Complete is true when the WHOLE argument is a compile-time constant, and Type
// is its static type ("string"/"int"/"float"/"bool", or "" if unknown).
type Arg struct {
	String   string
	Complete bool
	Type     string
}

// Guard is a compiled `when:` expression that decides whether a dynamic sink or
// callee fires, given the call's arguments as `arg[i]` (the i-th logical,
// receiver-excluded argument). It is standard expr-lang
// (https://expr-lang.org): a guard works on `arg[i].String` / `.Complete` /
// `.Type` with expr's native string operators and builtins — `startsWith`,
// `endsWith`, `contains`, `matches`, `in`, `==`, `hasPrefix`, `hasSuffix`, … A
// dynamic run is DynMarker, so an argument that cannot be confirmed fails an
// exact/prefix check and the entry is suppressed. Because DynMarker can be
// spanned by a wildcard regexp, combine `matches` with `.Complete` when an exact
// match matters. Compiled once at load.
type Guard struct {
	prog *vm.Program
	src  string
}

// guardEnv is the evaluation environment: `arg[i]` is the i-th logical argument.
type guardEnv struct {
	Arg []Arg `expr:"arg"`
}

// CompileGuard parses, type-checks, and compiles a `when:` expression. It returns
// an error for a syntax error, an unknown name, a non-boolean result, or an
// invalid constant regexp in `matches` (expr validates all of these at compile),
// so a bad guard fails `rules lint` at load rather than silently suppressing
// findings at scan time. An empty source yields (nil, nil): no guard.
func CompileGuard(src string) (*Guard, error) {
	if strings.TrimSpace(src) == "" {
		return nil, nil
	}
	prog, err := expr.Compile(src, expr.Env(guardEnv{}), expr.AsBool())
	if err != nil {
		return nil, fmt.Errorf("guard %q: %w", src, err)
	}
	return &Guard{prog: prog, src: src}, nil
}

// Eval reports whether the guard holds for the call's arguments. A nil guard
// always fires; a run error (e.g. an out-of-range arg index) is unconfirmed ->
// false (suppress).
func (g *Guard) Eval(args []Arg) bool {
	if g == nil {
		return true
	}
	out, err := expr.Run(g.prog, guardEnv{Arg: args})
	if err != nil {
		return false
	}
	b, _ := out.(bool)
	return b
}
