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
	// Name is the keyword/named-argument name this argument was passed under
	// ("shell" for `subprocess.run(cmd, shell=True)`), or "" for a positional
	// argument or a language/frontend that does not record names. Without it a
	// guard can only see that SOME boolean argument is true, which cannot
	// distinguish the dangerous `shell=True` from an innocuous `check=True` —
	// so a config-flag rule matches on `.Name` together with `.String`.
	Name string
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
}

// DenyGuard never fires. It stands in for a guard that could not be compiled or
// is unavailable, so a malformed/unusable `when:` SUPPRESSES its entry instead of
// degrading to "no guard" (which would fire unconditionally — the very
// false-positive the guard exists to prevent). Fail closed, never open.
var DenyGuard = &Guard{}

// guardEnv is the evaluation environment: `arg[i]` is the i-th logical argument,
// and `hostFixed()` answers whether every tainted injection-point argument is
// confined to the path/query of a constant scheme://host.
type guardEnv struct {
	Arg       []Arg       `expr:"arg"`
	HostFixed func() bool `expr:"hostFixed"`
}

// EvalHostFixed is the engine-supplied fact behind the `hostFixed()` guard
// builtin. It is a FACT the guard layer cannot compute for itself: deciding it
// needs the call's injection-point arguments, the current taint state, and the IR
// def map. Supplying it as a function keeps the *policy* -- whether a rule should
// suppress on it -- in the rule's `when:` expression, instead of the engine
// branching on a rule's CWE string.
//
// It is deliberately zero-arg rather than hostFixed(arg[i]): the URL is not always
// argument 0 (requests.request pins #1) and some sinks take a request OBJECT
// rather than a URL string (net/http Client.Do), so making the rule author restate
// the index would silently misfire. Zero-arg reuses the sink's own #idx pinning.
type EvalHostFixed func() bool

// alwaysControllable is the default when no engine fact is supplied (e.g. a
// dangerous-call guard, which has no taint state). It reports NOT host-fixed, so
// `not hostFixed()` holds and the entry fires -- failing open, never silently
// suppressing.
func alwaysControllable() bool { return false }

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
		return DenyGuard, fmt.Errorf("guard %q: %w", src, err)
	}
	return &Guard{prog: prog}, nil
}

// Eval reports whether the guard holds for the call's arguments. A nil guard
// (no `when:`) always fires; DenyGuard never does; a run error (e.g. an
// out-of-range arg index) is unconfirmed -> false (suppress).
func (g *Guard) Eval(args []Arg) bool { return g.EvalWith(args, nil) }

// EvalWith is Eval with the engine's optional facts supplied. hostFixed may be
// nil, in which case the guard sees a not-host-fixed answer (fail open).
func (g *Guard) EvalWith(args []Arg, hostFixed EvalHostFixed) bool {
	if g == nil {
		return true
	}
	if g.prog == nil {
		return false // DenyGuard
	}
	if hostFixed == nil {
		hostFixed = alwaysControllable
	}
	out, err := expr.Run(g.prog, guardEnv{Arg: args, HostFixed: hostFixed})
	if err != nil {
		return false
	}
	b, _ := out.(bool)
	return b
}
