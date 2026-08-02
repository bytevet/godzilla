package rules

import (
	"fmt"
	"regexp"
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
	Arg []Arg `expr:"arg"`
	// hostFixed() with no argument asks about the sink's own injection points;
	// hostFixed(arg[i]) asks about one specific argument. See EvalHostFixed.
	HostFixed func(...Arg) bool `expr:"hostFixed"`
	// argvList() answers whether the tainted injection point arrives as an
	// in-place argument LIST with no shell interpreter. See EvalArgvList.
	ArgvList func() bool `expr:"argvList"`
}

// hostFixedRe matches a constant prefix that already pins a complete
// scheme://authority followed by a path/query/fragment separator, so anything
// after it lands in the path or query and cannot redirect the request.
// "https://example.com/" matches; "https://" (no host yet) and
// "https://example.com" (taint could extend the host) do not.
var hostFixedRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/?#\\]+[/?#\\]`)

// ArgHostFixed reports whether one argument's reconstructed value pins a constant
// scheme://host before its first dynamic run. It reads the skeleton alone -- the
// text up to DynMarker IS the constant prefix -- so the explicit hostFixed(arg[i])
// form needs no engine state. An argument that is entirely dynamic reconstructs to
// DynMarker, leaving an empty prefix that cannot match: unrecoverable constructions
// stay "controllable" and keep firing.
func ArgHostFixed(a Arg) bool {
	s := a.String
	if i := strings.Index(s, DynMarker); i >= 0 {
		s = s[:i]
	}
	return hostFixedRe.MatchString(s)
}

// EvalHostFixed is the engine-supplied fact behind the `hostFixed()` guard
// builtin. It is a FACT the guard layer cannot compute for itself: deciding it
// needs the call's injection-point arguments, the current taint state, and the IR
// def map. Supplying it as a function keeps the *policy* -- whether a rule should
// suppress on it -- in the rule's `when:` expression, instead of the engine
// branching on a rule's CWE string.
//
// This backs the ZERO-ARG form, which reuses the sink's own #idx pinning and is
// the one to prefer: the URL is not always argument 0 (requests.request pins #1)
// and some sinks take a request OBJECT rather than a URL string (net/http
// Client.Do), so restating the index in the guard risks checking the wrong
// argument -- the HTTP method instead of the URL -- if the two ever disagree.
//
// The explicit hostFixed(arg[i]) form (see ArgHostFixed) stays available for rules
// that want the check spelled out or need an argument that is not an injection
// point; it reads the skeleton directly and needs no engine state.
type EvalHostFixed func() bool

// alwaysControllable is the default when no engine fact is supplied (e.g. a
// dangerous-call guard, which has no taint state). It reports NOT host-fixed, so
// `not hostFixed()` holds and the entry fires -- failing open, never silently
// suppressing.
func alwaysControllable() bool { return false }

// EvalArgvList is the engine-supplied fact behind the `argvList()` guard
// builtin: the tainted value reaches the sink's injection point as a container
// CONSTRUCTED IN PLACE (builtin.aggregate) and the call passes no truthy
// `shell=` keyword -- i.e. `subprocess.run(["ls", "-la", name])`, where the
// tainted element is an argv entry handed to execve, not shell-interpreted.
//
// Like hostFixed, it is a fact the guard layer cannot compute for itself: it
// needs the injection-point arguments, the taint state and the IR def map. The
// POLICY -- that command injection should suppress on it -- stays in the rule's
// `when:` rather than the engine branching on a CWE string.
//
// Python's frontend lowers every container literal to builtin.aggregate so that
// element taint survives into a later whole-container use; this fact is what
// keeps that from turning the safe argv form into a false positive.
type EvalArgvList func() bool

// Facts are the engine-supplied answers a `when:` expression may consult. A nil
// field fails OPEN -- the fact reads as "dangerous", so the entry still fires
// rather than being silently suppressed. Named fields (rather than positional
// func() bool parameters) keep two same-typed facts from being swapped at a
// call site.
type Facts struct {
	HostFixed EvalHostFixed
	ArgvList  EvalArgvList
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
		return DenyGuard, fmt.Errorf("guard %q: %w", src, err)
	}
	return &Guard{prog: prog}, nil
}

// Eval reports whether the guard holds for the call's arguments. A nil guard
// (no `when:`) always fires; DenyGuard never does; a run error (e.g. an
// out-of-range arg index) is unconfirmed -> false (suppress).
func (g *Guard) Eval(args []Arg) bool { return g.EvalWith(args, Facts{}) }

// EvalWith is Eval with the engine's optional facts supplied. Any nil fact fails
// open: hostFixed reads as not-host-fixed and argvList as not-an-argv-list, so a
// missing fact never silently suppresses an entry.
func (g *Guard) EvalWith(args []Arg, facts Facts) bool {
	if g == nil {
		return true
	}
	if g.prog == nil {
		return false // DenyGuard
	}
	// Zero-arg defers to the engine fact (see EvalHostFixed); explicit args are
	// answered from the skeletons alone and must ALL be host-fixed.
	fn := func(as ...Arg) bool {
		if len(as) == 0 {
			if facts.HostFixed == nil {
				return alwaysControllable()
			}
			return facts.HostFixed()
		}
		for _, a := range as {
			if !ArgHostFixed(a) {
				return false
			}
		}
		return true
	}
	argv := func() bool {
		if facts.ArgvList == nil {
			return false // fail open: not an argv list, so the entry still fires
		}
		return facts.ArgvList()
	}
	out, err := expr.Run(g.prog, guardEnv{Arg: args, HostFixed: fn, ArgvList: argv})
	if err != nil {
		return false
	}
	b, _ := out.(bool)
	return b
}
