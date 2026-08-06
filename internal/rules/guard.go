package rules

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

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
// is its static type ("string"/"int"/"float"/"bool", the container kinds
// "aggregate"/"map", or "" if unknown).
type Arg struct {
	String   string
	Complete bool
	Type     string
	// Name is the keyword/named-argument name this argument was passed under
	// ("shell" for `subprocess.run(cmd, shell=True)`), or "" for a positional
	// argument or a language/frontend that does not record names. Without it a
	// guard can only see that SOME boolean argument is true, which cannot
	// distinguish the dangerous `shell=True` from an innocuous `check=True`.
	// Rules read it through `kwargs`, which indexes arguments by this name.
	Name string
	// Tainted reports whether this argument carries taint at the call, so a rule
	// can ask WHICH argument the untrusted value arrived in: in
	// `subprocess.run(["ls", name])` it is an argv element, not the command.
	// False where there is no taint state (a dangerous-call guard), so a rule
	// keying on it never suppresses there.
	Tainted bool
	// Elems are an in-place container's elements in order (Type "aggregate"):
	// `arg[0].Elems[0]` is argv[0] of `subprocess.run(["sh", "-c", cmd])`.
	// Entries is the keyed form (Type "map"), indexed by constant keys; a
	// computed key names nothing and is absent.
	//
	// Both are EMPTY when the structure was not reconstructed, indistinguishably
	// from "no elements" — so a rule must demand positive evidence before
	// suppressing, and see .TaintInChildren below.
	Elems   []Arg
	Entries map[string]Arg
	// TaintInChildren reports that reading Elems/Entries will actually find the
	// taint. A value can be Tainted with this FALSE — mutated after it was built
	// (`d = {}` then `d[k] = tainted`), taint in a non-constant key, built
	// elsewhere (`tainted.split(",")`), or never reconstructed — where walking the
	// children finds nothing and would wrongly read as safe.
	//
	// The polarity is deliberate: the zero value is "not accounted for", so a site
	// that forgets this field costs a spurious finding, not a silent miss.
	TaintInChildren bool
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
	// What the source actually mentions. A guard cannot observe a root it never
	// names, so anything it does not read is not worth building: kwargsOf
	// allocates a map per evaluation and container reconstruction walks the IR.
	usesKWArgs     bool
	needsStructure bool
}

// NeedsStructure reports whether the guard reads container structure, so a caller
// can skip reconstructing it. A nil guard reads nothing.
func (g *Guard) NeedsStructure() bool { return g != nil && g.needsStructure }

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
	// KWArgs indexes the same arguments by the keyword they were passed under,
	// so a rule reads `kwargs.shell.String == "true"` instead of scanning
	// `arg[i].Name` at an index it cannot know. Derived from Arg, so the engine
	// supplies nothing extra. A MISSING keyword yields the zero Arg rather than
	// an error (expr's map semantics), so `kwargs.shell.String == "true"` is
	// simply false on a call with no `shell=` — the safe reading, and what lets
	// a guard mention a keyword that is usually absent.
	KWArgs map[string]Arg `expr:"kwargs"`
	// hostFixed() with no argument asks about the sink's own injection points;
	// hostFixed(arg[i]) asks about one specific argument. See EvalHostFixed.
	HostFixed func(...Arg) bool `expr:"hostFixed"`
}

// kwargsOf indexes arguments by keyword name, skipping positional ones. The map
// is allocated lazily: most guarded calls are all-positional, so building an
// empty one on every evaluation is pure waste.
func kwargsOf(args []Arg) map[string]Arg {
	var m map[string]Arg
	for _, a := range args {
		if a.Name == "" {
			continue
		}
		if m == nil {
			m = make(map[string]Arg, len(args))
		}
		if _, dup := m[a.Name]; !dup {
			m[a.Name] = a
		}
	}
	return m
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
// builtin. The guard layer cannot compute it: deciding it needs the call's
// injection-point arguments, the current taint state, and the IR def map.
// Supplying it as a function keeps the *policy* — whether a rule suppresses on
// it — in the rule's `when:`, instead of the engine branching on a CWE string.
//
// It backs the ZERO-ARG form, which reuses the sink's own #idx pinning and is
// the one to prefer: the URL is not always argument 0 (requests.request pins #1)
// and some sinks take a request OBJECT rather than a URL string (net/http
// Client.Do), so restating the index risks checking the wrong argument.
//
// The explicit hostFixed(arg[i]) form (see ArgHostFixed) stays available for a
// rule that wants the check spelled out or needs a non-injection-point argument;
// it reads the skeleton directly and needs no engine state.
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
	// One source recurs across a pack. A Guard is immutable and an expr program
	// is safe to Run concurrently, so programs are shared. Errors are not cached.
	if g, ok := guardCache.Load(src); ok {
		return g.(*Guard), nil
	}
	prog, err := expr.Compile(src, expr.Env(guardEnv{}), expr.AsBool())
	if err != nil {
		return DenyGuard, fmt.Errorf("guard %q: %w", src, err)
	}
	g := &Guard{
		prog:       prog,
		usesKWArgs: strings.Contains(src, "kwargs"),
		needsStructure: strings.Contains(src, "Elems") || strings.Contains(src, "Entries") ||
			strings.Contains(src, "TaintInChildren"),
	}
	guardCache.Store(src, g)
	return g, nil
}

// guardCache memoizes compiled guards by source.
var guardCache sync.Map

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
	// Zero-arg defers to the engine fact (see EvalHostFixed); explicit args are
	// answered from the skeletons alone and must ALL be host-fixed.
	fn := func(as ...Arg) bool {
		if len(as) == 0 {
			if hostFixed == nil {
				return alwaysControllable()
			}
			return hostFixed()
		}
		for _, a := range as {
			if !ArgHostFixed(a) {
				return false
			}
		}
		return true
	}
	env := guardEnv{Arg: args, HostFixed: fn}
	if g.usesKWArgs {
		env.KWArgs = kwargsOf(args)
	}
	out, err := expr.Run(g.prog, env)
	if err != nil {
		return false
	}
	b, _ := out.(bool)
	return b
}
