package analysis

import (
	"maps"
	"slices"
	"strings"

	ir "godzilla/pkg/ir/v1"
)

// CallGraph is a whole-program call graph over gIR functions. The
// inter-procedural taint engine (interproc.go) consumes it for its reverse
// edges (see buildCallers): when a callee is discovered to return taint, every
// caller that calls it is re-enqueued so the new return summary propagates.
//
// Build one with BuildCallGraph.
type CallGraph struct {
	// Funcs indexes every function in the program by its CanonicalName
	// (e.g. "go:net/http.HandleFunc" or
	// "go:godzilla/test/go/sql_injection.main$1"). Functions with an empty
	// CanonicalName cannot be addressed by callers (gIR always sets it for
	// real converter output) and are skipped.
	Funcs map[string]*ir.Function

	// Edges maps a caller's CanonicalName to a sorted, de-duplicated list
	// of callee CanonicalNames. Every name appearing in Edges is guaranteed
	// to be a key in Funcs -- calls we could not resolve to a known function
	// (stdlib/external code that was never lowered to gIR, or a dynamic
	// dispatch with no known implementation) are simply dropped, so Edges
	// never dangles.
	Edges map[string][]string
}

// BuildCallGraph walks every module/function in prog and builds a
// whole-program CallGraph.
//
// Instruction scan: for every OP_CODE_CALL, OP_CODE_INVOKE, and
// OP_CODE_INTRINSIC instruction with a non-nil Call (INTRINSIC covers
// go.defer/go.goroutine, which also carry a CallCommon), the callee is
// resolved as follows:
//
//   - Direct call (Call.IsInvoke == false and Call.MethodName == ""):
//     Call.Callee is a statically-known canonical function name. If it
//     names a function we have gIR for, add a single edge to it; otherwise
//     the call is dropped (e.g. calls into net/http, fmt, etc., which this
//     converter does not lower).
//
//   - Dynamic dispatch (Call.IsInvoke == true, OR -- as a defensive
//     fallback for IR that records a method call without setting the
//     IsInvoke flag -- Call.MethodName != ""): resolved via a Class
//     Hierarchy Analysis (CHA) approximation. An edge is added to *every*
//     known function whose bare method name equals the call's method name.
//     A candidate function's bare method name is its MethodName field if
//     set, otherwise the substring of its CanonicalName after the final
//     '.' (so plain functions and methods are both eligible candidates).
//     This intentionally over-approximates: it will add edges between types
//     that both happen to implement a same-named method but never actually
//     satisfy a common interface at the call site. That's a deliberate
//     trade-off -- soundness (never missing a real edge) matters more than
//     precision for a caller-index primitive, and a real points-to analysis
//     is out of scope here.
//
// Everything else (Callee == "" and no method name, e.g. a call through an
// unresolved/dynamic value the converter couldn't name) is silently
// dropped.
func BuildCallGraph(prog *ir.Program) *CallGraph {
	g := &CallGraph{
		Funcs: map[string]*ir.Function{},
		Edges: map[string][]string{},
	}
	if prog == nil {
		return g
	}

	var allFuncs []*ir.Function
	for _, mod := range prog.Modules {
		if mod == nil {
			continue
		}
		for _, fn := range mod.Functions {
			if fn == nil || fn.CanonicalName == "" {
				continue
			}
			g.Funcs[fn.CanonicalName] = fn
			allFuncs = append(allFuncs, fn)
		}
	}

	// CHA index: bare method/function name -> known functions exposing it.
	methodIndex := map[string][]string{}
	for _, fn := range allFuncs {
		name := bareMethodName(fn)
		if name == "" {
			continue
		}
		methodIndex[name] = append(methodIndex[name], fn.CanonicalName)
	}

	edgeSets := map[string]map[string]bool{}

	for _, fn := range allFuncs {
		caller := fn.CanonicalName
		for _, blk := range fn.Blocks {
			if blk == nil {
				continue
			}
			for _, inst := range blk.Instrs {
				if inst == nil || inst.Call == nil {
					continue
				}
				switch inst.Op {
				case ir.OpCode_OP_CODE_CALL, ir.OpCode_OP_CODE_INVOKE, ir.OpCode_OP_CODE_INTRINSIC:
				default:
					continue
				}
				resolveCall(g, caller, inst.Call, methodIndex, edgeSets)
			}
		}
	}

	for caller, set := range edgeSets {
		g.Edges[caller] = sortedKeys(set)
	}

	return g
}

// resolveCall applies the resolution rules documented on BuildCallGraph for
// a single call site, recording resolved edges into edgeSets. Calls that
// resolve to no known function are dropped.
func resolveCall(
	g *CallGraph,
	caller string,
	call *ir.CallCommon,
	methodIndex map[string][]string,
	edgeSets map[string]map[string]bool,
) {
	dynamic := call.GetIsInvoke() || call.GetMethodName() != ""

	if dynamic {
		method := call.GetMethodName()
		if method == "" {
			method = trailingName(call.GetCallee())
		}
		if method == "" {
			return
		}
		for _, t := range methodIndex[method] {
			addToSet(edgeSets, caller, t)
		}
		return
	}

	callee := call.GetCallee()
	if callee == "" {
		return
	}
	if _, ok := g.Funcs[callee]; ok {
		addToSet(edgeSets, caller, callee)
	}
}

// bareMethodName returns the name a call site would need to match to treat
// fn as a CHA candidate: its MethodName if the frontend set one, otherwise
// the trailing "<Name>" segment of its CanonicalName.
func bareMethodName(fn *ir.Function) string {
	if fn.GetMethodName() != "" {
		return fn.GetMethodName()
	}
	return trailingName(fn.GetCanonicalName())
}

// trailingName returns the substring of name after the final '.', or name
// itself if there is no '.'. Used to derive a bare method/function name
// from a canonical name like "go:(*database/sql.DB).Query" -> "Query".
func trailingName(name string) string {
	if idx := strings.LastIndexByte(name, '.'); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

func addToSet(sets map[string]map[string]bool, key, value string) {
	set, ok := sets[key]
	if !ok {
		set = map[string]bool{}
		sets[key] = set
	}
	set[value] = true
}

func sortedKeys(set map[string]bool) []string {
	return slices.Sorted(maps.Keys(set))
}
