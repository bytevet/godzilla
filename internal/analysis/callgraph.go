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

// BuildCallGraph builds a whole-program CallGraph from every CALL, INVOKE, and
// INTRINSIC-with-a-Call instruction (the latter covers go.defer/go.goroutine).
//
//   - A direct call (not IsInvoke, no MethodName) resolves through Call.Callee,
//     adding one edge if we have gIR for that function and dropping it otherwise
//     — calls into net/http, fmt and the rest of the unlowered stdlib.
//
//   - Dynamic dispatch (IsInvoke, or MethodName set as a defensive fallback for
//     IR that records a method call without the flag) resolves by Class
//     Hierarchy Analysis: an edge to every known function whose bare name — its
//     MethodName, else the tail of its CanonicalName after the final '.' —
//     equals the call's method name. This over-approximates on purpose, linking
//     types that share a method name without sharing an interface: for a
//     caller-index primitive, never missing a real edge beats precision, and a
//     points-to analysis is out of scope.
//
// A call naming neither (an unresolved dynamic value) is dropped.
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
	// Dynamic dispatch is signalled by the converter (IsInvoke). A statically
	// resolved method call also names its method (MethodName set) but resolves to
	// a precise callee, so it is NOT dynamic — routing it through CHA would add
	// spurious edges. (Method-bearing Functions still enter methodIndex via
	// bareMethodName below, which is how a real INVOKE finds its implementers.)
	if call.GetIsInvoke() {
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
