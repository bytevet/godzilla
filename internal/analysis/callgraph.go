package analysis

import (
	"github.com/bytevet/godzilla/internal/irwalk"
	"maps"
	"slices"
	"strings"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// CallGraph is a whole-program call graph over gIR functions. The
// inter-procedural taint engine (interproc.go) consumes it for its reverse
// edges (see buildCallers): when a callee is discovered to return taint, every
// caller that calls it is re-enqueued so the new return summary propagates.
//
// Build one with buildCallGraph, over the shared function/method indexes
// (buildFuncIndex, buildMethodImpls).
type CallGraph struct {
	// Funcs indexes every function in the program by its CanonicalName. A function
	// with an empty one gets a unique "__local<N>" fallback key so it is still
	// analyzed intra-procedurally. This is the ONE name->function index, shared
	// with Analyze (see buildFuncIndex).
	Funcs map[string]*ir.Function

	// Edges maps a caller's CanonicalName to a sorted, de-duplicated list
	// of callee names. Every name appearing in Edges is guaranteed to be a
	// key in Funcs -- calls we could not resolve to a known function
	// (stdlib/external code that was never lowered to gIR, or a dynamic
	// dispatch with no known implementation) are simply dropped, so Edges
	// never dangles. A "__local<N>"-keyed function is not addressable by
	// callers, so it never appears as an Edges key.
	Edges map[string][]string

	// Callees is the set of DISTINCT callee names this program calls, including the
	// unresolved ones Edges drops (unlowered stdlib, dynamic dispatch). The engine
	// uses it to skip a rule whose sink globs match nothing the program calls; it
	// is collected here rather than by a separate walk because this pass already
	// visits every instruction, and a second walk cost more than the skipping saved.
	Callees map[string]bool
}

// buildCallGraph builds a whole-program CallGraph from every CALL, INVOKE, and
// INTRINSIC-with-a-Call instruction (the latter covers go.defer/go.goroutine),
// over the prebuilt function index (buildFuncIndex) and CHA method index
// (buildMethodImpls) Analyze passes in — one index, one policy, for both
// consumers.
//
//   - A direct call resolves through Call.Callee, adding one edge if we have gIR
//     for that function and dropping it otherwise (the unlowered stdlib).
//
//   - Dynamic dispatch (IsInvoke) resolves by Class Hierarchy Analysis over the
//     same bare-method-name index the engine's INVOKE dispatch uses: an edge to
//     every known function whose Function.method_name matches. This
//     over-approximates on purpose, linking types that share a method name without
//     sharing an interface — for a caller-index primitive, never missing a real
//     edge beats precision, and a points-to analysis is out of scope.
//
// A call naming neither (an unresolved dynamic value) is dropped.
func buildCallGraph(byKey map[string]*ir.Function, methodImpls map[string][]string) *CallGraph {
	g := &CallGraph{
		Funcs:   byKey,
		Edges:   map[string][]string{},
		Callees: map[string]bool{},
	}

	edgeSets := map[string]map[string]bool{}

	for _, fn := range byKey {
		caller := fn.CanonicalName
		for inst := range irwalk.Instrs(fn) {
			if inst.Call == nil {
				continue
			}
			// Collect callees for EVERY function, including the "__local<N>"-keyed
			// ones excluded as callers below: they are still analyzed, so a sink
			// inside one must keep its rule from being prefiltered away.
			g.Callees[inst.Call.GetCallee()] = true
			if caller == "" {
				continue
			}
			switch inst.Op {
			case ir.OpCode_OP_CODE_CALL, ir.OpCode_OP_CODE_INVOKE, ir.OpCode_OP_CODE_INTRINSIC:
			default:
				continue
			}
			resolveCall(g, caller, inst.Call, methodImpls, edgeSets)
		}
	}

	for caller, set := range edgeSets {
		g.Edges[caller] = sortedKeys(set)
	}

	return g
}

// resolveCall applies the resolution rules documented on buildCallGraph for
// a single call site, recording resolved edges into edgeSets. Calls that
// resolve to no known function are dropped.
func resolveCall(
	g *CallGraph,
	caller string,
	call *ir.CallCommon,
	methodImpls map[string][]string,
	edgeSets map[string]map[string]bool,
) {
	// Dynamic dispatch is signalled by the converter (IsInvoke). A statically
	// resolved method call also names its method (MethodName set) but resolves to
	// a precise callee, so it is NOT dynamic — routing it through CHA would add
	// spurious edges. (Method-bearing Functions still enter methodImpls, which is
	// how a real INVOKE finds its implementers.)
	if call.GetIsInvoke() {
		method := call.GetMethodName()
		if method == "" {
			method = trailingName(call.GetCallee())
		}
		if method == "" {
			return
		}
		for _, t := range methodImpls[method] {
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

// trailingName returns the substring of name after the final '.', or name
// itself if there is no '.'. Used to derive a bare method name from an INVOKE
// call site whose converter set a Callee like "go:(io.Closer).Close" but no
// MethodName — a call-site fallback only. The FUNCTION side of the CHA index
// never parses a canonical name: a frontend marks its methods with
// Function.method_name, the engine contract (see buildMethodImpls).
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
