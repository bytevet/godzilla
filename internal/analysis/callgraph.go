package analysis

import (
	"sort"
	"strings"

	ir "godzilla/pkg/ir/v1"
)

// CallGraph is a whole-program call graph over gIR functions. It is the
// foundation for inter-procedural taint analysis (Phase 3): the taint
// engine in taint.go is intra-procedural today, and needs a call graph to
// (a) know which function to jump into when a call's arguments are tainted,
// and (b) tree-shake the program down to code reachable from a set of
// entrypoints before running the (much more expensive) inter-procedural
// analysis.
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
	// to be a key in Funcs -- calls we could not resolve to a known
	// function (stdlib/external code that was never lowered to gIR, or a
	// dynamic dispatch with no known implementation) are recorded in
	// Unresolved instead, so Edges/Reachable never dangle.
	Edges map[string][]string

	// Unresolved maps a caller's CanonicalName to a sorted, de-duplicated
	// list of callee identifiers that could not be resolved to a function
	// in Funcs. For direct calls this is the raw Callee string (e.g. a
	// stdlib function we don't have gIR for); for dynamic dispatch with no
	// matching implementation anywhere in the program it is
	// "invoke:<bareMethodName>". This is purely informational/diagnostic
	// (e.g. for auditing "what external API surface does this program
	// touch") and is not consulted by Reachable.
	Unresolved map[string][]string

	// inEdges is derived bookkeeping (which functions are the target of at
	// least one edge) used by Roots. It is not part of the public
	// contract, so it is unexported.
	inEdges map[string]bool
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
//     record it in Unresolved (e.g. calls into net/http, fmt, etc., which
//     this converter does not lower).
//
//   - Dynamic dispatch (Call.IsInvoke == true, OR -- as a defensive
//     fallback for IR that records a method call without setting the
//     IsInvoke flag -- Call.MethodName != ""): resolved via a Class
//     Hierarchy Analysis (CHA) approximation. An edge is added to *every*
//     known function whose bare method name equals the call's method name.
//     A candidate function's bare method name is its MethodName field if
//     set, otherwise the substring of its CanonicalName after the final
//     '.' (so plain functions and methods are both eligible candidates,
//     matching the instructions for this task). This intentionally
//     over-approximates: it will add edges between types that both happen
//     to implement a same-named method but never actually satisfy a common
//     interface at the call site. That's a deliberate, documented
//     trade-off -- soundness (never missing a real edge) matters more than
//     precision for a reachability/tree-shaking primitive, and a real
//     points-to analysis is out of scope here.
//
// Everything else (Callee == "" and no method name, e.g. a call through an
// unresolved/dynamic value the converter couldn't name) is silently
// dropped.
func BuildCallGraph(prog *ir.Program) *CallGraph {
	g := &CallGraph{
		Funcs:      map[string]*ir.Function{},
		Edges:      map[string][]string{},
		Unresolved: map[string][]string{},
		inEdges:    map[string]bool{},
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
	unresolvedSets := map[string]map[string]bool{}

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
				resolveCall(g, caller, inst.Call, methodIndex, edgeSets, unresolvedSets)
			}
		}
	}

	for caller, set := range edgeSets {
		targets := sortedKeys(set)
		g.Edges[caller] = targets
		for _, t := range targets {
			g.inEdges[t] = true
		}
	}
	for caller, set := range unresolvedSets {
		g.Unresolved[caller] = sortedKeys(set)
	}

	return g
}

// resolveCall applies the resolution rules documented on BuildCallGraph for
// a single call site, recording the outcome into edgeSets/unresolvedSets.
func resolveCall(
	g *CallGraph,
	caller string,
	call *ir.CallCommon,
	methodIndex map[string][]string,
	edgeSets map[string]map[string]bool,
	unresolvedSets map[string]map[string]bool,
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
		targets := methodIndex[method]
		if len(targets) == 0 {
			addToSet(unresolvedSets, caller, "invoke:"+method)
			return
		}
		for _, t := range targets {
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
	} else {
		addToSet(unresolvedSets, caller, callee)
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
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Reachable returns the set of CanonicalNames reachable from roots by
// following Edges (a plain BFS), including the roots themselves. This is
// the tree-shaking primitive: everything not in the returned set is dead
// code with respect to the given entrypoints and can be excluded from
// further (more expensive) inter-procedural analysis.
func (g *CallGraph) Reachable(roots []string) map[string]bool {
	visited := map[string]bool{}
	if g == nil {
		return visited
	}

	queue := make([]string, 0, len(roots))
	for _, r := range roots {
		if !visited[r] {
			visited[r] = true
			queue = append(queue, r)
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range g.Edges[cur] {
			if !visited[next] {
				visited[next] = true
				queue = append(queue, next)
			}
		}
	}

	return visited
}

// Roots returns a reasonable default set of program entrypoints:
//
//   - Every function whose ObjectName is "main" or "init" (the obvious
//     process entrypoints in Go).
//   - Every function that has no in-edges anywhere in the call graph.
//     This catches functions invoked by code we don't model in gIR --
//     most importantly closures/handlers registered with the runtime or
//     an external framework (e.g. the closure literal passed to
//     http.HandleFunc in the sql_injection sample: nothing in the IR
//     *calls* that closure, an external HTTP server does, so without this
//     rule it would look like dead code and Reachable would tree-shake it
//     away). It equally catches exported API functions, test functions,
//     etc. -- anything only ever invoked from outside the converted
//     program.
//
// The returned slice is sorted for deterministic output.
func (g *CallGraph) Roots() []string {
	if g == nil {
		return nil
	}

	set := map[string]bool{}
	for name, fn := range g.Funcs {
		if fn == nil {
			continue
		}
		if obj := fn.GetObjectName(); obj == "main" || obj == "init" {
			set[name] = true
			continue
		}
		if !g.inEdges[name] {
			set[name] = true
		}
	}

	return sortedKeys(set)
}
