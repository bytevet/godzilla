package analysis

import (
	"strings"
	"testing"

	go_converter "godzilla/converters/go"
	ir "godzilla/pkg/ir/v1"
)

// convertSQLInjectionSampleForCallGraph loads and converts the sql_injection
// sample used elsewhere in this package's tests (see taint_test.go's
// convertSQLInjectionSample) into a gIR Program, dedicated to the call-graph
// tests so this file has no compile-time dependency on taint.go/taint_test.go.
func convertSQLInjectionSampleForCallGraph(t *testing.T) *ir.Program {
	t.Helper()
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/sql_injection/main.go")
	if err != nil {
		t.Fatalf("failed to convert sql_injection sample: %v", err)
	}
	if prog == nil {
		t.Fatal("converted program is nil")
	}
	return prog
}

// findFuncByObjectName returns the first function in g.Funcs whose
// ObjectName matches, or nil if none does.
func findFuncByObjectName(g *CallGraph, objectName string) *ir.Function {
	for _, fn := range g.Funcs {
		if fn.GetObjectName() == objectName {
			return fn
		}
	}
	return nil
}

func TestBuildCallGraph_SQLInjectionSample(t *testing.T) {
	prog := convertSQLInjectionSampleForCallGraph(t)
	g := BuildCallGraph(prog)

	if len(g.Funcs) == 0 {
		t.Fatal("expected a non-empty Funcs map")
	}

	mainFn := findFuncByObjectName(g, "main")
	if mainFn == nil {
		t.Fatal("expected to find a function with ObjectName == \"main\"")
	}

	// main() calls http.HandleFunc(...) directly. net/http itself is
	// stdlib code the converter never lowers, so it can't be a key in
	// Funcs; per the documented design (see BuildCallGraph), such calls
	// are recorded in Unresolved rather than Edges (which only ever
	// contains resolvable, known-function targets). Check the union of
	// both so this test holds regardless of which set a given callee
	// lands in.
	callees := append(append([]string{}, g.Edges[mainFn.CanonicalName]...), g.Unresolved[mainFn.CanonicalName]...)
	foundHandleFunc := false
	for _, callee := range callees {
		if strings.Contains(callee, "net/http") && strings.Contains(callee, "HandleFunc") {
			foundHandleFunc = true
			break
		}
	}
	if !foundHandleFunc {
		t.Errorf("expected main (%s) to have a recorded call to a net/http.HandleFunc-ish callee, got edges=%v unresolved=%v",
			mainFn.CanonicalName, g.Edges[mainFn.CanonicalName], g.Unresolved[mainFn.CanonicalName])
	}

	// The vulnerable handler closure (SSA name main$1) must be present as
	// its own function in the call graph, even though nothing in the IR
	// directly calls it (it's passed by value to http.HandleFunc).
	foundClosure := false
	for name := range g.Funcs {
		if strings.Contains(name, "main$1") {
			foundClosure = true
			break
		}
	}
	if !foundClosure {
		t.Fatalf("expected a function whose CanonicalName contains \"main$1\", got funcs: %v", funcNames(g))
	}
}

func TestCallGraph_RootsIncludeHandlerClosure(t *testing.T) {
	prog := convertSQLInjectionSampleForCallGraph(t)
	g := BuildCallGraph(prog)

	roots := g.Roots()
	if len(roots) == 0 {
		t.Fatal("expected a non-empty root set")
	}

	reachable := g.Reachable(roots)

	found := false
	for name := range reachable {
		if strings.Contains(name, "main$1") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Reachable(Roots()) to include the handler closure (main$1); roots=%v reachable=%v",
			roots, keysOf(reachable))
	}
}

// TestCallGraph_Reachable_BasicBFS is a small, self-contained sanity check
// of the BFS/reachability primitive independent of the real converter, so a
// regression in BFS logic doesn't hide behind converter/CHA behavior.
func TestCallGraph_Reachable_BasicBFS(t *testing.T) {
	g := &CallGraph{
		Funcs: map[string]*ir.Function{
			"a": {CanonicalName: "a"},
			"b": {CanonicalName: "b"},
			"c": {CanonicalName: "c"},
			"d": {CanonicalName: "d"}, // unreachable from "a"
		},
		Edges: map[string][]string{
			"a": {"b"},
			"b": {"c"},
		},
	}

	got := g.Reachable([]string{"a"})
	want := map[string]bool{"a": true, "b": true, "c": true}
	if len(got) != len(want) {
		t.Fatalf("Reachable(%v) = %v, want %v", []string{"a"}, keysOf(got), keysOf(want))
	}
	for k := range want {
		if !got[k] {
			t.Errorf("expected %q to be reachable, got %v", k, keysOf(got))
		}
	}
	if got["d"] {
		t.Errorf("did not expect %q to be reachable", "d")
	}
}

// TestCallGraph_CHA_DynamicDispatch verifies the documented CHA
// over-approximation: an INVOKE call resolves to every known function
// sharing the invoked bare method name, not just the "real" target.
func TestCallGraph_CHA_DynamicDispatch(t *testing.T) {
	caller := &ir.Function{
		CanonicalName: "go:example.caller",
		Blocks: []*ir.BasicBlock{{Instrs: []*ir.Instruction{
			{
				Op: ir.OpCode_OP_CODE_INVOKE,
				Call: &ir.CallCommon{
					IsInvoke:   true,
					MethodName: "Close",
					Callee:     "go:(io.Closer).Close",
				},
			},
		}}},
	}
	implA := &ir.Function{CanonicalName: "go:example.(*A).Close", MethodName: "Close"}
	implB := &ir.Function{CanonicalName: "go:example.(*B).Close", MethodName: "Close"}
	unrelated := &ir.Function{CanonicalName: "go:example.Unrelated"}

	prog := &ir.Program{Modules: []*ir.Module{{
		Language:  "go",
		Functions: []*ir.Function{caller, implA, implB, unrelated},
	}}}

	g := BuildCallGraph(prog)
	edges := g.Edges[caller.CanonicalName]
	if len(edges) != 2 || edges[0] != implA.CanonicalName || edges[1] != implB.CanonicalName {
		t.Fatalf("expected CHA edges to both Close implementations, got %v", edges)
	}
}

func funcNames(g *CallGraph) []string {
	names := make([]string, 0, len(g.Funcs))
	for name := range g.Funcs {
		names = append(names, name)
	}
	return names
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
