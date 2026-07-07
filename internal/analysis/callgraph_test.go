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

	if findFuncByObjectName(g, "main") == nil {
		t.Fatal("expected to find a function with ObjectName == \"main\"")
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
