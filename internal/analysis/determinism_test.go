package analysis

import (
	"slices"
	"testing"

	go_converter "github.com/bytevet/godzilla/converters/go"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// The engine's worklist order decides which cross-function summary is recorded
// first, and every summary channel is first-seen-wins, so an index built by
// ranging over a map made a scan's finding count vary run to run (a 4x swing on a
// real project). Each index below is therefore sorted at construction; these tests
// pin that, because the symptom of losing it is a flaky number, not a failure.

func assertSorted(t *testing.T, what string, m map[string][]string) {
	t.Helper()
	for k, v := range m {
		if !slices.IsSorted(v) {
			t.Errorf("%s[%q] is not sorted: %v", what, k, v)
		}
	}
}

func TestSharedIndexesAreSorted(t *testing.T) {
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/sql_injection/main.go")
	if err != nil {
		t.Fatalf("convert sample: %v", err)
	}
	byKey, _ := buildFuncIndex(prog)
	impls := buildMethodImpls(byKey)
	assertSorted(t, "methodImpls", impls)
	assertSorted(t, "callers", buildCallers(buildCallGraph(byKey, impls)))
	assertSorted(t, "globalReaders", buildGlobalReaders(byKey))
}

// TestStringParamOriginsAllMatches pins the contract that made the worklist
// deterministic: one origin can seed SEVERAL parameters — a call site passing the
// same tainted value twice, `f(x, x)` — and every string one is returned, in
// ascending order. Returning just one had no deterministic answer to return.
func TestStringParamOriginsAllMatches(t *testing.T) {
	str := &ir.Type{Kind: ir.TypeKind_TYPE_KIND_BASIC, BasicKind: ir.BasicTypeKind_BASIC_TYPE_KIND_STRING}
	num := &ir.Type{Kind: ir.TypeKind_TYPE_KIND_BASIC, BasicKind: ir.BasicTypeKind_BASIC_TYPE_KIND_INT}
	fn := &ir.Function{Signature: &ir.Signature{Params: []*ir.Type{str, num, str}}}

	origin := &ir.Position{Filename: "a.go", Line: 7}
	other := &ir.Position{Filename: "a.go", Line: 9}
	seeds := paramPositions{0: origin, 1: origin, 2: origin, 3: other}

	// Param 1 is an int and param 3 carries a different origin, so neither is a
	// wrapper parameter for this flow.
	if got := stringParamOrigins(fn, seeds, origin); !slices.Equal(got, []int{0, 2}) {
		t.Errorf("stringParamOrigins = %v, want [0 2]", got)
	}
	if got := stringParamOrigins(fn, paramPositions{1: origin}, origin); len(got) != 0 {
		t.Errorf("a non-string parameter must not be summarized, got %v", got)
	}
	if got := stringParamOrigins(fn, seeds, &ir.Position{}); len(got) != 0 {
		t.Errorf("an unseeded origin must match nothing, got %v", got)
	}
}

// A method's receiver occupies fn.Params[0] but is absent from Signature.Params,
// so the index has to shift — and the receiver itself is never a wrapper param.
func TestStringParamOriginsSkipsReceiver(t *testing.T) {
	str := &ir.Type{Kind: ir.TypeKind_TYPE_KIND_BASIC, BasicKind: ir.BasicTypeKind_BASIC_TYPE_KIND_STRING}
	fn := &ir.Function{Signature: &ir.Signature{
		Recv:   &ir.Type{Kind: ir.TypeKind_TYPE_KIND_POINTER},
		Params: []*ir.Type{str},
	}}
	origin := &ir.Position{Filename: "a.go", Line: 3}
	if got := stringParamOrigins(fn, paramPositions{0: origin, 1: origin}, origin); !slices.Equal(got, []int{1}) {
		t.Errorf("stringParamOrigins = %v, want [1]", got)
	}
}

// Guards TestSharedIndexesAreSorted against becoming vacuous: a sortedness
// assertion over slices that are all length 1 proves nothing.
func TestSharedIndexesHaveMultiEntryLists(t *testing.T) {
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/sql_injection/main.go")
	if err != nil {
		t.Fatalf("convert sample: %v", err)
	}
	byKey, _ := buildFuncIndex(prog)
	impls := buildMethodImpls(byKey)
	for _, m := range []map[string][]string{impls, buildCallers(buildCallGraph(byKey, impls))} {
		multi := 0
		for _, v := range m {
			if len(v) > 1 {
				multi++
			}
		}
		if multi == 0 {
			t.Error("every list has at most one entry, so the sortedness assertion is vacuous")
		}
	}
}
