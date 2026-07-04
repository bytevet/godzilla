//go:build llvm

package llvm_converter

import (
	"os"
	"path/filepath"
	"testing"

	ir "godzilla/pkg/ir/v1"
)

// lowerLL writes src to a temp .ll and lowers it as C, failing the test on error.
func lowerLL(t *testing.T, src string) *ir.Module {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "m.ll")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	mod, err := Lower(path, "m.c", "c", "c:", CDemangle)
	if err != nil {
		t.Fatalf("Lower: %v", err)
	}
	return mod
}

// TestLowerSynthesizesArgvSource guards COV-8's CLI taint source: for
// `main(i32 argc, ptr argv)` the lowering must emit a synthetic `c:argv` source
// CALL so an `argv[i]` read carries taint into a sink.
func TestLowerSynthesizesArgvSource(t *testing.T) {
	const ll = `
define i32 @main(i32 %argc, ptr %argv) {
entry:
  ret i32 0
}
`
	mod := lowerLL(t, ll)
	found := false
	for _, fn := range mod.Functions {
		for _, blk := range fn.Blocks {
			for _, in := range blk.Instrs {
				if in.Call != nil && in.Call.GetCallee() == "c:argv" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("expected a synthesized c:argv source CALL for main(argc, argv)")
	}
}

// TestLowerWiresCFGEdges is a hermetic guard (a hand-written .ll, no clang) that
// the LLVM lowering populates each block's Succs/Preds. The flow-sensitive
// engine propagates taint in reverse-post-order over these edges, so a source
// and a sink split across a branch (the common `if (x) sink(x)` guard) only
// connect when the edges exist. Before this was wired, multi-block C/C++
// functions dropped all cross-block taint.
func TestLowerWiresCFGEdges(t *testing.T) {
	const ir = `
define i32 @main(i32 %n) {
entry:
  %c = icmp sgt i32 %n, 0
  br i1 %c, label %then, label %end
then:
  br label %end
end:
  ret i32 0
}
`
	mod := lowerLL(t, ir)
	if len(mod.Functions) != 1 {
		t.Fatalf("expected 1 function, got %d", len(mod.Functions))
	}
	fn := mod.Functions[0]
	if len(fn.Blocks) != 3 {
		t.Fatalf("expected 3 blocks (entry/then/end), got %d", len(fn.Blocks))
	}
	entry, then, end := fn.Blocks[0], fn.Blocks[1], fn.Blocks[2]
	// entry -> {then, end}
	if len(entry.Succs) != 2 {
		t.Errorf("entry.Succs = %v, want 2 successors", entry.Succs)
	}
	// then -> end
	if len(then.Succs) != 1 || then.Succs[0] != end.Index {
		t.Errorf("then.Succs = %v, want [%d]", then.Succs, end.Index)
	}
	// end is a join: predecessors entry and then.
	if len(end.Preds) != 2 {
		t.Errorf("end.Preds = %v, want 2 predecessors (entry, then)", end.Preds)
	}
	// The terminator ret has no block operands, so end has no successors.
	if len(end.Succs) != 0 {
		t.Errorf("end.Succs = %v, want none", end.Succs)
	}
}
