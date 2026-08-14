package ssabuild

import (
	"testing"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// sameCFG asserts two materialized CFGs are structurally identical: block
// count, preds/succs, and per-instruction name/op/operands/labels. It is the
// "byte-for-byte the open-coded dance" check backing the scaffolds.
func sameCFG(t *testing.T, got, want []*ir.BasicBlock) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("block count differs: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		g, w := got[i], want[i]
		if len(g.Preds) != len(w.Preds) || len(g.Succs) != len(w.Succs) {
			t.Fatalf("block %d preds/succs shape differs: got %v/%v, want %v/%v", i, g.Preds, g.Succs, w.Preds, w.Succs)
		}
		for j := range g.Preds {
			if g.Preds[j] != w.Preds[j] {
				t.Fatalf("block %d pred %d differs: got %d, want %d", i, j, g.Preds[j], w.Preds[j])
			}
		}
		for j := range g.Succs {
			if g.Succs[j] != w.Succs[j] {
				t.Fatalf("block %d succ %d differs: got %d, want %d", i, j, g.Succs[j], w.Succs[j])
			}
		}
		if len(g.Instrs) != len(w.Instrs) {
			t.Fatalf("block %d instr count differs: got %d, want %d", i, len(g.Instrs), len(w.Instrs))
		}
		for j := range g.Instrs {
			gi, wi := g.Instrs[j], w.Instrs[j]
			if gi.Name != wi.Name || gi.GetOp() != wi.GetOp() {
				t.Fatalf("block %d instr %d differs: got %s %q, want %s %q", i, j, gi.GetOp(), gi.Name, wi.GetOp(), wi.Name)
			}
			if gi.TrueBlock != wi.TrueBlock || gi.FalseBlock != wi.FalseBlock || gi.JumpBlock != wi.JumpBlock {
				t.Fatalf("block %d instr %d targets differ", i, j)
			}
			if len(gi.Operands) != len(wi.Operands) || len(gi.Blocks) != len(wi.Blocks) {
				t.Fatalf("block %d instr %d operand/label shape differs", i, j)
			}
			for k := range gi.Operands {
				if !valEq(gi.Operands[k], wi.Operands[k]) {
					t.Fatalf("block %d instr %d operand %d differs: got %v, want %v", i, j, k, gi.Operands[k], wi.Operands[k])
				}
			}
			for k := range gi.Blocks {
				if gi.Blocks[k] != wi.Blocks[k] {
					t.Fatalf("block %d instr %d label %d differs: got %q, want %q", i, j, k, gi.Blocks[k], wi.Blocks[k])
				}
			}
		}
	}
}

// TestIfDiamond checks the scaffold against the open-coded diamond it
// replaced: same blocks, same seal order (observable through the merge PHI's
// operands and predecessor labels), same fall-through behavior.
func TestIfDiamond(t *testing.T) {
	// Scaffold build: rebind x in both arms, read it in the merge.
	scaffold := func() []*ir.BasicBlock {
		b := NewBuilder()
		cur := b.NewBlock()
		b.Seal(cur)
		terminated := false
		b.IfDiamond(&cur, &terminated, constInt(1),
			func() { b.WriteVariable("x", cur, constInt(10)) },
			func() { b.WriteVariable("x", cur, constInt(20)) })
		if terminated {
			t.Fatalf("neither arm returned: merge must fall through")
		}
		_ = b.ReadVariable("x", cur)
		return b.Finish()
	}
	// Open-coded reference: the exact primitive sequence the frontends used.
	reference := func() []*ir.BasicBlock {
		b := NewBuilder()
		entry := b.NewBlock()
		b.Seal(entry)
		tb := b.NewBlock()
		fb := b.NewBlock()
		merge := b.NewBlock()
		b.SetIf(entry, constInt(1), tb, fb)
		b.Seal(tb)
		b.Seal(fb)
		b.WriteVariable("x", tb, constInt(10))
		b.SetJump(tb, merge)
		b.WriteVariable("x", fb, constInt(20))
		b.SetJump(fb, merge)
		b.Seal(merge)
		_ = b.ReadVariable("x", merge)
		return b.Finish()
	}
	sameCFG(t, scaffold(), reference())
}

// TestIfDiamondTerminatedArm: an arm that "returns" (sets *terminated) gets
// no edge to the merge; the merge stays live off the other arm alone.
func TestIfDiamondTerminatedArm(t *testing.T) {
	b := NewBuilder()
	cur := b.NewBlock()
	b.Seal(cur)
	terminated := false
	_, elseEnd, merge := b.IfDiamond(&cur, &terminated, constInt(1),
		func() { terminated = true }, // then-arm returns
		func() {})
	if terminated {
		t.Fatalf("only one arm returned: merge must fall through")
	}
	if cur != merge {
		t.Fatalf("cur = %d after diamond, want merge %d", cur, merge)
	}
	blocks := b.Finish()
	mb := blocks[merge]
	if len(mb.Preds) != 1 || BlockID(mb.Preds[0]) != elseEnd {
		t.Fatalf("merge preds = %v, want the else arm %d only", mb.Preds, elseEnd)
	}
	// Both arms returning leaves the merge dead.
	b2 := NewBuilder()
	cur2 := b2.NewBlock()
	b2.Seal(cur2)
	term2 := false
	b2.IfDiamond(&cur2, &term2, constInt(1),
		func() { term2 = true },
		func() { term2 = true })
	if !term2 {
		t.Fatalf("both arms returned: merge must be dead")
	}
}

// TestHeaderLoop checks the scaffold against the open-coded while it
// replaced. The loop variable is written in the body, so the sealed-late
// header must carry the [pre-loop, back-edge] PHI.
func TestHeaderLoop(t *testing.T) {
	scaffold := func() []*ir.BasicBlock {
		b := NewBuilder()
		cur := b.NewBlock()
		b.Seal(cur)
		terminated := false
		b.WriteVariable("i", cur, constInt(0))
		b.HeaderLoop(&cur, &terminated,
			func() *ir.Value { return b.ReadVariable("i", cur) },
			func() { b.WriteVariable("i", cur, constInt(1)) })
		if terminated {
			t.Fatalf("loop exit must fall through")
		}
		return b.Finish()
	}
	reference := func() []*ir.BasicBlock {
		b := NewBuilder()
		entry := b.NewBlock()
		b.Seal(entry)
		b.WriteVariable("i", entry, constInt(0))
		header := b.NewBlock()
		body := b.NewBlock()
		exit := b.NewBlock()
		b.SetJump(entry, header)
		cond := b.ReadVariable("i", header)
		b.SetIf(header, cond, body, exit)
		b.Seal(body)
		b.WriteVariable("i", body, constInt(1))
		b.SetJump(body, header)
		b.Seal(header)
		b.Seal(exit)
		return b.Finish()
	}
	got, want := scaffold(), reference()
	sameCFG(t, got, want)
	if len(phisOf(got[1])) != 1 {
		t.Fatalf("loop header must carry the loop-carried PHI, got %d", len(phisOf(got[1])))
	}
}

// TestBodyLoop checks the do-while scaffold: the body is the loop header,
// sealed only after the test block wires the back-edge, so a body write
// still yields the header PHI.
func TestBodyLoop(t *testing.T) {
	scaffold := func() []*ir.BasicBlock {
		b := NewBuilder()
		cur := b.NewBlock()
		b.Seal(cur)
		terminated := false
		b.WriteVariable("i", cur, constInt(0))
		b.BodyLoop(&cur, &terminated,
			func() {
				v := b.ReadVariable("i", cur) // parks the incomplete body PHI
				_ = v
				b.WriteVariable("i", cur, constInt(1))
			},
			func() *ir.Value { return b.ReadVariable("i", cur) })
		return b.Finish()
	}
	reference := func() []*ir.BasicBlock {
		b := NewBuilder()
		entry := b.NewBlock()
		b.Seal(entry)
		b.WriteVariable("i", entry, constInt(0))
		body := b.NewBlock()
		test := b.NewBlock()
		exit := b.NewBlock()
		b.SetJump(entry, body)
		_ = b.ReadVariable("i", body)
		b.WriteVariable("i", body, constInt(1))
		b.SetJump(body, test)
		b.Seal(test)
		cond := b.ReadVariable("i", test)
		b.SetIf(test, cond, body, exit)
		b.Seal(body)
		b.Seal(exit)
		return b.Finish()
	}
	got, want := scaffold(), reference()
	sameCFG(t, got, want)
	if len(phisOf(got[1])) != 1 {
		t.Fatalf("do-while body header must carry the loop-carried PHI, got %d", len(phisOf(got[1])))
	}
}
