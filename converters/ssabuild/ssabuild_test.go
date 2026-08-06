package ssabuild

import (
	"testing"

	ir "godzilla/pkg/ir/v1"
)

func constInt(n int64) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_IntVal{IntVal: n}}}}
}

func phisOf(blk *ir.BasicBlock) []*ir.Instruction {
	var out []*ir.Instruction
	for _, inst := range blk.Instrs {
		if inst.GetOp() == ir.OpCode_OP_CODE_PHI {
			out = append(out, inst)
		}
	}
	return out
}

// TestBuild is the table-driven core: each case builds a small CFG through the
// Builder and then asserts over the materialized blocks.
func TestBuild(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) []*ir.BasicBlock
		check func(t *testing.T, blocks []*ir.BasicBlock)
	}{
		{
			// (1) straight-line: one block, no PHI, no builder terminator.
			name: "straight_line_single_block",
			build: func(t *testing.T) []*ir.BasicBlock {
				b := NewBuilder()
				e := b.NewBlock()
				b.Seal(e)
				b.WriteVariable("x", e, constInt(1))
				b.WriteVariable("x", e, constInt(2))
				if got := b.ReadVariable("x", e).GetConstant().GetIntVal(); got != 2 {
					t.Fatalf("read x = %d, want 2", got)
				}
				return b.Finish()
			},
			check: func(t *testing.T, blocks []*ir.BasicBlock) {
				if len(blocks) != 1 {
					t.Fatalf("got %d blocks, want 1", len(blocks))
				}
				if len(blocks[0].Instrs) != 0 {
					t.Fatalf("straight-line block should have no builder instrs, got %d", len(blocks[0].Instrs))
				}
				if len(blocks[0].Succs) != 0 {
					t.Fatalf("straight-line block should have no successors, got %v", blocks[0].Succs)
				}
			},
		},
		{
			// (2) if/else diamond, var written in both arms -> merge PHI.
			name: "diamond_merge_phi",
			build: func(t *testing.T) []*ir.BasicBlock {
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
				b.WriteVariable("x", fb, constInt(20))
				b.SetJump(tb, merge)
				b.SetJump(fb, merge)
				b.Seal(merge)
				_ = b.ReadVariable("x", merge)
				return b.Finish()
			},
			check: func(t *testing.T, blocks []*ir.BasicBlock) {
				// entry(0) IF successors ordered [true, false] = [1,2].
				if got := blocks[0].Succs; len(got) != 2 || got[0] != 1 || got[1] != 2 {
					t.Fatalf("entry succs = %v, want [1 2]", got)
				}
				merge := blocks[3]
				ps := phisOf(merge)
				if len(ps) != 1 {
					t.Fatalf("merge should carry exactly one PHI, got %d", len(ps))
				}
				phi := ps[0]
				if len(phi.Operands) != 2 || len(phi.Blocks) != 2 {
					t.Fatalf("emitted PHI: %d operands, %d blocks", len(phi.Operands), len(phi.Blocks))
				}
				if phi.Blocks[0] != "b1" || phi.Blocks[1] != "b2" {
					t.Fatalf("PHI pred labels = %v, want [b1 b2]", phi.Blocks)
				}
				var saw10, saw20 bool
				for _, op := range phi.Operands {
					switch op.GetConstant().GetIntVal() {
					case 10:
						saw10 = true
					case 20:
						saw20 = true
					}
				}
				if !saw10 || !saw20 {
					t.Fatalf("PHI operands = %+v, want {10,20}", phi.Operands)
				}
				if len(merge.Preds) != 2 || merge.Preds[0] != 1 || merge.Preds[1] != 2 {
					t.Fatalf("merge preds = %v, want [1 2]", merge.Preds)
				}
			},
		},
		{
			// (3) var written only before the if reads through unchanged: the
			// merge PHI is trivial and removed, read yields the original const.
			name: "write_before_if_trivial_removed",
			build: func(t *testing.T) []*ir.BasicBlock {
				b := NewBuilder()
				entry := b.NewBlock()
				b.Seal(entry)
				tb := b.NewBlock()
				fb := b.NewBlock()
				merge := b.NewBlock()

				b.WriteVariable("x", entry, constInt(7))
				b.SetIf(entry, constInt(1), tb, fb)
				b.Seal(tb)
				b.Seal(fb)
				b.SetJump(tb, merge)
				b.SetJump(fb, merge)
				b.Seal(merge)

				if got := b.ReadVariable("x", merge); got.GetConstant().GetIntVal() != 7 {
					t.Fatalf("read x in merge = %v, want const 7 (trivial PHI collapsed)", got)
				}
				return b.Finish()
			},
			check: func(t *testing.T, blocks []*ir.BasicBlock) {
				for _, inst := range blocks[3].Instrs {
					if inst.GetOp() == ir.OpCode_OP_CODE_PHI {
						t.Fatalf("trivial PHI should have been removed from merge block")
					}
				}
			},
		},
		{
			// (4) while loop: header PHI over [pre-loop, back-edge] materializes
			// once the header is sealed after the back-edge is wired.
			name: "while_loop_header_phi",
			build: func(t *testing.T) []*ir.BasicBlock {
				b := NewBuilder()
				entry := b.NewBlock()
				b.Seal(entry)
				b.WriteVariable("i", entry, constInt(0))

				header := b.NewBlock() // unsealed: back-edge unknown
				body := b.NewBlock()
				exit := b.NewBlock()

				b.SetJump(entry, header)
				iHdr := b.ReadVariable("i", header) // parks incomplete PHI
				b.SetIf(header, iHdr, body, exit)

				b.Seal(body)
				inc := &ir.Instruction{Name: "t_inc", Op: ir.OpCode_OP_CODE_BIN_OP, BinOp: ir.BinOpKind_BIN_OP_ADD,
					Operands: []*ir.Value{iHdr, constInt(1)}}
				b.AddInstr(body, inc)
				b.WriteVariable("i", body, Reg("t_inc"))
				b.SetJump(body, header)

				b.Seal(header) // back-edge known -> fills incomplete PHI
				b.Seal(exit)

				blocks := b.Finish()
				// stash the inc for the check via a package-visible assertion here:
				if len(phisOf(blocks[1])) == 1 {
					phiName := phisOf(blocks[1])[0].Name
					if inc.Operands[0].GetRegName() != phiName {
						t.Fatalf("body use of i resolved to %v, want PHI %s", inc.Operands[0], phiName)
					}
				}
				return blocks
			},
			check: func(t *testing.T, blocks []*ir.BasicBlock) {
				header := blocks[1]
				ps := phisOf(header)
				if len(ps) != 1 {
					t.Fatalf("loop header should carry exactly one PHI, got %d", len(ps))
				}
				phi := ps[0]
				if len(phi.Operands) != 2 {
					t.Fatalf("loop PHI should merge 2 values, got %d", len(phi.Operands))
				}
				var sawConst, sawInc bool
				for _, op := range phi.Operands {
					if op.GetConstant().GetIntVal() == 0 {
						sawConst = true
					}
					if op.GetRegName() == "t_inc" {
						sawInc = true
					}
				}
				if !sawConst || !sawInc {
					t.Fatalf("loop PHI operands = %+v, want {0, t_inc}", phi.Operands)
				}
				// header preds [entry(0), body(1's back edge = block 2)].
				if len(header.Preds) != 2 {
					t.Fatalf("header preds = %v, want 2 (entry + back-edge)", header.Preds)
				}
			},
		},
		{
			// (5) nested if inside a loop: the two if-arms each update the loop
			// var, so a join PHI merges the arms and the loop-header PHI merges
			// the pre-loop value with that join PHI over the back-edge.
			name: "nested_if_in_loop",
			build: func(t *testing.T) []*ir.BasicBlock {
				b := NewBuilder()
				entry := b.NewBlock() // 0
				b.Seal(entry)
				b.WriteVariable("x", entry, constInt(0))

				header := b.NewBlock() // 1, unsealed
				body := b.NewBlock()   // 2
				thenB := b.NewBlock()  // 3
				elseB := b.NewBlock()  // 4
				join := b.NewBlock()   // 5
				exit := b.NewBlock()   // 6

				b.SetJump(entry, header)
				xh := b.ReadVariable("x", header) // parks incomplete header PHI
				b.SetIf(header, xh, body, exit)

				b.Seal(body)
				b.SetIf(body, constInt(1), thenB, elseB)
				b.Seal(thenB)
				b.Seal(elseB)

				t1 := &ir.Instruction{Name: "t1", Op: ir.OpCode_OP_CODE_BIN_OP, BinOp: ir.BinOpKind_BIN_OP_ADD,
					Operands: []*ir.Value{xh, constInt(1)}}
				b.AddInstr(thenB, t1)
				b.WriteVariable("x", thenB, Reg("t1"))
				b.SetJump(thenB, join)

				t2 := &ir.Instruction{Name: "t2", Op: ir.OpCode_OP_CODE_BIN_OP, BinOp: ir.BinOpKind_BIN_OP_ADD,
					Operands: []*ir.Value{xh, constInt(2)}}
				b.AddInstr(elseB, t2)
				b.WriteVariable("x", elseB, Reg("t2"))
				b.SetJump(elseB, join)

				b.Seal(join)
				b.SetJump(join, header) // back-edge

				b.Seal(header)
				b.Seal(exit)

				blocks := b.Finish()
				// The body arms' use of x must resolve to the header PHI.
				hp := phisOf(blocks[1])
				if len(hp) == 1 {
					if t1.Operands[0].GetRegName() != hp[0].Name {
						t.Fatalf("thenB use of x = %v, want header PHI %s", t1.Operands[0], hp[0].Name)
					}
					if t2.Operands[0].GetRegName() != hp[0].Name {
						t.Fatalf("elseB use of x = %v, want header PHI %s", t2.Operands[0], hp[0].Name)
					}
				}
				return blocks
			},
			check: func(t *testing.T, blocks []*ir.BasicBlock) {
				header := blocks[1]
				join := blocks[5]

				jps := phisOf(join)
				if len(jps) != 1 {
					t.Fatalf("join should carry one PHI merging the two arms, got %d", len(jps))
				}
				var sawT1, sawT2 bool
				for _, op := range jps[0].Operands {
					switch op.GetRegName() {
					case "t1":
						sawT1 = true
					case "t2":
						sawT2 = true
					}
				}
				if !sawT1 || !sawT2 {
					t.Fatalf("join PHI operands = %+v, want {t1,t2}", jps[0].Operands)
				}

				hps := phisOf(header)
				if len(hps) != 1 {
					t.Fatalf("header should carry one loop PHI, got %d", len(hps))
				}
				// header PHI merges const 0 (pre-loop) and the join PHI (back-edge).
				var sawZero, sawJoinPhi bool
				for _, op := range hps[0].Operands {
					if op.GetConstant().GetIntVal() == 0 {
						sawZero = true
					}
					if op.GetRegName() == jps[0].Name {
						sawJoinPhi = true
					}
				}
				if !sawZero || !sawJoinPhi {
					t.Fatalf("header PHI operands = %+v, want {0, %s}", hps[0].Operands, jps[0].Name)
				}
			},
		},
		{
			// (6) self-referential trivial PHI: a loop var never modified inside
			// the loop yields a PHI whose only real operand is the pre-loop value
			// (the back-edge operand is the PHI itself) -> collapses away.
			name: "self_referential_phi_elimination",
			build: func(t *testing.T) []*ir.BasicBlock {
				b := NewBuilder()
				entry := b.NewBlock()
				b.Seal(entry)
				b.WriteVariable("x", entry, constInt(5))

				header := b.NewBlock() // unsealed
				body := b.NewBlock()
				exit := b.NewBlock()

				b.SetJump(entry, header)
				xh := b.ReadVariable("x", header) // parks incomplete PHI
				b.SetIf(header, xh, body, exit)

				b.Seal(body)
				b.SetJump(body, header) // back-edge, no write to x

				b.Seal(header) // fills PHI: operands {5, self} -> trivial
				b.Seal(exit)

				if got := b.ReadVariable("x", header); got.GetConstant().GetIntVal() != 5 {
					t.Fatalf("read x in header = %v, want const 5 (self-ref PHI collapsed)", got)
				}
				return b.Finish()
			},
			check: func(t *testing.T, blocks []*ir.BasicBlock) {
				for i, blk := range blocks {
					if len(phisOf(blk)) != 0 {
						t.Fatalf("block %d should carry no PHI after self-ref elimination", i)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocks := tc.build(t)
			tc.check(t, blocks)
		})
	}
}

// (7) Determinism: identical construction yields byte-identical PHI names,
// block ids, operand and pred-label ordering across independent builds.
func TestDeterministic(t *testing.T) {
	build := func() []*ir.BasicBlock {
		b := NewBuilder()
		entry := b.NewBlock()
		b.Seal(entry)
		tb := b.NewBlock()
		fb := b.NewBlock()
		merge := b.NewBlock()
		b.SetIf(entry, constInt(1), tb, fb)
		b.Seal(tb)
		b.Seal(fb)
		b.WriteVariable("a", tb, constInt(1))
		b.WriteVariable("a", fb, constInt(2))
		b.WriteVariable("b", tb, constInt(3))
		b.WriteVariable("b", fb, constInt(4))
		b.SetJump(tb, merge)
		b.SetJump(fb, merge)
		b.Seal(merge)
		_ = b.ReadVariable("a", merge)
		_ = b.ReadVariable("b", merge)
		return b.Finish()
	}
	a := build()
	c := build()
	if len(a) != len(c) {
		t.Fatalf("block count differs: %d vs %d", len(a), len(c))
	}
	for i := range a {
		if len(a[i].Instrs) != len(c[i].Instrs) {
			t.Fatalf("block %d instr count differs: %d vs %d", i, len(a[i].Instrs), len(c[i].Instrs))
		}
		if len(a[i].Preds) != len(c[i].Preds) || len(a[i].Succs) != len(c[i].Succs) {
			t.Fatalf("block %d preds/succs shape differs", i)
		}
		for j := range a[i].Instrs {
			ia, ic := a[i].Instrs[j], c[i].Instrs[j]
			if ia.Name != ic.Name {
				t.Fatalf("block %d instr %d name differs: %q vs %q", i, j, ia.Name, ic.Name)
			}
			if ia.GetOp() != ic.GetOp() {
				t.Fatalf("block %d instr %d op differs", i, j)
			}
			if len(ia.Blocks) != len(ic.Blocks) {
				t.Fatalf("block %d instr %d phi-label count differs", i, j)
			}
			for k := range ia.Blocks {
				if ia.Blocks[k] != ic.Blocks[k] {
					t.Fatalf("block %d instr %d phi label %d differs: %q vs %q", i, j, k, ia.Blocks[k], ic.Blocks[k])
				}
			}
		}
	}
}
