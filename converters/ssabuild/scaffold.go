package ssabuild

import (
	ir "godzilla/pkg/ir/v1"
)

// This file holds the CFG scaffolds shared by the AST-walking frontends
// (Python, JavaScript, Ruby): the if/else diamond and the two loop shapes.
// Each scaffold owns the block creation, the edge wiring and — crucially —
// the seal ORDER for its shape; the frontend supplies closures that lower its
// source-language constructs into whichever block the scaffold has made
// current. The seal order matters (a block may only be sealed once ALL of its
// predecessors are known, and a loop header must stay unsealed until its
// back-edge is wired — see the package doc) and is why the frontends share
// these scaffolds rather than each open-coding the dance.
//
// The frontend's lowering position is passed as cur/terminated POINTERS
// (the addresses of its per-function state fields): the scaffold moves *cur
// from block to block around each closure, and the closures are free to move
// it further (a nested branch lowers into its own diamond) and to set
// *terminated (a lowered `return`); the scaffold reads both back after each
// closure returns.

// IfDiamond lowers a two-armed conditional into a REAL CFG diamond: the
// current block ends in an OP_CODE_IF on cond (which the caller has already
// lowered in *cur) to a fresh then-block and else-block; each arm is lowered
// in its own block and jumps to a fresh merge block; the merge is sealed once
// both arm-ends are its known predecessors, so any variable rebound on one or
// both arms reconciles automatically via an on-demand ReadVariable PHI. An
// arm that terminated (returned) gets no fall-through edge to the merge, and
// the merge is dead — *terminated left true — only if BOTH arms terminated.
// Returns the two arm-end blocks and the merge block so a value-producing
// conditional (Ruby's if-expression) can reconcile the arms' result values
// across them; statement-form callers ignore them.
func (b *Builder) IfDiamond(cur *BlockID, terminated *bool, cond *ir.Value, lowerThen, lowerElse func()) (thenEnd, elseEnd, merge BlockID) {
	thenB := b.NewBlock()
	elseB := b.NewBlock()
	merge = b.NewBlock()
	b.SetIf(*cur, cond, thenB, elseB)
	b.Seal(thenB) // sole predecessor (the branch block) is known
	b.Seal(elseB)

	*cur = thenB
	*terminated = false
	lowerThen()
	thenEnd = *cur // the arm may itself have branched; jump from its END
	thenTerm := *terminated
	if !thenTerm { // a returning arm has no fall-through edge to the merge
		b.SetJump(thenEnd, merge)
	}

	*cur = elseB
	*terminated = false
	lowerElse()
	elseEnd = *cur
	elseTerm := *terminated
	if !elseTerm {
		b.SetJump(elseEnd, merge)
	}

	b.Seal(merge) // predecessors (only the non-returning arms) now wired
	*cur = merge
	// The merge is dead only if BOTH arms returned; otherwise it falls through.
	*terminated = thenTerm && elseTerm
	return thenEnd, elseEnd, merge
}

// HeaderLoop lowers a header-tested loop (while/for) into a REAL loop CFG:
// header/body/exit blocks. The current block jumps to the header; the header
// runs lowerCond and branches (body, exit); lowerBody fills the body, which
// jumps BACK to the header (the back-edge) — unless it terminated: a body
// that always returns has no back-edge. The header is left UNSEALED while the
// body is built, so a loop variable read in the condition or body parks an
// incomplete PHI that is filled when the header is sealed after the back-edge
// is wired — this is what gives loop-carried taint: a value written in the
// body and read at the top of the next iteration flows through the header PHI
// (which a single-block lowering could not model). The header PHI over
// [pre-loop, back-edge] carries taint into and out of the loop. The seal
// ORDER matters and is why every loop form shares this scaffold rather than
// each open-coding it. Leaves *cur at the (sealed) exit block, *terminated
// false.
//
// A frontend puts a loop prologue (binding the iteration variable) at the top
// of lowerBody and a step (a C-style for's update) at its bottom; an opaque
// iteration condition (a for-range) is a lowerCond returning a constant
// placeholder.
func (b *Builder) HeaderLoop(cur *BlockID, terminated *bool, lowerCond func() *ir.Value, lowerBody func()) {
	header := b.NewBlock()
	body := b.NewBlock()
	exit := b.NewBlock()

	b.SetJump(*cur, header) // enter the loop
	*cur = header
	cond := lowerCond() // condition, lowered in the (unsealed) header
	b.SetIf(header, cond, body, exit)

	b.Seal(body) // body's sole predecessor (header) is known
	*cur = body
	*terminated = false
	lowerBody()
	if !*terminated { // a body that always returns has no back-edge
		b.SetJump(*cur, header) // back-edge from the body's END block
	}

	b.Seal(header) // predecessors (entry-jump [+ back-edge]) now known
	b.Seal(exit)   // exit's sole predecessor is the header
	*cur = exit
	*terminated = false
}

// BodyLoop lowers a body-first loop (do/while: the body runs BEFORE the test)
// into a loop CFG: the current block jumps into the body block; the body is
// the loop header (its back-edge comes from the test block), so it is left
// UNSEALED until the back-edge is wired; the test block runs lowerCond and
// re-enters the body when true, or falls to exit. Loop-carried taint flows
// through the body-header PHI. Leaves *cur at the (sealed) exit block,
// *terminated false.
func (b *Builder) BodyLoop(cur *BlockID, terminated *bool, lowerBody func(), lowerCond func() *ir.Value) {
	body := b.NewBlock()
	test := b.NewBlock()
	exit := b.NewBlock()

	b.SetJump(*cur, body) // the body always runs at least once
	*cur = body           // body is the loop header (UNSEALED: has a back-edge)
	*terminated = false
	lowerBody()
	if !*terminated {
		b.SetJump(*cur, test) // body end -> test
	}

	b.Seal(test) // test's sole predecessor (the body end) is known
	*cur = test
	cond := lowerCond()
	b.SetIf(test, cond, body, exit) // wire the back-edge test -> body

	b.Seal(body) // predecessors (entry-jump + back-edge) now known
	b.Seal(exit)
	*cur = exit
	*terminated = false
}
