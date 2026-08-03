package analysis

import (
	"iter"

	"godzilla/internal/irwalk"
	ir "godzilla/pkg/ir/v1"
)

// funcs and instrs are thin package-local aliases for the shared
// internal/irwalk iterators (which grew out of this file), kept so every
// analysis pass's call sites read and compile unchanged. See the irwalk
// package doc for the traversal contract; the per-(function × rule) inner
// loops in analyzeFunc deliberately stay on hand-written loops.

// funcs yields every non-nil function in prog with its owning module.
func funcs(prog *ir.Program) iter.Seq2[*ir.Module, *ir.Function] {
	return irwalk.Funcs(prog)
}

// instrs yields every non-nil instruction of fn.
func instrs(fn *ir.Function) iter.Seq[*ir.Instruction] {
	return irwalk.Instrs(fn)
}
