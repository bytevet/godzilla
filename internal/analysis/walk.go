package analysis

import (
	"iter"

	ir "godzilla/pkg/ir/v1"
)

// The gIR walks below replace the four-deep `for module → function → block →
// instruction` nest, each level nil-guarded, that every whole-program pass had
// written out by hand. Repeating it meant a pass could silently forget a nil
// check, and it buried each pass's actual work under a dozen lines of scaffolding.
//
// These are range-over-func iterators, so a `continue`/`break`/`return` in the
// caller behaves exactly as it did in the hand-written loops. Every consumer runs
// ONCE per scan (Analyze's function index, the call graph, the dangerous-call and
// secret passes), so the per-element closure call is not on a hot path — the
// per-(function × rule) inner loops in analyzeFunc are deliberately left alone.

// funcs yields every non-nil function in prog with its owning module.
func funcs(prog *ir.Program) iter.Seq2[*ir.Module, *ir.Function] {
	return func(yield func(*ir.Module, *ir.Function) bool) {
		if prog == nil {
			return
		}
		for _, mod := range prog.Modules {
			if mod == nil {
				continue
			}
			for _, fn := range mod.Functions {
				if fn == nil {
					continue
				}
				if !yield(mod, fn) {
					return
				}
			}
		}
	}
}

// instrs yields every non-nil instruction of fn.
func instrs(fn *ir.Function) iter.Seq[*ir.Instruction] {
	return func(yield func(*ir.Instruction) bool) {
		if fn == nil {
			return
		}
		for _, blk := range fn.Blocks {
			if blk == nil {
				continue
			}
			for _, inst := range blk.Instrs {
				if inst == nil {
					continue
				}
				if !yield(inst) {
					return
				}
			}
		}
	}
}
