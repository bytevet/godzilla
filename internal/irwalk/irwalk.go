// Package irwalk provides the nil-guarded gIR traversal iterators shared by the
// analysis passes, the frontends' whole-program rewrites, and converter tests.
// Use them instead of hand-writing the four-deep `module → function → block →
// instruction` nest, where a pass can silently forget a nil check.
//
// These are range-over-func iterators, so `continue`/`break`/`return` behaves as
// in a plain loop. Every consumer runs ONCE per scan, so the per-element closure
// call is not hot; the engine's per-(function × rule) inner loops are
// deliberately left as hand-written loops.
package irwalk

import (
	"iter"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// Funcs yields every non-nil function in prog with its owning module.
func Funcs(prog *ir.Program) iter.Seq2[*ir.Module, *ir.Function] {
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

// Instrs yields every non-nil instruction of fn.
func Instrs(fn *ir.Function) iter.Seq[*ir.Instruction] {
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

// Calls yields the CallCommon of every CALL/INVOKE instruction in prog.
func Calls(prog *ir.Program) iter.Seq[*ir.CallCommon] {
	return func(yield func(*ir.CallCommon) bool) {
		for _, fn := range Funcs(prog) {
			for inst := range Instrs(fn) {
				if cc := inst.GetCall(); cc != nil {
					if !yield(cc) {
						return
					}
				}
			}
		}
	}
}

// SetCallee rewrites a call's resolved callee to name, keeping the call's
// function-value operand (when it names a function) in sync — the two fields
// name the same callee, and a rewrite that updated only Callee would leave a
// stale FuncName behind for any pass that reads the operand.
func SetCallee(cc *ir.CallCommon, name string) {
	cc.Callee = name
	if fnv := cc.GetValue(); fnv != nil && fnv.GetFuncName() != "" {
		fnv.Kind = &ir.Value_FuncName{FuncName: name}
	}
}
