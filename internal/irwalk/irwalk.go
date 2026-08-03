// Package irwalk provides the nil-guarded gIR traversal iterators shared by
// the analysis passes, the frontends' whole-program rewrites, and converter
// tests. They replace the four-deep `for module → function → block →
// instruction` nest, each level nil-guarded, that every whole-program pass had
// written out by hand. Repeating it meant a pass could silently forget a nil
// check, and it buried each pass's actual work under a dozen lines of
// scaffolding.
//
// These are range-over-func iterators, so a `continue`/`break`/`return` in the
// caller behaves exactly as it did in the hand-written loops. Every consumer
// runs ONCE per scan (Analyze's function index, the call graph, the
// dangerous-call and secret passes, the frontends' cross-module callee
// rewrites), so the per-element closure call is not on a hot path — the
// per-(function × rule) inner loops in the engine's funcAnalysis methods are
// deliberately left on hand-written loops.
package irwalk

import (
	"iter"

	ir "godzilla/pkg/ir/v1"
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

// Calls yields the CallCommon of every CALL/INVOKE instruction in prog — the
// walk shared by the frontends' cross-module callee rewrites and by converter
// tests that assert on the callees a lowering produced.
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
