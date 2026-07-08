package analysis

import (
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// guardIndex answers, for a rule that declares validators, whether a sink is
// guarded by a validation check on the path that reaches it (ENG-9). It is a
// lightweight, opt-in flow-sensitivity layer: a validator (an allowlist test, a
// regexp match, a path-containment predicate like filepath.IsLocal) whose
// boolean result controls an IF, and which dominates the sink on the branch the
// code takes to reach it, clears the checked value's taint for that sink. This
// suppresses the false positive that a flow-insensitive engine cannot: the very
// common "validate, then use" idiom (`if !valid(x) { return }; sink(x)` and
// `if valid(x) { sink(x) }`).
//
// The index is structural — dominators and guard-IF shapes do not depend on the
// taint state — so it is built once per function; only the final origin match at
// the sink consults the taint map. A rule without validators never builds one.
type guardIndex struct {
	// dom[b] is the set of block indices that dominate block b (b included).
	dom map[int32]map[int32]bool
	// guards lists every validator-controlled branch found in the function.
	guards []guardBranch
}

// guardBranch records a validator guard: an IF whose condition derives from a
// validator call applied to validatedRegs, with the two branch-target block
// indices. A sink dominated by either branch was reached only after the check.
type guardBranch struct {
	trueIdx, falseIdx int32
	validatedRegs     []string
}

// buildGuardIndex builds the guard index for fn under rule. It returns nil when
// the rule declares no validators (the common case), so callers pay nothing.
func buildGuardIndex(fn *ir.Function, rule *rules.Rule, defs map[string]*ir.Instruction) *guardIndex {
	if !rule.HasValidators() || len(fn.Blocks) == 0 {
		return nil
	}
	gi := &guardIndex{dom: computeDominators(fn)}

	for _, blk := range fn.Blocks {
		if blk == nil {
			continue
		}
		// A conditional block's successor edges are [trueTarget, falseTarget]
		// (the frontend emits them in that order alongside the IF terminator), so
		// they need no block-name parsing and stay frontend-agnostic.
		succs := blk.GetSuccs()
		if len(succs) < 2 {
			continue
		}
		for _, inst := range blk.Instrs {
			if inst == nil || inst.Op != ir.OpCode_OP_CODE_IF {
				continue
			}
			ops := inst.GetOperands()
			if len(ops) == 0 {
				continue
			}
			condReg := ops[0].GetRegName()
			if condReg == "" {
				continue
			}
			validated := validatorArgsOf(condReg, defs, rule)
			if len(validated) == 0 {
				continue
			}
			gi.guards = append(gi.guards, guardBranch{trueIdx: succs[0], falseIdx: succs[1], validatedRegs: validated})
		}
	}
	if len(gi.guards) == 0 {
		return nil
	}
	return gi
}

// guarded reports whether a sink in block sinkIdx, on a flow whose source origin
// is o, is neutralized by a validator guard: some guarded branch dominates the
// sink block AND the validator was applied to a register carrying that same
// source origin (so it is the SAME untrusted value that was checked). The origin
// match ties the guard to this specific flow, so validating one value does not
// suppress an unrelated tainted sink.
func (gi *guardIndex) guarded(sinkIdx int32, o *ir.Position, tainted taintState) bool {
	if gi == nil {
		return false
	}
	for _, g := range gi.guards {
		if !gi.dominates(g.trueIdx, sinkIdx) && !gi.dominates(g.falseIdx, sinkIdx) {
			continue
		}
		for _, reg := range g.validatedRegs {
			if tainted[reg] == o {
				return true
			}
		}
	}
	return false
}

// dominates reports whether block a dominates block b (every path from entry to
// b passes through a). a == b is dominance too.
func (gi *guardIndex) dominates(a, b int32) bool {
	d := gi.dom[b]
	return d != nil && d[a]
}

// validatorArgsOf returns the registers a validator was applied to, if the value
// in condReg derives from a validator call. It walks the def chain back through
// boolean-shaping operations (a negation `!valid(x)`, a comparison `valid(x) ==
// true`, a convert) to the underlying validator CALL, and returns that call's
// argument and receiver registers. Empty if condReg is not validator-controlled.
func validatorArgsOf(condReg string, defs map[string]*ir.Instruction, rule *rules.Rule) []string {
	seen := map[string]bool{}
	var walk func(reg string) []string
	walk = func(reg string) []string {
		if reg == "" || seen[reg] {
			return nil
		}
		seen[reg] = true
		def := defs[reg]
		if def == nil {
			return nil
		}
		if def.Call != nil && rule.IsValidator(def.Call.GetCallee()) {
			var regs []string
			if v := def.Call.GetValue(); v != nil {
				if r := v.GetRegName(); r != "" {
					regs = append(regs, r)
				}
			}
			for _, a := range def.Call.GetArgs() {
				if r := a.GetRegName(); r != "" {
					regs = append(regs, r)
				}
			}
			return regs
		}
		// Not a validator call itself: follow boolean-shaping operands (negation,
		// comparison against a constant, type convert) toward the validator.
		switch def.Op {
		case ir.OpCode_OP_CODE_UN_OP, ir.OpCode_OP_CODE_BIN_OP, ir.OpCode_OP_CODE_CONVERT:
			var regs []string
			for _, op := range def.GetOperands() {
				regs = append(regs, walk(op.GetRegName())...)
			}
			return regs
		}
		return nil
	}
	return walk(condReg)
}

// computeDominators returns dom[b] = the set of block indices dominating b,
// via the classic iterative data-flow algorithm over the frontend-populated
// predecessor edges. The entry block is fn.Blocks[0].
func computeDominators(fn *ir.Function) map[int32]map[int32]bool {
	all := make([]int32, 0, len(fn.Blocks))
	preds := map[int32][]int32{}
	for _, blk := range fn.Blocks {
		if blk == nil {
			continue
		}
		idx := blk.GetIndex()
		all = append(all, idx)
		preds[idx] = blk.GetPreds()
	}
	if len(all) == 0 {
		return nil
	}
	entry := all[0]

	dom := map[int32]map[int32]bool{}
	// entry is dominated only by itself; every other block starts dominated by
	// all blocks and is narrowed by intersection until fixpoint.
	dom[entry] = map[int32]bool{entry: true}
	for _, b := range all {
		if b == entry {
			continue
		}
		full := map[int32]bool{}
		for _, x := range all {
			full[x] = true
		}
		dom[b] = full
	}

	for changed := true; changed; {
		changed = false
		for _, b := range all {
			if b == entry {
				continue
			}
			// newdom = {b} ∪ (intersection of dom[p] over predecessors p).
			var inter map[int32]bool
			for _, p := range preds[b] {
				dp := dom[p]
				if dp == nil {
					continue
				}
				if inter == nil {
					inter = map[int32]bool{}
					for k := range dp {
						inter[k] = true
					}
					continue
				}
				for k := range inter {
					if !dp[k] {
						delete(inter, k)
					}
				}
			}
			if inter == nil {
				inter = map[int32]bool{}
			}
			inter[b] = true
			if !sameSet(inter, dom[b]) {
				dom[b] = inter
				changed = true
			}
		}
	}
	return dom
}

func sameSet(a, b map[int32]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
