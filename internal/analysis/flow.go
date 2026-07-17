package analysis

import ir "godzilla/pkg/ir/v1"

// taintState maps a tainted register (or access-path key) to the source origin
// its taint came from. It is the per-block dataflow fact for the flow-sensitive
// intra-procedural pass (ENG-2). Callers clone/compare it with maps.Clone /
// maps.Equal (origin pointers are shared and compared by identity).
type taintState = map[string]*ir.Position

// reversePostOrder returns fn's block indices in reverse post-order from the
// entry block (fn.Blocks[0]) over the successor edges, followed by any blocks
// unreachable from entry (so none are dropped). RPO visits a block before its
// forward successors, so the forward taint dataflow converges in few passes.
func reversePostOrder(fn *ir.Function) []int32 {
	if len(fn.Blocks) == 0 {
		return nil
	}
	succ := map[int32][]int32{}
	exists := map[int32]bool{}
	for _, blk := range fn.Blocks {
		if blk == nil {
			continue
		}
		exists[blk.GetIndex()] = true
		succ[blk.GetIndex()] = blk.GetSuccs()
	}

	visited := map[int32]bool{}
	var post []int32
	// Iterative post-order DFS (an explicit stack avoids deep recursion on large
	// functions). Each frame tracks how many successors it has processed.
	type frame struct {
		b int32
		i int
	}
	dfs := func(start int32) {
		if visited[start] || !exists[start] {
			return
		}
		stack := []frame{{b: start, i: 0}}
		visited[start] = true
		for len(stack) > 0 {
			top := &stack[len(stack)-1]
			ss := succ[top.b]
			if top.i < len(ss) {
				n := ss[top.i]
				top.i++
				if exists[n] && !visited[n] {
					visited[n] = true
					stack = append(stack, frame{b: n, i: 0})
				}
				continue
			}
			post = append(post, top.b)
			stack = stack[:len(stack)-1]
		}
	}

	dfs(fn.Blocks[0].GetIndex())
	for _, blk := range fn.Blocks {
		if blk != nil {
			dfs(blk.GetIndex()) // sweep in any blocks unreachable from entry
		}
	}

	order := make([]int32, 0, len(post))
	for i := len(post) - 1; i >= 0; i-- {
		order = append(order, post[i])
	}
	return order
}

// nonEscapingAllocs returns the set of ALLOC result registers whose address does
// not escape the function: the register is used only as a STORE destination
// (operand 0) or as the operand of a dereferencing read (LOAD / UN_OP). For such
// an alloc no alias can observe its cell, so a clean store fully overwrites it
// and a strong update — clearing the cell's taint — is sound (ENG-2). Any other
// use (a call argument, a return, a field/index base, a stored-as-value address,
// a PHI, …) may leak the address, so the alloc is excluded and keeps the
// conservative monotonic (weak-update) behaviour, losing no real flow.
func nonEscapingAllocs(fn *ir.Function, defs map[string]*ir.Instruction) map[string]bool {
	cand := map[string]bool{}
	for r, d := range defs {
		if d != nil && d.Op == ir.OpCode_OP_CODE_ALLOC {
			cand[r] = true
		}
	}
	if len(cand) == 0 {
		return cand
	}
	for _, blk := range fn.Blocks {
		if blk == nil {
			continue
		}
		for _, inst := range blk.Instrs {
			if inst == nil {
				continue
			}
			switch inst.Op {
			case ir.OpCode_OP_CODE_STORE:
				// operand[0] (addr) is a safe use; operand[1] (value) using the
				// register would store the address itself elsewhere — an escape.
				ops := inst.GetOperands()
				if len(ops) >= 2 {
					if r := ops[1].GetRegName(); r != "" {
						delete(cand, r)
					}
				}
			case ir.OpCode_OP_CODE_LOAD, ir.OpCode_OP_CODE_UN_OP:
				// Reading the cell through its address (a deref) is a safe use.
			default:
				for _, op := range operandsAndCallArgs(inst) {
					if r := op.GetRegName(); r != "" {
						delete(cand, r)
					}
				}
			}
		}
	}
	return cand
}

// operandsAndCallArgs returns every value an instruction references: its plain
// operands plus, for a call-carrying instruction, the receiver (Call.Value) and
// arguments. Used by escape analysis to find every use of an address.
func operandsAndCallArgs(inst *ir.Instruction) []*ir.Value {
	vals := append([]*ir.Value{}, inst.GetOperands()...)
	if inst.Call != nil {
		if v := inst.Call.GetValue(); v != nil {
			vals = append(vals, v)
		}
		vals = append(vals, inst.Call.GetArgs()...)
	}
	return vals
}
