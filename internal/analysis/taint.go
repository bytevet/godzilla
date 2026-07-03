package analysis

import (
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// Engine runs taint analysis over a gIR program for a fixed set of rules.
// Analysis is inter-procedural; see interproc.go for the orchestration.
type Engine struct {
	rs *rules.RuleSet
}

// NewEngine builds an Engine that will evaluate every rule in rs.
func NewEngine(rs *rules.RuleSet) *Engine {
	return &Engine{rs: rs}
}

// intrinsicPropagators is the set of language-specific OP_CODE_INTRINSIC
// operations that pass taint from operand to result register.
var intrinsicPropagators = map[string]bool{
	"builtin.slice": true,
	// builtin.aggregate models a tuple/array/struct/enum-variant construction
	// (used by the Rust frontend): taint on any constructed element flows to the
	// aggregate value, so a later whole-aggregate use (e.g. a format! argument
	// pack) observes it. Field-precise reads are folded at lowering time.
	"builtin.aggregate": true,
	"go.map.lookup":     true,
	"go.next":           true,
	"go.range":          true,
}

// propagatingOps are non-call opcodes that propagate taint from any tainted
// operand to the instruction's result register.
var propagatingOps = map[ir.OpCode]bool{
	ir.OpCode_OP_CODE_BIN_OP:         true,
	ir.OpCode_OP_CODE_UN_OP:          true,
	ir.OpCode_OP_CODE_CONVERT:        true,
	ir.OpCode_OP_CODE_TYPE_ASSERT:    true, // v := x.(T): the result is x's value with a narrower static type
	ir.OpCode_OP_CODE_FIELD:          true,
	ir.OpCode_OP_CODE_FIELD_ADDR:     true,
	ir.OpCode_OP_CODE_INDEX:          true,
	ir.OpCode_OP_CODE_INDEX_ADDR:     true,
	ir.OpCode_OP_CODE_EXTRACT:        true,
	ir.OpCode_OP_CODE_PHI:            true,
	ir.OpCode_OP_CODE_MAKE_INTERFACE: true,
	ir.OpCode_OP_CODE_LOAD:           true,
}

// buildDefs maps each SSA result register to the instruction that defines it,
// so taint transfer can walk value-derivation chains (e.g. from an element
// address back to its container).
func buildDefs(fn *ir.Function) map[string]*ir.Instruction {
	defs := map[string]*ir.Instruction{}
	for _, blk := range fn.Blocks {
		if blk == nil {
			continue
		}
		for _, inst := range blk.Instrs {
			if inst != nil && inst.Name != "" {
				defs[inst.Name] = inst
			}
		}
	}
	return defs
}

// visitStore approximates store-then-load through an alloc: if the stored
// value is tainted, the destination address register is marked tainted too,
// so a later LOAD from that register (a distinct SSA register on ssa.Alloc
// pointers) observes the taint.
func visitStore(inst *ir.Instruction, defs map[string]*ir.Instruction, tainted map[string]*ir.Position) {
	operands := inst.GetOperands()
	if len(operands) < 2 {
		return
	}
	addr, val := operands[0], operands[1]
	pos, ok := isTainted(tainted, val)
	if !ok {
		return
	}
	addrReg := addr.GetRegName()
	if addrReg == "" {
		return
	}
	markTainted(tainted, addrReg, pos)
	// Storing a tainted value into an element/field address taints the whole
	// container, so a later read of the container (e.g. arr[:] for variadic
	// packing, or a struct field load) observes the taint. Walk the
	// address-derivation chain to taint every enclosing aggregate base.
	taintContainer(defs, tainted, addrReg, pos)
}

// taintContainer walks up the address-derivation chain from reg (produced by
// INDEX_ADDR/FIELD_ADDR/INDEX/FIELD) and marks each enclosing container base
// tainted. This is a field-insensitive over-approximation that recovers taint
// through Go's variadic slice packing and aggregate mutation.
func taintContainer(defs map[string]*ir.Instruction, tainted map[string]*ir.Position, reg string, pos *ir.Position) {
	seen := map[string]bool{}
	for reg != "" && !seen[reg] {
		seen[reg] = true
		def := defs[reg]
		if def == nil {
			return
		}
		switch def.Op {
		case ir.OpCode_OP_CODE_INDEX_ADDR, ir.OpCode_OP_CODE_FIELD_ADDR,
			ir.OpCode_OP_CODE_INDEX, ir.OpCode_OP_CODE_FIELD:
			ops := def.GetOperands()
			if len(ops) == 0 {
				return
			}
			base := ops[0].GetRegName()
			if base == "" {
				return
			}
			markTainted(tainted, base, pos)
			reg = base
		default:
			return
		}
	}
}

func visitIntrinsic(inst *ir.Instruction, defs map[string]*ir.Instruction, tainted map[string]*ir.Position) {
	if inst.Intrinsic == "go.map.update" {
		visitMapUpdate(inst, defs, tainted)
		return
	}
	if inst.Name == "" || !intrinsicPropagators[inst.Intrinsic] {
		return
	}
	markTaintFromOperands(tainted, inst.Name, inst.GetOperands())
}

// visitMapUpdate handles the go.map.update intrinsic (m[k] = v). A tainted
// value taints the map's register (and any enclosing container), so a later
// go.map.lookup read observes it. go.map.update is a void instruction, so
// there is no result register to taint — we taint the map operand instead,
// mirroring visitStore.
func visitMapUpdate(inst *ir.Instruction, defs map[string]*ir.Instruction, tainted map[string]*ir.Position) {
	ops := inst.GetOperands()
	if len(ops) < 3 {
		return
	}
	pos, ok := isTainted(tainted, ops[2])
	if !ok {
		return
	}
	reg := ops[0].GetRegName()
	if reg == "" {
		return
	}
	markTainted(tainted, reg, pos)
	taintContainer(defs, tainted, reg, pos)
}

// isTainted reports whether operand v refers to a tainted register, and if
// so, the Position it originated from.
func isTainted(tainted map[string]*ir.Position, v *ir.Value) (*ir.Position, bool) {
	if v == nil {
		return nil, false
	}
	reg := v.GetRegName()
	if reg == "" {
		return nil, false
	}
	pos, ok := tainted[reg]
	return pos, ok
}

// firstTaintedOrigin scans vals in order and returns the origin Position of
// the first tainted value found.
func firstTaintedOrigin(tainted map[string]*ir.Position, vals []*ir.Value) (*ir.Position, bool) {
	for _, v := range vals {
		if pos, ok := isTainted(tainted, v); ok {
			return pos, true
		}
	}
	return nil, false
}

// markTainted records reg as tainted with the given origin, unless it is
// already tainted (taint is monotonic; the first-recorded origin wins so
// fixpoint iteration keeps converging).
func markTainted(tainted map[string]*ir.Position, reg string, pos *ir.Position) {
	if reg == "" {
		return
	}
	if _, exists := tainted[reg]; exists {
		return
	}
	tainted[reg] = pos
}

// markTaintFromOperands marks `name` tainted (with the origin of the first
// tainted operand) if name is non-empty and any operand is tainted.
func markTaintFromOperands(tainted map[string]*ir.Position, name string, operands []*ir.Value) {
	if name == "" {
		return
	}
	if pos, ok := firstTaintedOrigin(tainted, operands); ok {
		markTainted(tainted, name, pos)
	}
}
