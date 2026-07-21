package analysis

import (
	"strconv"
	"strings"

	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// Engine runs taint analysis over a gIR program for a fixed set of rules.
// Analysis is inter-procedural; see interproc.go for the orchestration.
type Engine struct {
	rs *rules.RuleSet
	// reportable, when non-empty, restricts the worklist SEED to functions in
	// these (user-authored) packages: dependency functions are then analyzed
	// DEMAND-DRIVEN — only when taint actually reaches them via a call — instead
	// of proactively analyzing the whole lowered dependency closure. Empty means
	// seed every function (the default when no dependencies were lowered).
	reportable map[string]bool
}

// NewEngine builds an Engine that will evaluate every rule in rs.
func NewEngine(rs *rules.RuleSet) *Engine {
	return &Engine{rs: rs}
}

// ScopeSeed restricts the worklist seed to the given (user-authored) packages,
// so lowered dependency functions are analyzed only when taint reaches them.
// Returns the engine for chaining. A nil/empty set seeds every function.
func (e *Engine) ScopeSeed(reportable map[string]bool) *Engine {
	e.reportable = reportable
	return e
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
	ir.OpCode_OP_CODE_BIN_OP:      true,
	ir.OpCode_OP_CODE_UN_OP:       true,
	ir.OpCode_OP_CODE_CONVERT:     true,
	ir.OpCode_OP_CODE_TYPE_ASSERT: true, // v := x.(T): the result is x's value with a narrower static type
	// FIELD / FIELD_ADDR are NOT here: struct-field reads are handled
	// field-sensitively by visitFieldRead so tainting one field does not taint a
	// read of a different field (see ENG-3). INDEX(_ADDR) stay whole-container
	// (array elements can't be statically distinguished — variadic packing).
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
//
// A clean store (a non-tainted value) into a non-escaping alloc is a STRONG
// UPDATE (ENG-2): it fully overwrites the cell, so the cell's prior taint is
// cleared on this path. This is what makes the flow-sensitive pass reject the
// "taint, then overwrite with a constant, then use" false positive that a
// monotonic (never-un-taint) model cannot. It is applied only to non-escaping
// allocs — where no alias can hold the taint — so no real flow is lost.
func visitStore(inst *ir.Instruction, defs map[string]*ir.Instruction, tainted taintState, nonEscaping map[string]bool) {
	operands := inst.GetOperands()
	if len(operands) < 2 {
		return
	}
	addr, val := operands[0], operands[1]
	addrReg := addr.GetRegName()
	if addrReg == "" {
		return
	}
	pos, ok := isTainted(tainted, val)
	if !ok {
		if nonEscaping[addrReg] {
			delete(tainted, addrReg)
			clearFieldPaths(tainted, addrReg)
		}
		return
	}
	markTainted(tainted, addrReg, pos)
	// Storing a tainted value into an element/field address taints the whole
	// container, so a later read of the container (e.g. arr[:] for variadic
	// packing, or a struct field load) observes the taint. Walk the
	// address-derivation chain to taint every enclosing aggregate base.
	taintContainer(defs, tainted, addrReg, pos)
}

// clearFieldPaths removes every one-level access-path key (base#f…, base#*)
// rooted at base from the taint state — the field-precise companion to clearing
// base itself in a strong update.
func clearFieldPaths(tainted taintState, base string) {
	prefix := base + "#"
	for k := range tainted {
		if strings.HasPrefix(k, prefix) {
			delete(tainted, k)
		}
	}
}

// fieldPathKey is the taint-map key for a specific struct field of a base
// register — a one-level access path. Register names never contain '#', so a
// path key can't collide with a plain register.
func fieldPathKey(base string, idx int32) string {
	return base + "#f" + strconv.Itoa(int(idx))
}

// fieldAnyKey marks that a base register has SOME tainted field. It is consulted
// ONLY when the base is passed to a function (isTaintedArg), not by field reads
// — so intra-procedurally a clean field of the struct stays clean (ENG-3), but
// passing the whole struct across a call still carries the field taint into the
// callee (which then sees the parameter wholesale-tainted, its Medium-confidence
// over-approximation). This preserves cross-function struct-field recall.
func fieldAnyKey(base string) string {
	return base + "#*"
}

// isTaintedArg reports whether a call argument carries taint for the purpose of
// seeding a callee parameter: either the whole value is tainted, or the value's
// register carries the any-field marker (a struct with at least one tainted field
// stored directly into it). Field reads use isTainted (precise); only cross-call
// seeding uses this broader check.
func isTaintedArg(tainted taintState, v *ir.Value) (*ir.Position, bool) {
	if pos, ok := isTainted(tainted, v); ok {
		return pos, true
	}
	if v != nil {
		if reg := v.GetRegName(); reg != "" {
			if pos, ok := tainted[fieldAnyKey(reg)]; ok {
				return pos, true
			}
		}
	}
	return nil, false
}

// isAggregateAccess reports whether an instruction is a FIELD/INDEX (value or
// address) access — used to tell a "root" base (an alloc/param) apart from a
// nested access.
func isAggregateAccess(def *ir.Instruction) bool {
	if def == nil {
		return false
	}
	switch def.Op {
	case ir.OpCode_OP_CODE_FIELD, ir.OpCode_OP_CODE_FIELD_ADDR,
		ir.OpCode_OP_CODE_INDEX, ir.OpCode_OP_CODE_INDEX_ADDR:
		return true
	}
	return false
}

// taintContainer walks up the address-derivation chain from reg (produced by
// INDEX_ADDR/FIELD_ADDR/INDEX/FIELD) and records the taint a store just wrote.
// For a one-level STRUCT field on a root base (p.f = x, where p is an
// alloc/param), it records the precise access path base#f rather than tainting
// the whole struct — so a later read of a DIFFERENT field is not falsely
// tainted (ENG-3). Array elements (INDEX) stay field-insensitive (whole
// container), since elements can't be statically distinguished (variadic slice
// packing), and nested field accesses fall back to whole-container too (a
// one-level path can't name them precisely), preserving recall.
func taintContainer(defs map[string]*ir.Instruction, tainted taintState, reg string, pos *ir.Position) {
	seen := map[string]bool{}
	for reg != "" && !seen[reg] {
		seen[reg] = true
		def := defs[reg]
		if def == nil {
			return
		}
		switch def.Op {
		case ir.OpCode_OP_CODE_FIELD_ADDR, ir.OpCode_OP_CODE_FIELD:
			ops := def.GetOperands()
			if len(ops) == 0 {
				return
			}
			base := ops[0].GetRegName()
			if base == "" {
				return
			}
			if isAggregateAccess(defs[base]) {
				// Nested (p.q.f): a one-level path can't name it; fall back to
				// whole-container to preserve recall, and keep walking up.
				markTainted(tainted, base, pos)
				reg = base
				continue
			}
			// One-level struct field on a root base: field-precise for reads,
			// plus the any-field marker so passing the whole struct to a call
			// still carries the taint into the callee.
			markTainted(tainted, fieldPathKey(base, def.GetFieldIndex()), pos)
			markTainted(tainted, fieldAnyKey(base), pos)
			return
		case ir.OpCode_OP_CODE_INDEX_ADDR, ir.OpCode_OP_CODE_INDEX:
			ops := def.GetOperands()
			if len(ops) == 0 {
				return
			}
			base := ops[0].GetRegName()
			if base == "" {
				return
			}
			markTainted(tainted, base, pos) // array: whole container
			reg = base
		default:
			return
		}
	}
}

// rootBaseReg walks the address-derivation chain from reg (through
// FIELD(_ADDR)/INDEX(_ADDR) accesses) to the ultimate root register — the base
// an aggregate access is rooted at. It is used to tell whether a STORE writes
// into memory reachable from a function parameter (ENG-6b: out-parameter fill),
// by resolving the store address back to its root and checking it is a param.
func rootBaseReg(defs map[string]*ir.Instruction, reg string) string {
	seen := map[string]bool{}
	for reg != "" && !seen[reg] {
		seen[reg] = true
		def := defs[reg]
		if def == nil {
			return reg
		}
		if !isAggregateAccess(def) {
			return reg
		}
		ops := def.GetOperands()
		if len(ops) == 0 {
			return reg
		}
		base := ops[0].GetRegName()
		if base == "" {
			return reg
		}
		reg = base
	}
	return reg
}

// visitFieldRead handles a FIELD / FIELD_ADDR read field-sensitively: the result
// is tainted if the specific field's access path (base#f) was tainted, OR if the
// whole base value is untrusted (e.g. a struct that came straight from a source
// or a seeded parameter). This is what stops a tainted p.A from falsely tainting
// a read of the clean p.B (ENG-3), while still flagging p.A and any field of a
// wholly-untrusted struct.
func visitFieldRead(inst *ir.Instruction, tainted taintState) {
	if inst.Name == "" {
		return
	}
	ops := inst.GetOperands()
	if len(ops) == 0 {
		return
	}
	base := ops[0].GetRegName()
	if base == "" {
		// Non-register base (e.g. a global): can't form a path key, so fall back
		// to the conservative operand propagation.
		markTaintFromOperands(tainted, inst.Name, ops)
		return
	}
	if pos, ok := tainted[fieldPathKey(base, inst.GetFieldIndex())]; ok {
		markTainted(tainted, inst.Name, pos)
		return
	}
	if pos, ok := tainted[base]; ok {
		markTainted(tainted, inst.Name, pos)
	}
}

func visitIntrinsic(inst *ir.Instruction, defs map[string]*ir.Instruction, tainted taintState) {
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
func visitMapUpdate(inst *ir.Instruction, defs map[string]*ir.Instruction, tainted taintState) {
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

// reconstructPath best-effort recovers the taint path from source to sink by
// walking the def-use chain backward from the sink's tainted argument, following
// the first tainted operand at each hop and collecting each defining
// instruction's position. It returns the path ordered source -> ... -> sink
// (with srcPos first and sinkPos last), consecutive duplicates removed. The walk
// is bounded and stops at a register with no tainted operand (a source result, a
// seeded parameter, or an opaque value), so the result may be a partial
// intra-procedural segment — good enough to render a data flow.
func reconstructPath(defs map[string]*ir.Instruction, tainted taintState, argReg string, srcPos, sinkPos *ir.Position) []*ir.Position {
	var rev []*ir.Position // sink -> ... -> source order while walking
	if sinkPos != nil {
		rev = append(rev, sinkPos)
	}
	seen := map[string]bool{}
	for reg := argReg; reg != "" && !seen[reg]; {
		seen[reg] = true
		def := defs[reg]
		if def == nil {
			break
		}
		if p := def.GetPos(); p != nil {
			rev = append(rev, p)
		}
		reg = firstTaintedOperandReg(tainted, def)
	}
	if srcPos != nil {
		rev = append(rev, srcPos)
	}
	// Reverse to source -> sink and drop consecutive duplicate positions.
	path := make([]*ir.Position, 0, len(rev))
	for i := len(rev) - 1; i >= 0; i-- {
		if len(path) > 0 && samePos(path[len(path)-1], rev[i]) {
			continue
		}
		path = append(path, rev[i])
	}
	return path
}

// firstTaintedOperandReg returns the register name of def's first tainted
// operand (including the receiver of a method call), or "" if none.
func firstTaintedOperandReg(tainted taintState, def *ir.Instruction) string {
	if def.Call != nil {
		if v := def.Call.GetValue(); v != nil {
			if reg := v.GetRegName(); reg != "" {
				if _, ok := tainted[reg]; ok {
					return reg
				}
			}
		}
		for _, a := range def.Call.GetArgs() {
			if reg := a.GetRegName(); reg != "" {
				if _, ok := tainted[reg]; ok {
					return reg
				}
			}
		}
	}
	for _, op := range def.GetOperands() {
		if reg := op.GetRegName(); reg != "" {
			if _, ok := tainted[reg]; ok {
				return reg
			}
		}
	}
	return ""
}

// samePos reports whether two positions point at the same file:line:col.
func samePos(a, b *ir.Position) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.GetFilename() == b.GetFilename() && a.GetLine() == b.GetLine() && a.GetColumn() == b.GetColumn()
}

// isTainted reports whether operand v refers to a tainted register, and if
// so, the Position it originated from.
func isTainted(tainted taintState, v *ir.Value) (*ir.Position, bool) {
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

// firstTainted scans vals in order and returns the register and origin
// Position of the first tainted value found. Both were previously separate
// scans (firstTaintedReg / firstTaintedOrigin) with the identical predicate,
// run back-to-back over the same slice on the sink path.
func firstTainted(tainted taintState, vals []*ir.Value) (reg string, pos *ir.Position, ok bool) {
	for _, v := range vals {
		if p, hit := isTainted(tainted, v); hit {
			return v.GetRegName(), p, true
		}
	}
	return "", nil, false
}

// markTainted records reg as tainted with the given origin, unless it is
// already tainted (taint is monotonic; the first-recorded origin wins so
// fixpoint iteration keeps converging).
func markTainted(tainted taintState, reg string, pos *ir.Position) {
	if reg == "" {
		return
	}
	if _, exists := tainted[reg]; exists {
		return
	}
	tainted[reg] = pos
}

// isByteOrRuneSlice reports whether t is a []byte or []rune (a slice of uint8 or
// int32), including a named type whose underlying type is such a slice. It gates
// the `builtin.append` propagator to character-level string reconstruction so
// append is not a blanket taint carrier across every slice in a program.
func isByteOrRuneSlice(t *ir.Type) bool {
	if t == nil {
		return false
	}
	if t.GetKind() == ir.TypeKind_TYPE_KIND_NAMED {
		if u := t.GetUnderlyingType(); u != nil {
			t = u
		}
	}
	if t.GetKind() != ir.TypeKind_TYPE_KIND_SLICE {
		return false
	}
	el := t.GetElemType()
	if el == nil || el.GetKind() != ir.TypeKind_TYPE_KIND_BASIC {
		return false
	}
	k := el.GetBasicKind()
	return k == ir.BasicTypeKind_BASIC_TYPE_KIND_UINT8 || k == ir.BasicTypeKind_BASIC_TYPE_KIND_INT32
}

// markTaintFromOperands marks `name` tainted (with the origin of the first
// tainted operand) if name is non-empty and any operand is tainted.
func markTaintFromOperands(tainted taintState, name string, operands []*ir.Value) {
	if name == "" {
		return
	}
	if _, pos, ok := firstTainted(tainted, operands); ok {
		markTainted(tainted, name, pos)
	}
}
