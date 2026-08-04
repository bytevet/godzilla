// Package ssabuild constructs pruned, minimal SSA form for a single function
// while the caller walks a structured AST, following Braun, Buchwald, Hack et
// al. "Simple and Efficient Construction of SSA Form" (CC 2013).
//
// # Why this package exists
//
// A frontend that lowers into one block with a flat variable->value environment
// drops branch bodies, cannot model loop-carried values, and never exercises the
// engine's dominator-based guard precision. This package generalizes that env map
// into a per-block map of current definitions with PHI nodes inserted on demand,
// so a frontend can emit a real CFG (blocks + preds/succs + OP_CODE_IF/JUMP/PHI)
// byte-for-byte the shape the Go frontend emits and the taint engine consumes. It
// depends only on the gIR value type (pkg/ir/v1) and knows nothing about any
// source language.
//
// # The algorithm (Braun et al.)
//
// SSA is built during the AST walk, not by a separate dominance-frontier pass:
//
//   - WriteVariable(name, block, value) records, for a source-level variable, the
//     value that is current at the end of (so far) that block.
//   - ReadVariable(name, block) returns the value current in that block. If the
//     block has a local definition it is returned directly. Otherwise the value
//     must come from the block's predecessors (readVariableRecursive):
//     a SEALED block with one predecessor forwards that predecessor's value;
//     a SEALED block with >=2 predecessors gets a fresh operandless PHI (recorded
//     immediately to break cycles), then one operand per predecessor, then
//     removeTrivialPhi; an UNSEALED block (a loop header whose back-edge
//     predecessors are not yet known) gets an "incomplete" PHI that is filled in
//     later when the block is sealed.
//   - Seal(block) is called once ALL of a block's predecessors are known. It
//     fills every incomplete PHI of that block with operands and runs
//     removeTrivialPhi. Loop headers are created, their body built (which reads
//     the loop variables through the header and parks incomplete PHIs), and then
//     sealed once the back-edge is wired — this is how loop-carried values get
//     their PHIs with no dominance computation.
//   - removeTrivialPhi eliminates a PHI all of whose operands are the same value
//     (or self-references): it is replaced by that single value and every user
//     (including other PHIs, which are then re-checked) is rewritten. This keeps
//     the result minimal.
//
// # CFG shape and determinism
//
// SetIf / SetJump set a block's terminator and, as a side effect, record the CFG
// edges (a block is added as a predecessor of each successor). Finish()
// materializes []*ir.BasicBlock: PHIs first (parallel operands + "b<idx>"
// predecessor labels, matching the Go frontend's blockName), then the caller's
// body instructions (AddInstr), then the terminator (OP_CODE_IF with successors
// ordered [trueTarget, falseTarget]; OP_CODE_JUMP; or none for a block that just
// returns). Block ids are sequential ints (BasicBlock.Index). All map iteration
// is done over sorted keys, so output is byte-stable across runs.
//
// A function with no branches produces exactly ONE block (no PHIs, no
// terminator inserted by the builder), so straight-line handlers keep the
// engine's single-block linear fast path and cost nothing extra.
package ssabuild

import (
	"sort"
	"strconv"

	ir "godzilla/pkg/ir/v1"
)

// BlockID identifies a basic block within one Builder. Ids are sequential ints
// starting at 0 (the order NewBlock is called), and become BasicBlock.Index.
type BlockID int

type blockData struct {
	id BlockID

	preds []BlockID // filled by SetIf/SetJump on predecessors, in edge order

	// terminator
	term termKind
	cond *ir.Value // IF condition
	tBlk BlockID   // IF true target
	fBlk BlockID   // IF false target / JUMP target
	body []*ir.Instruction

	phis []*phi // PHIs living at the head of this block, in creation order

	// Per-block SSA-construction state (Braun et al.). BlockID is a dense index
	// into Builder.blocks, so this state belongs on the block itself rather than
	// in three parallel maps keyed by id.
	defs       map[string]*ir.Value // current definition of each variable in this block
	sealed     bool                 // every predecessor of this block is known
	incomplete map[string]*phi      // PHIs parked while unsealed, by variable
}

type termKind int

const (
	termNone termKind = iota
	termIf
	termJump
)

type phi struct {
	name     string
	variable string
	block    BlockID
	operands []*ir.Value
	blocks   []BlockID     // predecessor per operand, parallel to operands
	users    map[*phi]bool // other phis that reference this one as an operand
	removed  bool
	val      *ir.Value // cached &Value{reg_name:name}
}

func (p *phi) value() *ir.Value {
	if p.val == nil {
		p.val = Reg(p.name)
	}
	return p.val
}

// Builder incrementally constructs SSA for one function. It is not safe for
// concurrent use; build one function per Builder.
type Builder struct {
	blocks []*blockData

	// replacements maps a removed PHI's register name to the value it collapsed
	// to; resolve() follows these chains so no reference to a removed PHI ever
	// reaches the output.
	replacements map[string]*ir.Value
	phiByName    map[string]*phi

	phiCount int
}

// NewBuilder returns an empty Builder with no blocks. Call NewBlock to create
// the entry block (and every other block).
func NewBuilder() *Builder {
	return &Builder{
		replacements: map[string]*ir.Value{},
		phiByName:    map[string]*phi{},
	}
}

func (b *Builder) NewBlock() BlockID {
	id := BlockID(len(b.blocks))
	// defs/incomplete are allocated eagerly rather than lazily: WriteVariable and
	// readVariableRecursive write them directly, and a write to a nil map panics.
	b.blocks = append(b.blocks, &blockData{
		id:         id,
		defs:       map[string]*ir.Value{},
		incomplete: map[string]*phi{},
	})
	return id
}

// AddInstr appends a caller-produced body instruction to a block, in order.
// Body instructions are emitted after the block's PHIs and before its terminator.
// The builder inspects them only to resolve operands that referenced a PHI which
// was later eliminated.
func (b *Builder) AddInstr(block BlockID, inst *ir.Instruction) {
	b.blocks[block].body = append(b.blocks[block].body, inst)
}

// SetIf makes `block` end in a two-way branch on cond, recording block as a
// predecessor of both targets. Successors are emitted [trueBlk, falseBlk].
func (b *Builder) SetIf(block BlockID, cond *ir.Value, trueBlk, falseBlk BlockID) {
	bd := b.blocks[block]
	bd.term = termIf
	bd.cond = cond
	bd.tBlk = trueBlk
	bd.fBlk = falseBlk
	b.addEdge(block, trueBlk)
	b.addEdge(block, falseBlk)
}

// SetJump makes `block` end in an unconditional jump to target, recording block
// as a predecessor of target.
func (b *Builder) SetJump(block BlockID, target BlockID) {
	bd := b.blocks[block]
	bd.term = termJump
	bd.fBlk = target
	b.addEdge(block, target)
}

func (b *Builder) addEdge(from, to BlockID) {
	b.blocks[to].preds = append(b.blocks[to].preds, from)
}

// WriteVariable records value as the current definition of name in block.
func (b *Builder) WriteVariable(name string, block BlockID, value *ir.Value) {
	b.blocks[block].defs[name] = value
}

// ReadVariable returns the value current for name in block, inserting PHIs on
// demand (and eliminating any that turn out trivial) so the result is the
// correct SSA value reaching that block.
func (b *Builder) ReadVariable(name string, block BlockID) *ir.Value {
	if v, ok := b.blocks[block].defs[name]; ok {
		return b.resolve(v)
	}
	return b.readVariableRecursive(name, block)
}

func (b *Builder) readVariableRecursive(name string, block BlockID) *ir.Value {
	bd := b.blocks[block]
	var val *ir.Value
	switch {
	case !bd.sealed:
		// Predecessors not yet all known: park an incomplete PHI.
		p := b.newPhi(name, block)
		bd.incomplete[name] = p
		val = p.value()
	case len(bd.preds) == 0:
		// Sealed entry with no def: variable is undefined on this path.
		val = undefValue()
	case len(bd.preds) == 1:
		val = b.ReadVariable(name, bd.preds[0])
	default:
		p := b.newPhi(name, block)
		// Record before adding operands to break read cycles (loops).
		b.WriteVariable(name, block, p.value())
		val = b.addPhiOperands(p)
	}
	b.WriteVariable(name, block, val)
	return val
}

// Seal marks a block: all of its predecessors are now known. Any incomplete
// PHIs are given their operands and simplified. Idempotent.
func (b *Builder) Seal(block BlockID) {
	bd := b.blocks[block]
	if bd.sealed {
		return
	}
	// Deterministic order over the parked variables.
	pending := bd.incomplete
	names := make([]string, 0, len(pending))
	for name := range pending {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b.addPhiOperands(pending[name])
	}
	// Only readVariableRecursive's !sealed branch writes incomplete, so once the
	// block is sealed nothing can park another PHI here.
	bd.incomplete = nil
	bd.sealed = true
}

// Finish materializes the SSA CFG as []*ir.BasicBlock, in id order, with all
// operands resolved through the trivial-PHI replacement chains. Call once, after
// every block has been sealed and terminated.
func (b *Builder) Finish() []*ir.BasicBlock {
	out := make([]*ir.BasicBlock, 0, len(b.blocks))
	for _, bd := range b.blocks {
		blk := &ir.BasicBlock{Index: int32(bd.id)}
		if n := len(bd.preds); n > 0 {
			blk.Preds = make([]int32, n)
			for i, p := range bd.preds {
				blk.Preds[i] = int32(p)
			}
		}
		switch bd.term {
		case termIf:
			blk.Succs = []int32{int32(bd.tBlk), int32(bd.fBlk)}
		case termJump:
			blk.Succs = []int32{int32(bd.fBlk)}
		}

		// PHIs first.
		for _, p := range bd.phis {
			if p.removed {
				continue
			}
			inst := &ir.Instruction{
				Name: p.name,
				Op:   ir.OpCode_OP_CODE_PHI,
			}
			for i, op := range p.operands {
				inst.Operands = append(inst.Operands, b.resolve(op))
				inst.Blocks = append(inst.Blocks, blockLabel(p.blocks[i]))
			}
			blk.Instrs = append(blk.Instrs, inst)
		}

		// Body instructions, with operands resolved.
		for _, inst := range bd.body {
			b.resolveInstr(inst)
			blk.Instrs = append(blk.Instrs, inst)
		}

		// Terminator last.
		switch bd.term {
		case termIf:
			blk.Instrs = append(blk.Instrs, &ir.Instruction{
				Op:         ir.OpCode_OP_CODE_IF,
				Operands:   []*ir.Value{b.resolve(bd.cond)},
				TrueBlock:  blockLabel(bd.tBlk),
				FalseBlock: blockLabel(bd.fBlk),
			})
		case termJump:
			blk.Instrs = append(blk.Instrs, &ir.Instruction{
				Op:        ir.OpCode_OP_CODE_JUMP,
				JumpBlock: blockLabel(bd.fBlk),
			})
		}

		out = append(out, blk)
	}
	return out
}

// --- PHI machinery -------------------------------------------------------

func (b *Builder) newPhi(name string, block BlockID) *phi {
	p := &phi{
		name:     "__phi" + strconv.Itoa(b.phiCount),
		variable: name,
		block:    block,
		users:    map[*phi]bool{},
	}
	b.phiCount++
	b.phiByName[p.name] = p
	b.blocks[block].phis = append(b.blocks[block].phis, p)
	return p
}

func (b *Builder) addPhiOperands(p *phi) *ir.Value {
	for _, pred := range b.blocks[p.block].preds {
		op := b.resolve(b.ReadVariable(p.variable, pred))
		p.operands = append(p.operands, op)
		p.blocks = append(p.blocks, pred)
		if src := b.livePhi(op); src != nil && src != p {
			src.users[p] = true
		}
	}
	return b.tryRemoveTrivialPhi(p)
}

// tryRemoveTrivialPhi implements Algorithm 2 of Braun et al.: a PHI whose
// operands are all one value (ignoring self-references) is replaced by that
// value, and users are rewritten and re-checked. Returns the value the PHI
// resolves to (itself if it is not trivial).
func (b *Builder) tryRemoveTrivialPhi(p *phi) *ir.Value {
	var same *ir.Value
	for _, op := range p.operands {
		op = b.resolve(op)
		if valEq(op, p.value()) || (same != nil && valEq(op, same)) {
			continue // self-reference or duplicate operand
		}
		if same != nil {
			return p.value() // merges two distinct values: not trivial
		}
		same = op
	}
	if same == nil {
		// The PHI had no real operands (unreachable / undefined).
		same = undefValue()
	}

	p.removed = true
	b.replacements[p.name] = same

	// Collect phi users other than self, deterministically.
	users := make([]*phi, 0, len(p.users))
	for u := range p.users {
		if u != p && !u.removed {
			users = append(users, u)
		}
	}
	sort.Slice(users, func(i, j int) bool { return users[i].name < users[j].name })

	// Rewrite this PHI out of every user's operands.
	for _, u := range users {
		for i, op := range u.operands {
			if op.GetRegName() == p.name {
				u.operands[i] = same
				if sp := b.livePhi(same); sp != nil && sp != u {
					sp.users[u] = true
				}
			}
		}
	}
	// Re-check users, which may have become trivial.
	for _, u := range users {
		if !u.removed {
			b.tryRemoveTrivialPhi(u)
		}
	}
	return same
}

// resolve follows trivial-PHI replacement chains to a final value.
func (b *Builder) resolve(v *ir.Value) *ir.Value {
	for i := 0; v != nil && i <= len(b.replacements); i++ {
		name := v.GetRegName()
		if name == "" {
			return v
		}
		next, ok := b.replacements[name]
		if !ok {
			return v
		}
		v = next
	}
	return v
}

func (b *Builder) resolveInstr(inst *ir.Instruction) {
	for i, op := range inst.Operands {
		inst.Operands[i] = b.resolve(op)
	}
	if c := inst.Call; c != nil {
		if c.Value != nil {
			c.Value = b.resolve(c.Value)
		}
		for i, a := range c.Args {
			c.Args[i] = b.resolve(a)
		}
	}
	for i, cs := range inst.Cases {
		if cs.Value != nil {
			inst.Cases[i].Value = b.resolve(cs.Value)
		}
	}
}

// livePhi returns the not-yet-removed PHI a value names, or nil.
func (b *Builder) livePhi(v *ir.Value) *phi {
	if v == nil {
		return nil
	}
	if name := v.GetRegName(); name != "" {
		if p, ok := b.phiByName[name]; ok && !p.removed {
			return p
		}
	}
	return nil
}

// --- value helpers -------------------------------------------------------

// undefValue represents a read of an undefined variable (a value reaching a
// point on no real path). Well-formed input should not produce one.
func undefValue() *ir.Value {
	return Reg("__undef")
}

// blockLabel is the gIR label for a block ("b<index>"), naming a PHI's
// predecessor and a terminator's targets. The format matches the Go frontend's
// blockName, so every frontend's blocks are labelled identically.
func blockLabel(id BlockID) string {
	return "b" + strconv.Itoa(int(id))
}

// valEq reports whether two operand values are the same SSA value: same
// register/global/func name, or equal constant.
func valEq(a, b *ir.Value) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if n := a.GetRegName(); n != "" || b.GetRegName() != "" {
		return n == b.GetRegName()
	}
	if n := a.GetGlobalName(); n != "" || b.GetGlobalName() != "" {
		return n == b.GetGlobalName()
	}
	if n := a.GetFuncName(); n != "" || b.GetFuncName() != "" {
		return n == b.GetFuncName()
	}
	ca, cb := a.GetConstant(), b.GetConstant()
	if ca == nil || cb == nil {
		return ca == cb
	}
	return constKey(ca) == constKey(cb)
}

func constKey(c *ir.Constant) string {
	if c.GetIsNil() {
		return "nil"
	}
	switch v := c.GetValue().(type) {
	case *ir.Constant_BoolVal:
		return "b:" + strconv.FormatBool(v.BoolVal)
	case *ir.Constant_IntVal:
		return "i:" + strconv.FormatInt(v.IntVal, 10)
	case *ir.Constant_FloatVal:
		return "f:" + strconv.FormatFloat(v.FloatVal, 'g', -1, 64)
	case *ir.Constant_StringVal:
		return "s:" + v.StringVal
	default:
		return "?"
	}
}
