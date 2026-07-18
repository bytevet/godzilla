package java_converter

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	ir "godzilla/pkg/ir/v1"
)

// convertClass turns one dumped class into a gIR module (one function per method).
func convertClass(cl dumpClass, filename string) *ir.Module {
	mod := &ir.Module{Name: cl.Name, Language: "java"}
	for _, m := range cl.Methods {
		mod.Functions = append(mod.Functions, convertMethod(cl.Name, m, filename))
	}
	return mod
}

// methodState holds the operand-stack simulation state for one method.
type methodState struct {
	filename  string
	className string
	counter   int
	stack     []*ir.Value
	locals    map[int]*ir.Value
	instrs    []*ir.Instruction
}

// convertMethod simulates the JVM operand stack over a method's bytecode to
// recover SSA-style values, emitting one straight-line gIR basic block. Control
// flow is flattened (like the Python/JS frontends), which is sufficient for the
// common source→sink handler shape.
func convertMethod(className string, m dumpMethod, filename string) *ir.Function {
	s := &methodState{filename: filename, className: className, locals: map[int]*ir.Value{}}

	fn := &ir.Function{
		Name:          className + "." + m.Name,
		ObjectName:    m.Name,
		PackageName:   className,
		CanonicalName: "java:" + className + "." + m.Name,
	}

	// Local-slot layout: for an instance method, slot 0 is the receiver `this`
	// (the engine maps an INVOKE receiver to param 0), then the declared
	// parameters. Each is bound to a parameter register so a tainted argument at
	// a call site flows into the callee. Slot advancement uses slotWidth(pt):
	// long/double occupy two local slots, everything else one, so subsequent
	// parameters land on their correct slots (see the `slot += slotWidth(pt)`
	// below). Taint itself is width-agnostic — the width only affects slot index.
	slot := 0
	if !m.Static {
		this := regValue("this")
		fn.Params = append(fn.Params, this)
		s.locals[0] = this
		slot = 1
	}
	for i, pt := range parseParams(m.Descriptor) {
		name := fmt.Sprintf("p%d", i)
		v := regValue(name)
		fn.Params = append(fn.Params, v)
		s.locals[slot] = v
		// A parameter carrying framework annotations (e.g. Spring's
		// @RequestParam) is untrusted input read outside this program's own
		// call graph. The engine only seeds taint at a CALL matching a source
		// glob, so we synthesize one — the same trick the JS/Python frontends
		// use for opaque-base member reads — and rebind the slot to its (now
		// tainted) result so every LOAD of this parameter carries taint.
		if i < len(m.ParamAnnotations) && len(m.ParamAnnotations[i]) > 0 {
			s.locals[slot] = s.annotatedParamSource(m.ParamAnnotations[i], s.pos(entryLine(m)))
		}
		slot += slotWidth(pt)
	}

	s.run(m.Instrs)
	fn.Blocks = []*ir.BasicBlock{{Index: 0, Instrs: s.instrs}}
	return fn
}

// annotatedParamSource emits, at method entry, one synthetic source CALL per
// annotation on a parameter (callee "java:<annotation-internal-name>", e.g.
// "java:org/springframework/web/bind/annotation/RequestParam"), which a rule's
// `sources` glob can match. It returns the value the parameter slot should
// resolve to: the single call's result, or a PHI over all of them so the slot is
// tainted iff any annotation is a source (a parameter may also carry unrelated
// annotations like @Valid).
func (s *methodState) annotatedParamSource(anns []string, pos *ir.Position) *ir.Value {
	results := make([]*ir.Value, 0, len(anns))
	for _, ann := range anns {
		callee := "java:" + ann
		r := s.reg()
		s.instrs = append(s.instrs, &ir.Instruction{
			Name: r,
			Op:   ir.OpCode_OP_CODE_CALL,
			Call: &ir.CallCommon{
				Callee: callee,
				Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}},
			},
			Pos: pos,
		})
		results = append(results, regValue(r))
	}
	if len(results) == 1 {
		return results[0]
	}
	phi := s.reg()
	s.instrs = append(s.instrs, &ir.Instruction{Name: phi, Op: ir.OpCode_OP_CODE_PHI, Operands: results, Pos: pos})
	return regValue(phi)
}

// entryLine returns the first source line recorded in a method's bytecode, used
// to position the synthesized parameter-source call for reporting.
func entryLine(m dumpMethod) int {
	for _, in := range m.Instrs {
		if in.Line > 0 {
			return in.Line
		}
	}
	return 0
}

// run lowers a method body. For straight-line code (no branch targets) it is a
// single linear operand-stack simulation, identical to the original frontend.
// When the method has control flow it is lowered block-by-block over the
// reconstructed CFG, merging the operand stack and locals at each join with
// OP_CODE_PHI (FE-4) — so a branch-selected value (`cond ? tainted : default`,
// an if/else assignment) is no longer silently dropped, and the stack stays
// aligned past the join instead of garbling every later instruction.
func (s *methodState) run(instrs []dumpInstr) {
	blocks, labelIdx := splitBlocks(instrs)
	if len(blocks) <= 1 {
		for _, in := range instrs {
			s.step(in)
		}
		return
	}
	s.runBlocks(blocks, labelIdx)
}

// step lowers one instruction against the current operand-stack state.
func (s *methodState) step(in dumpInstr) {
	pos := s.pos(in.Line)
	switch in.Op {
	case "LABEL":
		// Block marker only (FE-4); no stack effect.
	case "SWITCH":
		s.pop() // the switch key
	case "LOAD":
		s.push(s.load(in.Slot))
	case "STORE":
		s.locals[in.Slot] = s.pop()
	case "CONST":
		// Model every constant as a string: harmless for taint and lets the
		// secrets scanner see string literals.
		s.push(constString(in.Cst))
	case "INVOKE":
		s.invoke(in, pos)
	case "INVOKEDYNAMIC":
		s.invokeDynamic(in, pos)
	case "FIELD":
		s.field(in, pos)
	case "NEW":
		s.push(s.emit("", ir.OpCode_OP_CODE_ALLOC, nil, pos))
	case "NEWARRAY":
		s.pop() // count/dims
		s.push(s.emit("", ir.OpCode_OP_CODE_ALLOC, nil, pos))
	case "ARRAYLOAD":
		s.pop()        // index
		arr := s.pop() // array ref
		s.push(s.emit(s.reg(), ir.OpCode_OP_CODE_INDEX, []*ir.Value{arr}, pos))
	case "ARRAYSTORE":
		val := s.pop()
		s.pop()                                                         // index
		arr := s.pop()                                                  // array ref
		s.emit("", ir.OpCode_OP_CODE_STORE, []*ir.Value{arr, val}, pos) // element taint → array
	case "OPERATOR":
		s.operator(in, pos)
	case "CONVERT":
		v := s.pop()
		s.push(s.emit(s.reg(), ir.OpCode_OP_CODE_CONVERT, []*ir.Value{v}, pos))
	case "STACK":
		s.stackOp(in.Kind)
	case "TYPECHECK":
		// CHECKCAST leaves the value (narrower static type); INSTANCEOF pops a
		// ref and pushes an int.
		if in.Kind == "INSTANCEOF" {
			s.pop()
			s.push(constString("0"))
		}
	case "RETURN":
		s.ret(in, pos)
	case "THROW":
		s.pop()
	case "BRANCH":
		s.branch(in.Kind)
	case "NOP":
		// no stack effect
	default: // "OTHER" — best-effort stack delta for unmodeled opcodes
		s.other(in.Kind, pos)
	}
}

// block is one basic block of a method's reconstructed CFG: the half-open
// instruction range [start,end) and the slice of instructions it spans.
type block struct {
	start  int
	end    int
	instrs []dumpInstr
}

// simState snapshots the operand stack and locals at a block boundary.
type simState struct {
	stack  []*ir.Value
	locals map[int]*ir.Value
}

// splitBlocks reconstructs the basic blocks of a method from its linear
// instruction stream: leaders are index 0, every branch/switch target (a LABEL
// position), and the instruction after any terminator (branch/switch/return/
// throw). Returns the blocks in textual order and a label-id→instruction-index
// map for wiring edges. A method with no branch targets yields a single block.
func splitBlocks(instrs []dumpInstr) ([]block, map[int]int) {
	labelIdx := map[int]int{}
	for i, in := range instrs {
		if in.Op == "LABEL" {
			labelIdx[in.ID] = i
		}
	}
	leaders := map[int]bool{0: true}
	addTarget := func(id int) {
		if idx, ok := labelIdx[id]; ok {
			leaders[idx] = true
		}
	}
	for i, in := range instrs {
		switch in.Op {
		case "BRANCH":
			addTarget(in.Target)
			if i+1 < len(instrs) {
				leaders[i+1] = true
			}
		case "SWITCH":
			addTarget(in.Default)
			for _, t := range in.Targets {
				addTarget(t)
			}
			if i+1 < len(instrs) {
				leaders[i+1] = true
			}
		case "RETURN", "THROW":
			if i+1 < len(instrs) {
				leaders[i+1] = true
			}
		}
	}
	starts := slices.Sorted(maps.Keys(leaders))
	blocks := make([]block, len(starts))
	for i, st := range starts {
		end := len(instrs)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		blocks[i] = block{start: st, end: end, instrs: instrs[st:end]}
	}
	return blocks, labelIdx
}

// runBlocks lowers a method block-by-block over its CFG, threading the operand
// stack and locals along control-flow edges and PHI-merging divergent bindings
// at every join (≥2 predecessors). Blocks are processed in textual order —
// which is topological for the forward edges javac emits — so a join's
// predecessors are already lowered; a block reachable only via an unprocessed
// (back-)edge falls back to the previous block's exit, never doing worse than
// the old linear walk.
func (s *methodState) runBlocks(blocks []block, labelIdx map[int]int) {
	blockAt := map[int]int{} // leader instruction index -> block index
	for bi, b := range blocks {
		blockAt[b.start] = bi
	}
	preds := make([][]int, len(blocks))
	for bi, b := range blocks {
		for _, sc := range blockSuccs(b, blockAt, labelIdx) {
			preds[sc] = append(preds[sc], bi)
		}
	}

	seed := simState{locals: s.locals} // block 0 entry: seeded params, empty stack
	exits := make([]*simState, len(blocks))
	var prevExit *simState
	for bi, b := range blocks {
		var known []int
		for _, p := range preds[bi] {
			if exits[p] != nil {
				known = append(known, p)
			}
		}
		var entry simState
		switch {
		case bi == 0:
			entry = cloneState(seed)
		case len(known) == 0:
			if prevExit != nil {
				entry = cloneState(*prevExit)
			} else {
				entry = cloneState(seed)
			}
		case len(known) == 1:
			entry = cloneState(*exits[known[0]])
		default:
			entry = s.mergeStates(known, exits, b)
		}
		s.stack = entry.stack
		s.locals = entry.locals
		for _, in := range b.instrs {
			s.step(in)
		}
		ex := simState{stack: s.stack, locals: s.locals}
		exits[bi] = &ex
		prevExit = &ex
	}
}

// blockSuccs resolves a block's normal-control-flow successors from its
// terminator: a conditional branch reaches its target and its fallthrough; a
// GOTO only its target; a switch its default and every case; return/throw
// nothing; a block with no terminator falls through to the next.
func blockSuccs(b block, blockAt, labelIdx map[int]int) []int {
	fallthr := func() []int {
		if nx, ok := blockAt[b.end]; ok {
			return []int{nx}
		}
		return nil
	}
	target := func(id int) (int, bool) {
		idx, ok := labelIdx[id]
		if !ok {
			return 0, false
		}
		bi, ok := blockAt[idx]
		return bi, ok
	}
	if len(b.instrs) == 0 {
		return fallthr()
	}
	last := b.instrs[len(b.instrs)-1]
	switch last.Op {
	case "BRANCH":
		tgt, ok := target(last.Target)
		if strings.HasPrefix(last.Kind, "GOTO") {
			if ok {
				return []int{tgt}
			}
			return nil
		}
		res := fallthr()
		if ok {
			res = append(res, tgt)
		}
		return res
	case "SWITCH":
		var res []int
		if d, ok := target(last.Default); ok {
			res = append(res, d)
		}
		for _, t := range last.Targets {
			if bi, ok := target(t); ok {
				res = append(res, bi)
			}
		}
		return res
	case "RETURN", "THROW":
		return nil
	default:
		return fallthr()
	}
}

// mergeStates builds a join block's entry state from its already-lowered
// predecessors, emitting an OP_CODE_PHI for each operand-stack slot and local
// whose incoming values diverge (identical bindings pass through unchanged). The
// stack depth is the minimum across predecessors — defensive against the rare
// unbalanced-stack case; valid bytecode has equal depth at every join.
func (s *methodState) mergeStates(preds []int, exits []*simState, b block) simState {
	depth := -1
	for _, p := range preds {
		if d := len(exits[p].stack); depth < 0 || d < depth {
			depth = d
		}
	}
	if depth < 0 {
		depth = 0
	}
	pos := s.blockPos(b)
	out := simState{stack: make([]*ir.Value, depth), locals: map[int]*ir.Value{}}
	// collect gathers the distinct (dedup by pointer identity) incoming values
	// across predecessors for one operand-stack slot or local.
	collect := func(get func(p int) *ir.Value) []*ir.Value {
		vals := make([]*ir.Value, 0, len(preds))
		seen := map[*ir.Value]bool{}
		for _, p := range preds {
			v := get(p)
			if v == nil || seen[v] {
				continue
			}
			seen[v] = true
			vals = append(vals, v)
		}
		return vals
	}
	for i := 0; i < depth; i++ {
		out.stack[i] = s.mergeVals(collect(func(p int) *ir.Value { return exits[p].stack[i] }), pos)
	}
	slots := map[int]bool{}
	for _, p := range preds {
		for k := range exits[p].locals {
			slots[k] = true
		}
	}
	for slot := range slots {
		if vals := collect(func(p int) *ir.Value { return exits[p].locals[slot] }); len(vals) > 0 {
			out.locals[slot] = s.mergeVals(vals, pos)
		}
	}
	return out
}

// mergeVals returns the single value unchanged, or emits an OP_CODE_PHI over
// several — the taint engine treats PHI as a propagator, so the join is tainted
// iff any incoming edge is.
func (s *methodState) mergeVals(vals []*ir.Value, pos *ir.Position) *ir.Value {
	if len(vals) == 0 {
		return constString("")
	}
	if len(vals) == 1 {
		return vals[0]
	}
	r := s.reg()
	s.instrs = append(s.instrs, &ir.Instruction{Name: r, Op: ir.OpCode_OP_CODE_PHI, Operands: vals, Pos: pos})
	return regValue(r)
}

func (s *methodState) blockPos(b block) *ir.Position {
	for _, in := range b.instrs {
		if in.Line > 0 {
			return s.pos(in.Line)
		}
	}
	return nil
}

func cloneState(st simState) simState {
	out := simState{locals: make(map[int]*ir.Value, len(st.locals))}
	if len(st.stack) > 0 {
		out.stack = append([]*ir.Value(nil), st.stack...)
	}
	for k, v := range st.locals {
		out.locals[k] = v
	}
	return out
}

// invoke lowers a method call. Calls with a receiver (virtual/interface/special)
// become OP_CODE_INVOKE with the receiver in CallCommon.Value and the explicit
// args in Args, so a sink's `#0` injection point and the engine's arg→param
// mapping both line up (receiver → param 0). invokestatic becomes a CALL.
func (s *methodState) invoke(in dumpInstr, pos *ir.Position) {
	args := s.popN(len(parseParams(in.Mdesc)))
	callee := "java:" + in.Owner + "." + in.Mname
	cc := &ir.CallCommon{Callee: callee, Args: args}

	op := ir.OpCode_OP_CODE_CALL
	if in.Kind == "INVOKESTATIC" {
		cc.Value = &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}}
	} else {
		// virtual/interface/special: the receiver (popped after the args) becomes
		// operand 0 via CallCommon.Value, so a sink's `#0` lines up with it.
		op = ir.OpCode_OP_CODE_INVOKE
		cc.Value = s.pop() // receiver
		cc.IsInvoke = true
		cc.MethodName = in.Mname
	}

	name := ""
	if !returnsVoid(in.Mdesc) {
		name = s.reg()
	}
	s.instrs = append(s.instrs, &ir.Instruction{Name: name, Op: op, Call: cc, Pos: pos})
	if name != "" {
		s.push(regValue(name))
	}
}

// invokeDynamic handles the JVM's invokedynamic. String concatenation
// (`"a" + x`, compiled to makeConcatWithConstants since JDK 9) is modeled as a
// BIN_OP over its dynamic arguments so taint from any spliced value flows to the
// result — mirroring the Python f-string / JS template-literal lowering. Other
// invokedynamic (lambda metafactory, etc.) yields a fresh untainted value.
func (s *methodState) invokeDynamic(in dumpInstr, pos *ir.Position) {
	args := s.popN(len(parseParams(in.Mdesc)))
	if strings.HasPrefix(in.Mname, "makeConcat") {
		inst := &ir.Instruction{Name: s.reg(), Op: ir.OpCode_OP_CODE_BIN_OP, BinOp: ir.BinOpKind_BIN_OP_ADD, Operands: args, Pos: pos}
		s.instrs = append(s.instrs, inst)
		s.push(regValue(inst.Name))
		return
	}
	if returnsVoid(in.Mdesc) {
		return
	}
	s.push(s.emit(s.reg(), ir.OpCode_OP_CODE_ALLOC, nil, pos))
}

func (s *methodState) field(in dumpInstr, pos *ir.Position) {
	switch in.Kind {
	case "GETFIELD":
		recv := s.pop()
		s.push(s.emit(s.reg(), ir.OpCode_OP_CODE_FIELD, []*ir.Value{recv}, pos))
	case "GETSTATIC":
		s.push(s.emit(s.reg(), ir.OpCode_OP_CODE_FIELD, nil, pos))
	case "PUTFIELD":
		val := s.pop()
		recv := s.pop()
		s.emit("", ir.OpCode_OP_CODE_STORE, []*ir.Value{recv, val}, pos)
	case "PUTSTATIC":
		s.pop()
	}
}

func (s *methodState) operator(in dumpInstr, pos *ir.Position) {
	if strings.Contains(in.Kind, "NEG") {
		v := s.pop()
		s.push(s.emit(s.reg(), ir.OpCode_OP_CODE_UN_OP, []*ir.Value{v}, pos))
		return
	}
	b := s.pop()
	a := s.pop()
	s.push(s.emit(s.reg(), ir.OpCode_OP_CODE_BIN_OP, []*ir.Value{a, b}, pos))
}

func (s *methodState) stackOp(kind string) {
	switch kind {
	case "DUP":
		s.push(s.peek())
	case "DUP2":
		if n := len(s.stack); n >= 2 {
			a, b := s.stack[n-2], s.stack[n-1]
			s.push(a)
			s.push(b)
		} else {
			s.push(s.peek())
		}
	case "DUP_X1":
		if n := len(s.stack); n >= 2 {
			top := s.stack[n-1]
			s.stack = append(s.stack[:n-2], top, s.stack[n-2], top)
		}
	case "POP":
		s.pop()
	case "POP2":
		s.pop()
		s.pop()
	case "SWAP":
		if n := len(s.stack); n >= 2 {
			s.stack[n-1], s.stack[n-2] = s.stack[n-2], s.stack[n-1]
		}
	default:
		// DUP_X2 / DUP2_X1 / DUP2_X2: rare; approximate by duplicating the top.
		s.push(s.peek())
	}
}

func (s *methodState) ret(in dumpInstr, pos *ir.Position) {
	inst := &ir.Instruction{Op: ir.OpCode_OP_CODE_RET, Pos: pos}
	if in.Kind != "RETURN" { // a*/i*/l*/f*/d*return returns a value
		inst.Operands = []*ir.Value{s.pop()}
	}
	s.instrs = append(s.instrs, inst)
}

func (s *methodState) branch(kind string) {
	// Straight-line lowering: consume the comparison operands, no block split.
	switch {
	case strings.HasPrefix(kind, "IF_"): // IF_ICMP* / IF_ACMP*: two operands
		s.pop()
		s.pop()
	case strings.HasPrefix(kind, "IF"): // IFEQ/IFNULL/...: one operand
		s.pop()
	}
	// GOTO/GOTO_W: no operands.
}

func (s *methodState) other(kind string, pos *ir.Position) {
	switch kind {
	case "ARRAYLENGTH":
		arr := s.pop()
		s.push(s.emit(s.reg(), ir.OpCode_OP_CODE_FIELD, []*ir.Value{arr}, pos))
	case "MONITORENTER", "MONITOREXIT":
		s.pop()
	case "LOOKUPSWITCH", "TABLESWITCH":
		s.pop()
	}
	// Anything else: assume no net stack effect.
}

// --- stack / register helpers ---

func (s *methodState) reg() string {
	r := fmt.Sprintf("t%d", s.counter)
	s.counter++
	return r
}

func (s *methodState) emit(name string, op ir.OpCode, operands []*ir.Value, pos *ir.Position) *ir.Value {
	inst := &ir.Instruction{Name: name, Op: op, Operands: operands, Pos: pos}
	s.instrs = append(s.instrs, inst)
	if name == "" {
		return nil
	}
	return regValue(name)
}

func (s *methodState) push(v *ir.Value) {
	if v == nil {
		v = constString("")
	}
	s.stack = append(s.stack, v)
}

func (s *methodState) pop() *ir.Value {
	n := len(s.stack)
	if n == 0 {
		return constString("") // defensive: unbalanced stack (unmodeled op)
	}
	v := s.stack[n-1]
	s.stack = s.stack[:n-1]
	return v
}

func (s *methodState) popN(n int) []*ir.Value {
	out := make([]*ir.Value, n)
	for i := n - 1; i >= 0; i-- {
		out[i] = s.pop()
	}
	return out
}

func (s *methodState) peek() *ir.Value {
	if len(s.stack) == 0 {
		return constString("")
	}
	return s.stack[len(s.stack)-1]
}

func (s *methodState) load(slot int) *ir.Value {
	if v, ok := s.locals[slot]; ok {
		return v
	}
	return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: fmt.Sprintf("slot%d", slot)}}
}

func (s *methodState) pos(line int) *ir.Position {
	if line <= 0 {
		return nil
	}
	return &ir.Position{Filename: s.filename, Line: int32(line)}
}

func regValue(name string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_RegName{RegName: name}}
}

func constString(v string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: v}}}}
}

// --- JVM descriptor parsing ---

// parseParams returns the parameter type descriptors of a method descriptor,
// e.g. "(Ljava/lang/String;I[B)V" → ["Ljava/lang/String;", "I", "[B"].
func parseParams(desc string) []string {
	open := strings.IndexByte(desc, '(')
	closeIdx := strings.IndexByte(desc, ')')
	if open < 0 || closeIdx < 0 || closeIdx < open {
		return nil
	}
	body := desc[open+1 : closeIdx]
	var params []string
	for k := 0; k < len(body); {
		start := k
		for k < len(body) && body[k] == '[' { // array dimensions
			k++
		}
		if k >= len(body) {
			break
		}
		if body[k] == 'L' {
			semi := strings.IndexByte(body[k:], ';')
			if semi < 0 {
				break
			}
			k += semi + 1
		} else {
			k++ // primitive: B C D F I J S Z
		}
		params = append(params, body[start:k])
	}
	return params
}

func returnsVoid(desc string) bool {
	closeIdx := strings.IndexByte(desc, ')')
	return closeIdx >= 0 && closeIdx+1 < len(desc) && desc[closeIdx+1] == 'V'
}

// slotWidth reports how many local-variable slots a parameter type occupies
// (long/double take two). Taint is width-agnostic; this only keeps slot indices
// aligned with the bytecode.
func slotWidth(paramType string) int {
	if paramType == "J" || paramType == "D" {
		return 2
	}
	return 1
}
