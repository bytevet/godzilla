package java_converter

import (
	"fmt"
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
	// a call site flows into the callee. (Long/double occupy two slots, but taint
	// is width-agnostic, so we advance one slot per parameter — sufficient for the
	// reference/int-heavy handler code that matters.)
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

func (s *methodState) run(instrs []dumpInstr) {
	for _, in := range instrs {
		pos := s.pos(in.Line)
		switch in.Op {
		case "LOAD":
			s.push(s.load(in.Slot))
		case "STORE":
			s.locals[in.Slot] = s.pop()
		case "CONST":
			// All constants are modeled as string constants: harmless for taint
			// (constants are untrusted-free) and lets the secrets scanner see
			// string literals.
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
