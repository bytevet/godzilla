//go:build llvm

// Package llvm_converter lowers LLVM IR (as produced by clang for C/C++ or rustc
// for Rust) into Godzilla's language-neutral gIR, so the one taint engine
// analyzes native/systems code the same way it analyzes Go/Python/JS. LLVM IR is
// already SSA, so the mapping is direct.
//
// This package is compiled only under the `llvm` build tag (it binds libLLVM via
// cgo through tinygo.org/x/go-llvm). The C/C++/Rust frontends provide a no-op
// stub for the default pure-Go build. See converters/cpp and converters/rust.
package llvm_converter

import (
	"fmt"

	ir "godzilla/pkg/ir/v1"

	"tinygo.org/x/go-llvm"
)

// DemangleFunc turns a raw LLVM symbol into a readable, canonical member name
// (without the language prefix). See demangle.go for the C/C++/Rust variants.
type DemangleFunc func(string) string

// Lower parses the LLVM IR at irPath and lowers it to a gIR module. srcFile is
// the original source path used for finding positions; lang is the module
// Language tag ("c"/"cpp"/"rust"); prefix is the canonical-name prefix
// ("c:"/"cpp:"/"rust:"); demangle normalizes symbol names.
func Lower(irPath, srcFile, lang, prefix string, demangle DemangleFunc) (*ir.Module, error) {
	ctx := llvm.NewContext()
	buf, err := llvm.NewMemoryBufferFromFile(irPath)
	if err != nil {
		return nil, fmt.Errorf("reading IR %s: %w", irPath, err)
	}
	mod, err := ctx.ParseIR(buf)
	if err != nil {
		return nil, fmt.Errorf("parsing IR %s: %w", irPath, err)
	}
	// The C/C++/Rust drivers emit the IR at -O1, which runs mem2reg, so locals
	// are already SSA registers (no in-process pass needed).

	out := &ir.Module{Name: srcFile, Language: lang}
	for fn := mod.FirstFunction(); !fn.IsNil(); fn = llvm.NextFunction(fn) {
		if fn.IsDeclaration() {
			continue
		}
		fl := &funcLowerer{srcFile: srcFile, prefix: prefix, demangle: demangle, regs: map[llvm.Value]string{}}
		out.Functions = append(out.Functions, fl.lower(fn))
	}
	return out, nil
}

type funcLowerer struct {
	srcFile  string
	prefix   string
	demangle DemangleFunc
	regs     map[llvm.Value]string
	counter  int
}

func (fl *funcLowerer) lower(fn llvm.Value) *ir.Function {
	out := &ir.Function{
		Name:          fn.Name(),
		ObjectName:    fl.canon(fn.Name()),
		CanonicalName: fl.canonName(fn.Name()),
	}
	for i := 0; i < fn.ParamsCount(); i++ {
		p := fn.Param(i)
		out.Params = append(out.Params, &ir.Value{Kind: &ir.Value_RegName{RegName: fl.reg(p)}})
	}

	// The command line is attacker-controlled input. For `main(int argc, char
	// **argv)` synthesize a source CALL whose result is bound to the argv
	// parameter, so every `argv[i]` read carries taint (the same trick the axum /
	// Spring frontends use for framework-provided request data). The engine only
	// introduces taint at a CALL matching a source glob (`c*:argv`), so this makes
	// argv a real CLI/CGI source (COV-8) with no gIR or engine change.
	var prologue *ir.Instruction
	if fn.Name() == "main" && fn.ParamsCount() >= 2 {
		argv := fn.Param(1)
		src := fl.prefix + "argv"
		r := fl.freshReg()
		prologue = &ir.Instruction{
			Name: r, Op: ir.OpCode_OP_CODE_CALL,
			Call: &ir.CallCommon{Callee: src, Value: &ir.Value{Kind: &ir.Value_FuncName{FuncName: src}}},
		}
		fl.regs[argv] = r // uses of argv now resolve to the (tainted) source result
	}

	// Index the basic blocks first so a terminator's successor blocks resolve to
	// block indices in the second pass.
	blockIdx := map[llvm.BasicBlock]int32{}
	var bbs []llvm.BasicBlock
	for bb := fn.FirstBasicBlock(); !bb.IsNil(); bb = llvm.NextBasicBlock(bb) {
		blockIdx[bb] = int32(len(bbs))
		bbs = append(bbs, bb)
	}

	// Lower each block and wire its CFG edges (Preds/Succs). The flow-sensitive
	// engine (ENG-2) propagates taint in reverse-post-order over these edges, so
	// without them a branch between a source and a sink — `l = fgets(...); if (l)
	// system(l);` — would strand the taint in the entry block (a false negative).
	// A terminator's successor blocks appear among its operands as block values.
	preds := make([][]int32, len(bbs))
	for i, bb := range bbs {
		block := &ir.BasicBlock{Index: int32(i)}
		for in := bb.FirstInstruction(); !in.IsNil(); in = llvm.NextInstruction(in) {
			if inst := fl.lowerInst(in); inst != nil {
				block.Instrs = append(block.Instrs, inst)
				if prologue != nil && prologue.Pos == nil {
					prologue.Pos = inst.Pos // anchor the synthetic argv source to main's first line
				}
			}
		}
		if i == 0 && prologue != nil {
			block.Instrs = append([]*ir.Instruction{prologue}, block.Instrs...)
		}
		if term := bb.LastInstruction(); !term.IsNil() {
			seen := map[int32]bool{}
			for k := 0; k < term.OperandsCount(); k++ {
				op := term.Operand(k)
				if !op.IsBasicBlock() {
					continue
				}
				si, ok := blockIdx[op.AsBasicBlock()]
				if !ok || seen[si] {
					continue
				}
				seen[si] = true
				block.Succs = append(block.Succs, si)
				preds[si] = append(preds[si], int32(i))
			}
		}
		out.Blocks = append(out.Blocks, block)
	}
	for i, ps := range preds {
		out.Blocks[i].Preds = ps
	}
	return out
}

func (fl *funcLowerer) lowerInst(in llvm.Value) *ir.Instruction {
	pos := fl.pos(in)
	switch in.InstructionOpcode() {
	case llvm.Ret:
		inst := &ir.Instruction{Op: ir.OpCode_OP_CODE_RET, Pos: pos}
		if in.OperandsCount() > 0 {
			inst.Operands = []*ir.Value{fl.val(in.Operand(0))}
		}
		return inst

	case llvm.Call, llvm.Invoke:
		return fl.lowerCall(in, pos)

	case llvm.Alloca:
		return &ir.Instruction{Name: fl.reg(in), Op: ir.OpCode_OP_CODE_ALLOC, Pos: pos}

	case llvm.Load:
		return &ir.Instruction{Name: fl.reg(in), Op: ir.OpCode_OP_CODE_LOAD, Operands: []*ir.Value{fl.val(in.Operand(0))}, Pos: pos}

	case llvm.Store:
		// LLVM: `store value, ptr` (Operand0=value, Operand1=ptr). gIR STORE
		// convention is (addr, value) so a tainted value taints the pointee.
		return &ir.Instruction{Op: ir.OpCode_OP_CODE_STORE, Operands: []*ir.Value{fl.val(in.Operand(1)), fl.val(in.Operand(0))}, Pos: pos}

	case llvm.GetElementPtr:
		// Address computation: taint flows from the base pointer.
		return &ir.Instruction{Name: fl.reg(in), Op: ir.OpCode_OP_CODE_INDEX_ADDR, Operands: []*ir.Value{fl.val(in.Operand(0))}, Pos: pos}

	case llvm.PHI:
		var ops []*ir.Value
		for i := 0; i < in.OperandsCount(); i++ {
			ops = append(ops, fl.val(in.Operand(i)))
		}
		return &ir.Instruction{Name: fl.reg(in), Op: ir.OpCode_OP_CODE_PHI, Operands: ops, Pos: pos}

	case llvm.BitCast, llvm.Trunc, llvm.ZExt, llvm.SExt, llvm.PtrToInt, llvm.IntToPtr,
		llvm.FPToUI, llvm.FPToSI, llvm.UIToFP, llvm.SIToFP, llvm.FPTrunc, llvm.FPExt:
		return &ir.Instruction{Name: fl.reg(in), Op: ir.OpCode_OP_CODE_CONVERT, Operands: []*ir.Value{fl.val(in.Operand(0))}, Pos: pos}

	case llvm.ExtractValue:
		return &ir.Instruction{Name: fl.reg(in), Op: ir.OpCode_OP_CODE_EXTRACT, Operands: []*ir.Value{fl.val(in.Operand(0))}, Pos: pos}

	case llvm.Select:
		// `select c, a, b` → value is a or b; merge both for conservative taint.
		return &ir.Instruction{Name: fl.reg(in), Op: ir.OpCode_OP_CODE_BIN_OP, Operands: []*ir.Value{fl.val(in.Operand(1)), fl.val(in.Operand(2))}, Pos: pos}

	case llvm.Add, llvm.FAdd, llvm.Sub, llvm.FSub, llvm.Mul, llvm.FMul, llvm.UDiv, llvm.SDiv, llvm.FDiv,
		llvm.URem, llvm.SRem, llvm.FRem, llvm.Shl, llvm.LShr, llvm.AShr, llvm.And, llvm.Or, llvm.Xor,
		llvm.ICmp, llvm.FCmp:
		if in.OperandsCount() >= 2 {
			return &ir.Instruction{Name: fl.reg(in), Op: ir.OpCode_OP_CODE_BIN_OP, Operands: []*ir.Value{fl.val(in.Operand(0)), fl.val(in.Operand(1))}, Pos: pos}
		}
		return &ir.Instruction{Name: fl.reg(in), Op: ir.OpCode_OP_CODE_UN_OP, Operands: []*ir.Value{fl.val(in.Operand(0))}, Pos: pos}

	case llvm.Unreachable:
		return &ir.Instruction{Op: ir.OpCode_OP_CODE_UNREACHABLE, Pos: pos}

	case llvm.Br, llvm.Switch:
		// Control flow: the engine uses def-use fixpoint, not strict CFG order, so
		// a bare terminator carries no taint. Drop it.
		return nil

	default:
		// Unmodeled opcode: keep the result register defined (so operands resolve)
		// as an inert intrinsic.
		if in.Name() != "" || hasResult(in) {
			return &ir.Instruction{Name: fl.reg(in), Op: ir.OpCode_OP_CODE_INTRINSIC, Intrinsic: "llvm.op", Pos: pos}
		}
		return nil
	}
}

func (fl *funcLowerer) lowerCall(in llvm.Value, pos *ir.Position) *ir.Instruction {
	callee := in.CalledValue()
	cc := &ir.CallCommon{}
	if !callee.IsAFunction().IsNil() {
		cc.Callee = fl.canonName(callee.Name())
		cc.Value = &ir.Value{Kind: &ir.Value_FuncName{FuncName: cc.Callee}}
	}
	// Call operands are [args..., callee] (invoke also trails dest blocks); take
	// the leading value (non-block) operands as arguments.
	n := in.OperandsCount()
	for i := 0; i < n; i++ {
		op := in.Operand(i)
		if op == callee || op.IsBasicBlock() {
			continue
		}
		cc.Args = append(cc.Args, fl.val(op))
	}
	name := ""
	if hasResult(in) {
		name = fl.reg(in)
	}
	return &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_CALL, Call: cc, Pos: pos}
}

// val resolves an LLVM operand to a gIR value: functions → FuncName, globals →
// GlobalName, constants → a placeholder constant (untainted), everything else
// (instruction results, arguments) → the SSA register.
func (fl *funcLowerer) val(v llvm.Value) *ir.Value {
	if v.IsNil() {
		return constString("")
	}
	if !v.IsAFunction().IsNil() {
		return &ir.Value{Kind: &ir.Value_FuncName{FuncName: fl.canonName(v.Name())}}
	}
	if !v.IsAGlobalVariable().IsNil() {
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: v.Name()}}
	}
	if v.IsConstant() {
		return constString("")
	}
	return &ir.Value{Kind: &ir.Value_RegName{RegName: fl.reg(v)}}
}

func (fl *funcLowerer) reg(v llvm.Value) string {
	if r, ok := fl.regs[v]; ok {
		return r
	}
	r := fl.freshReg()
	fl.regs[v] = r
	return r
}

// freshReg mints a register name not bound to any LLVM value (used for
// synthesized instructions such as the argv source CALL).
func (fl *funcLowerer) freshReg() string {
	r := fmt.Sprintf("v%d", fl.counter)
	fl.counter++
	return r
}

func (fl *funcLowerer) pos(in llvm.Value) *ir.Position {
	md := in.InstructionDebugLoc()
	if md.C == nil {
		return nil
	}
	line := md.LocationLine()
	if line == 0 {
		return nil
	}
	return &ir.Position{Filename: fl.srcFile, Line: int32(line), Column: int32(md.LocationColumn())}
}

func (fl *funcLowerer) canonName(sym string) string { return fl.prefix + fl.canon(sym) }

func (fl *funcLowerer) canon(sym string) string {
	if fl.demangle != nil {
		return fl.demangle(sym)
	}
	return sym
}

// hasResult reports whether an instruction produces a (non-void) SSA value that
// other instructions can reference.
func hasResult(in llvm.Value) bool {
	return in.Type().TypeKind() != llvm.VoidTypeKind
}

func constString(v string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: v}}}}
}
