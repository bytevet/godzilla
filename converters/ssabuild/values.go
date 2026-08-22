package ssabuild

import ir "github.com/bytevet/godzilla/pkg/ir/v1"

// gIR value constructors shared by every frontend. Each is a one-liner, but
// before living here the same one-liners were re-declared privately in six
// packages (regValue/constString/stringValue/globalValue/nilValue), which is
// exactly the kind of copy that drifts. ssabuild is the frontend-shared,
// IR-only package, so the shared spelling lives with the rest of the
// frontend-side IR scaffolding.

func Reg(name string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_RegName{RegName: name}}
}

func Str(s string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: s}}}}
}

func Global(name string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: name}}
}

func Nil() *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{IsNil: true}}}
}

// SetKwargMarker stamps inst as a `builtin.kwarg(<name>, <value>)` marker: the
// intrinsic a frontend emits to tag a keyword argument with the name it was
// passed under, since gIR carries positional arguments only.
//
// TWO channels, and dropping either fails silently. Operands is what the engine's
// markTaintFromOperands reads, and builtin.kwarg is an intrinsic propagator, so
// without it every `f(x=tainted)` loses its taint. Call.Args is what unwrapKwarg
// reads to give a rule guard `kwargs.<name>`, so without it a guard can see that
// SOME argument is set but not which. Shared so the pairing is stated once rather
// than re-derived per frontend.
func SetKwargMarker(inst *ir.Instruction, name string, v *ir.Value) {
	inst.Op = ir.OpCode_OP_CODE_INTRINSIC
	inst.Intrinsic = "builtin.kwarg"
	inst.Operands = []*ir.Value{v}
	inst.Call = &ir.CallCommon{Callee: "builtin.kwarg", Args: []*ir.Value{Str(name), v}}
}
