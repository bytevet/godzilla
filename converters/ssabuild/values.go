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
