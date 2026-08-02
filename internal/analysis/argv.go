package analysis

import (
	ir "godzilla/pkg/ir/v1"
)

// shellKwarg is the keyword that turns a process-exec call into a shell
// invocation. `subprocess.run(cmd, shell=True)` hands cmd to /bin/sh; without
// it the arguments go straight to execve and are never shell-interpreted.
const shellKwarg = "shell"

// aggregateIntrinsic is the language-neutral container construction (a list,
// tuple, set or dict built in place). The Python frontend emits it for every
// container literal and comprehension so element taint survives into a later
// whole-container use; taint.go lists it in intrinsicPropagators.
const aggregateIntrinsic = "builtin.aggregate"

// argvListSafe is the engine fact behind the `argvList()` guard builtin. It
// reports whether EVERY tainted injection-point value reaches this call as a
// container constructed in place, with no truthy `shell=` keyword — the safe
// argv form, `subprocess.run(["ls", "-la", name])`, where the tainted value is
// one argv element passed to execve rather than a shell string.
//
// It reads only neutral IR — an intrinsic name and a keyword marker, never a
// callee name — so it stays language-agnostic in the same way ssrf.go's
// hostFixed() fact does.
//
// Conservative in both directions:
//   - `shell=True` anywhere on the call disqualifies it outright, because then
//     the list IS joined into a shell string.
//   - a tainted injection point that is NOT an in-place container (a plain
//     string, or a container that arrived from elsewhere and whose construction
//     we cannot see) reports false, so the sink still fires. Only the shape we
//     can positively prove safe is suppressed.
func argvListSafe(inj []*ir.Value, tainted taintState, defs map[string]*ir.Instruction, call *ir.CallCommon) bool {
	if call == nil || defs == nil {
		return false
	}
	if callHasTruthyShell(call, defs) {
		return false
	}
	sawTainted := false
	for _, v := range inj {
		if _, ok := isTainted(tainted, v); !ok {
			continue
		}
		sawTainted = true
		def := defs[v.GetRegName()]
		if def == nil || def.GetIntrinsic() != aggregateIntrinsic {
			return false
		}
	}
	// No tainted injection point at all means there is nothing to vouch for;
	// report false so the guard never suppresses on an empty basis.
	return sawTainted
}

// callHasTruthyShell reports whether the call passes `shell=<truthy constant>`.
// Keyword names survive lowering as builtin.kwarg markers (gIR's CallCommon
// carries positional arguments only), which is exactly what unwrapKwarg
// resolves. A non-constant `shell=` value is unrecoverable, so it counts as
// truthy: we cannot prove no shell is involved.
func callHasTruthyShell(call *ir.CallCommon, defs map[string]*ir.Instruction) bool {
	for _, a := range call.GetArgs() {
		name, val := unwrapKwarg(a, defs)
		if name != shellKwarg {
			continue
		}
		c := val.GetConstant()
		if c == nil {
			return true // shell=<dynamic>: cannot prove it is off
		}
		switch c.Value.(type) {
		case *ir.Constant_BoolVal:
			if c.GetBoolVal() {
				return true
			}
		case *ir.Constant_IntVal:
			if c.GetIntVal() != 0 {
				return true
			}
		default:
			return true // any other constant shape: treat as enabled
		}
	}
	return false
}
