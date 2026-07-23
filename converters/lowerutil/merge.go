// Package lowerutil holds small lowering helpers shared by the straight-line,
// env-based frontends (Python, JavaScript, Ruby), which lower without a real CFG
// and so reconstruct branch joins the same way.
package lowerutil

import (
	"maps"

	ir "godzilla/pkg/ir/v1"
)

// MergeBranchEnvs PHI-merges the variable bindings of two mutually-exclusive
// if/else arms that were both lowered from the pre-branch environment `before`.
// afterBody and afterElse are the arms' resulting environments. For each name
// that ends up bound to different values on the two paths, emitPhi(bv, ev) must
// emit the frontend's PHI instruction and return its value; a name bound on only
// one path falls back to its pre-branch value, and a name unchanged (or absent)
// on both paths is left as-is. This keeps taint from EITHER path (the engine
// treats a PHI as a propagator), fixing the "default if empty" false negative
// (`if not x: x = "d"`) uniformly across the frontends.
func MergeBranchEnvs(before, afterBody, afterElse map[string]*ir.Value, emitPhi func(bv, ev *ir.Value) *ir.Value) map[string]*ir.Value {
	merged := maps.Clone(afterElse)
	names := map[string]bool{}
	for k := range afterBody {
		names[k] = true
	}
	for k := range afterElse {
		names[k] = true
	}
	for name := range names {
		bv, ev := afterBody[name], afterElse[name]
		if bv == nil {
			bv = before[name] // else-only rebind: body kept the pre-branch value
		}
		if ev == nil {
			ev = before[name] // body-only rebind: else kept the pre-branch value
		}
		if bv == ev || bv == nil || ev == nil {
			continue // unchanged on both paths, or only ever bound on one path
		}
		merged[name] = emitPhi(bv, ev)
	}
	return merged
}
