package analysis

import "testing"

// A keyword marker stands in for the value it wraps in the call's argument list,
// and frontends wrap NON-CONSTANT values so a guard can tell an absent keyword
// from a dynamic one. That makes propagation load-bearing: drop it and taint dies
// at every `f(x=tainted)` with nothing to show for it — a silent false negative,
// the one failure mode a scanner cannot surface.
//
// This is pinned here rather than left to a sample because the corpus catches it
// only by accident: exactly one sample routes taint through a keyword, and it
// does so incidentally (ast.Module(body=[node], ...) in fastapi_code_injection),
// so a rewrite of that sample would silently remove the only coverage.
func TestKwargMarkerPropagatesTaint(t *testing.T) {
	if !intrinsicPropagators[kwargIntrinsic] {
		t.Fatalf("%s must be in intrinsicPropagators: it wraps non-constant values, "+
			"so omitting it drops taint at every Python keyword argument", kwargIntrinsic)
	}
}
