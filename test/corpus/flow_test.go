package corpus

import (
	"testing"

	"github.com/bytevet/godzilla/internal/analysis"
)

// boundaryKinds are the hops that explain a change of frame along a taint path.
var boundaryKinds = map[analysis.StepKind]bool{
	analysis.StepCall:   true,
	analysis.StepReturn: true,
	analysis.StepGlobal: true,
}

// assertPathsAreContinuous checks every reported taint path for the property the
// whole path mechanism exists to provide: it never teleports. Wherever adjacent
// hops sit in different functions, one of the two must be the boundary that
// crossed — a call into the next frame, a return out of this one, or a global
// that published the value.
//
// EITHER side, not specifically the earlier one, because a boundary is a single
// event seen from two frames and only one of the two hops need survive: a
// callee's own exit hop can share a position with the statement before it and
// deduplicate away (a Ruby implicit return of the source expression does exactly
// that), leaving the caller's hop to carry the label.
//
// It runs over EVERY sample in the corpus rather than a hand-picked few, because
// the failure it guards against is silent: a summary channel that forgets to
// carry its trail still reports the same finding at the same source and sink,
// and only the middle disappears. No count or location oracle can see that.
func assertPathsAreContinuous(t *testing.T, findings []analysis.Finding) {
	t.Helper()
	for _, f := range findings {
		for i, s := range f.Steps {
			if s.Pos == nil {
				t.Errorf("%s: path step %d has no position", f.RuleID, i)
				continue
			}
			if i == 0 {
				continue
			}
			prev := f.Steps[i-1]
			if prev.Func != s.Func && !boundaryKinds[prev.Kind] && !boundaryKinds[s.Kind] {
				t.Errorf("%s: taint path jumps frames with no boundary hop: %s (%s) in %s -> %s (%s) in %s",
					f.RuleID, analysis.PosString(prev.Pos), prev.Kind, prev.Func,
					analysis.PosString(s.Pos), s.Kind, s.Func)
			}
		}
	}
}
