package analysis

import (
	"strings"
	"testing"

	go_converter "github.com/bytevet/godzilla/converters/go"
	"github.com/bytevet/godzilla/internal/rules"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// cmdInjRule is the one rule these tests analyze under: request data reaching
// os/exec. Every sample below is an existing corpus fixture, so what is pinned
// here is the PATH, not the detection — that already has a corpus oracle.
func cmdInjRule() *rules.RuleSet {
	return &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "GO-CMDI-PATH",
		Languages: []string{"go"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "untrusted input reaches os/exec",
		Sources:   []string{"go:@net/http.Request", "go:*net/url*.Get"},
		Sinks:     rules.SinksOf("go:*os/exec.Command*"),
		// A hand-built RuleSet carries no DefaultPropagators (the loader supplies
		// those), so the stdlib transforms the samples use are declared here or
		// taint dies at the first strings.TrimSpace.
		Propagators: []string{"go:strings.*", "go:fmt.*"},
	}}}
}

// pathOf scans one Go sample and returns the single expected finding's steps.
func pathOf(t *testing.T, sample string) (Finding, []FlowStep) {
	t.Helper()
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/" + sample + "/main.go")
	if err != nil {
		t.Fatalf("convert %s: %v", sample, err)
	}
	// Scope the seed the way internal/scan does, so a lowered dependency is a
	// dependency here too — otherwise every hop reports InScope — and drop the
	// dep-internal findings the same way scopeFindings does, or a sink wrapper
	// hands back the library's own finding instead of the user's.
	targets := conv.TargetPackages()
	for _, f := range NewEngine(cmdInjRule()).ScopeSeed(targets).Analyze(prog) {
		if len(targets) > 0 && f.Package != "" && !targets[f.Package] {
			continue
		}
		return f, f.Steps
	}
	t.Fatalf("%s: expected a command-injection finding in user code, got none", sample)
	return Finding{}, nil
}

// boundaryKinds are the hops that explain a change of frame.
var boundaryKinds = map[StepKind]bool{StepCall: true, StepReturn: true, StepGlobal: true}

// assertContinuous is THE oracle for this whole mechanism: a path must never
// teleport. Wherever two adjacent hops sit in different functions, one of them
// has to be the boundary that crossed — a call into the next frame, a return out
// of this one, or a global that published the value. A path that jumps from a
// source in one function straight to a sink in another, which is what an
// endpoints-only path looks like, fails here.
//
// Either side satisfies it, since a boundary is one event seen from two frames
// and the callee's own hop can deduplicate into the statement before it (see the
// corpus-wide version of this check in test/corpus/flow_test.go).
func assertContinuous(t *testing.T, sample string, steps []FlowStep) {
	t.Helper()
	if len(steps) < 2 {
		t.Fatalf("%s: path has %d step(s); a source->sink flow needs at least 2", sample, len(steps))
	}
	if steps[0].Kind != StepSource {
		t.Errorf("%s: path starts with %q, want %q", sample, steps[0].Kind, StepSource)
	}
	if last := steps[len(steps)-1]; last.Kind != StepSink {
		t.Errorf("%s: path ends with %q, want %q", sample, last.Kind, StepSink)
	}
	for i, s := range steps {
		if s.Pos == nil {
			t.Errorf("%s: step %d has no position", sample, i)
		}
		if s.Func == "" {
			t.Errorf("%s: step %d (%s) names no function", sample, i, s.Kind)
		}
		if i == 0 {
			continue
		}
		if prev := steps[i-1]; prev.Func != s.Func && !boundaryKinds[prev.Kind] && !boundaryKinds[s.Kind] {
			t.Errorf("%s: path jumps from %s (%s, %s) to %s (%s, %s) with no boundary hop",
				sample, prev.Func, prev.Kind, PosString(prev.Pos), s.Func, s.Kind, PosString(s.Pos))
		}
	}
}

// funcsOn returns the distinct functions a path visits, in order.
func funcsOn(steps []FlowStep) []string {
	var out []string
	for _, s := range steps {
		if len(out) == 0 || out[len(out)-1] != s.Func {
			out = append(out, s.Func)
		}
	}
	return out
}

// TestPath_CrossesEveryChannel walks one sample per inter-procedural channel and
// asserts each produces a continuous path spanning more than one function. A
// summary that carries only the source position across its boundary reports two
// endpoints and nothing between, which is what these catch.
func TestPath_CrossesEveryChannel(t *testing.T) {
	for _, tc := range []struct {
		sample string
		frames int // distinct functions the flow must visit
	}{
		{"taint_flow_chain", 4}, // argument channel, three hops deep
		{"return_flow", 2},      // return channel
		{"global_taint", 2},     // package-global channel
		{"outparam_fill", 2},    // out-parameter fill
		{"dep_sink_wrapper", 2}, // dependency sink wrapper
	} {
		t.Run(tc.sample, func(t *testing.T) {
			_, steps := pathOf(t, tc.sample)
			assertContinuous(t, tc.sample, steps)
			if got := funcsOn(steps); len(got) < tc.frames {
				t.Errorf("path visits %d frame(s) %v, want at least %d", len(got), got, tc.frames)
			}
		})
	}
}

// TestPath_EscapesMemory pins the other half: a flow whose value passes through
// a struct field and a slice literal. Def-use cannot walk back out of either, so
// without the store index the path skips straight from the source to the
// container and the transforms in between are invisible.
func TestPath_EscapesMemory(t *testing.T) {
	_, steps := pathOf(t, "taint_path_memory")
	assertContinuous(t, "taint_path_memory", steps)

	lines := map[int32]bool{}
	for _, s := range steps {
		lines[s.Pos.GetLine()] = true
	}
	// 27 the transform, 28 the struct literal, 30 the map write, 32 the slice
	// literal — each behind a memory write, and each dropped when the walk stops
	// at the container.
	for _, want := range []int32{27, 28, 30, 32} {
		if !lines[want] {
			t.Errorf("path is missing line %d; got %v", want, steps)
		}
	}
	// The decoy: tainted from the same request and written into the SAME map, but
	// never read at the sink. A container is tainted as a unit, so both writes
	// look alike to the engine and nothing but the walk's choice keeps this out —
	// a path through code the value never took is worse than a short path.
	for _, unwanted := range []int32{26, 31} {
		if lines[unwanted] {
			t.Errorf("path includes decoy line %d, which the traced value never passed through; got %v", unwanted, steps)
		}
	}
}

// TestPath_DepWrapperReachesTheLibrarySink checks that a flow into a dependency's
// sink wrapper shows the library line that is actually dangerous. The finding's
// own SinkPos stays the user call site — that is where the fix belongs — so
// without the trailing hops the reader is never told what the wrapper does.
func TestPath_DepWrapperReachesTheLibrarySink(t *testing.T) {
	f, steps := pathOf(t, "dep_sink_wrapper")
	last := steps[len(steps)-1]
	if last.InScope {
		t.Fatalf("expected the final hop inside the dependency, got %s in %s", PosString(last.Pos), last.Func)
	}
	if last.Pos.GetFilename() == f.SinkPos.GetFilename() {
		t.Errorf("the wrapper's sink should sit in a different file from the reported call site (%s)", PosString(f.SinkPos))
	}
	// The entry point stays in the scanned code, which is the location a reader
	// can act on even though the source and the real sink are both elsewhere.
	if f.EntryPos == nil {
		t.Fatal("a flow through a dependency wrapper must still name an in-scope entry point")
	}
	if strings.Contains(f.EntryFunc, "cmdutil") {
		t.Errorf("entry point %s is inside the dependency", f.EntryFunc)
	}
}

// TestTrailStepsDropsRepeats pins the display contract: a call instruction and
// the return hop landing on it share a position, and a path that shows the same
// line twice reads as a bug. A repeat carrying an endpoint label promotes the
// kept hop instead of vanishing, so the source and sink stay labelled.
func TestTrailStepsDropsRepeats(t *testing.T) {
	at := func(line int32) *ir.Position { return &ir.Position{Filename: "a.go", Line: line} }
	var tr *trail
	tr = tr.push(FlowStep{Pos: at(1), Func: "f", Kind: StepSource})
	tr = tr.push(FlowStep{Pos: at(2), Func: "f", Kind: StepCall})
	tr = tr.push(FlowStep{Pos: at(2), Func: "f", Kind: StepStep}) // repeat: dropped
	tr = tr.push(FlowStep{Pos: at(2), Func: "g", Kind: StepStep}) // same line, other frame: kept
	tr = tr.push(FlowStep{Pos: at(2), Func: "g", Kind: StepSink}) // repeat, but promotes

	got := tr.steps()
	if len(got) != 3 {
		t.Fatalf("got %d steps, want 3: %+v", len(got), got)
	}
	if got[2].Kind != StepSink {
		t.Errorf("a repeated sink hop must promote the kept hop's kind, got %q", got[2].Kind)
	}
	if got[1].Func != "f" || got[2].Func != "g" {
		t.Errorf("a repeat in a DIFFERENT frame must not be dropped, got %+v", got)
	}
}

// TestTrailPushIsBounded guards the defensive depth cap: a pathological program
// must not grow a trail without limit.
func TestTrailPushIsBounded(t *testing.T) {
	var tr *trail
	for i := 0; i < maxTrailHops*2; i++ {
		tr = tr.push(FlowStep{Pos: &ir.Position{Filename: "a.go", Line: int32(i + 1)}, Func: "f"})
	}
	if got := len(tr.steps()); got != maxTrailHops {
		t.Errorf("trail grew to %d hops, want it capped at %d", got, maxTrailHops)
	}
}

// TestPathCoversIsASubsequence pins the corpus oracle's semantics: the listed
// lines must appear in order but need not be adjacent, so ADDING an intermediate
// hop does not break a hand-written expectation while losing one does.
func TestPathCoversIsASubsequence(t *testing.T) {
	step := func(line int32) FlowStep {
		return FlowStep{Pos: &ir.Position{Filename: "a.go", Line: line}}
	}
	f := Finding{Steps: []FlowStep{step(1), step(4), step(4), step(9)}}

	for _, want := range [][]int32{nil, {1, 9}, {1, 4, 9}, {4, 4}} {
		if !f.PathCovers(want) {
			t.Errorf("PathCovers(%v) = false, want true", want)
		}
	}
	for _, want := range [][]int32{{9, 1}, {1, 5}, {4, 4, 4}} {
		if f.PathCovers(want) {
			t.Errorf("PathCovers(%v) = true, want false", want)
		}
	}
}

// TestEntryOfSkipsDependencyHops pins what makes a finding actionable when the
// modeled source is a framework internal: the entry point is the first hop the
// reader can actually open.
func TestEntryOfSkipsDependencyHops(t *testing.T) {
	dep := FlowStep{Pos: &ir.Position{Filename: "gin/context.go", Line: 427}, Func: "gin.Query", Kind: StepSource}
	mine := FlowStep{Pos: &ir.Position{Filename: "app/h.go", Line: 12}, Func: "app.handler", Kind: StepReturn, InScope: true}

	pos, fn := entryOf([]FlowStep{dep, mine})
	if pos == nil || pos.GetLine() != 12 || fn != "app.handler" {
		t.Errorf("entryOf = %v/%q, want the in-scope hop", pos, fn)
	}
	if pos, _ := entryOf([]FlowStep{dep}); pos != nil {
		t.Errorf("a path entirely inside a dependency has no entry point, got %v", pos)
	}
}
