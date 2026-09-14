package analysis

import (
	"slices"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// This file holds the taint path: the record of HOW a value travelled from a
// source to a sink, as opposed to the fact that it did.
//
// The path is reconstructed from two complementary records, and the split is the
// whole design:
//
//   - Inside a function, nothing is recorded while the analysis runs. The hops
//     are recovered on demand by walking SSA def-use backward from the sink (see
//     localHops), plus the store index for the edges def-use cannot express.
//   - Across a function boundary, def-use has nothing to walk, so the hops MUST
//     be recorded as they happen. Each cross-function summary channel therefore
//     carries a taintFact — an origin together with the trail that delivered it —
//     instead of a bare origin.
//
// Recording intra-procedural hops eagerly would cost a slice per tainted
// register per fixpoint pass; not recording the inter-procedural ones leaves a
// finding with two endpoints and no middle.

// StepKind labels what happened at one hop, so a reader is told why a line is on
// the path rather than being handed a bare list of positions.
type StepKind string

const (
	StepSource StepKind = "source" // where the untrusted value entered the program
	StepStep   StepKind = "step"   // a transform within one function
	StepCall   StepKind = "call"   // taint passed into a callee as an argument
	StepReturn StepKind = "return" // taint came back out of a callee
	StepGlobal StepKind = "global" // taint travelled through a package-level global
	StepSink   StepKind = "sink"   // where it reached the dangerous callee
)

// FlowStep is one hop on a taint path.
type FlowStep struct {
	Pos  *ir.Position
	Func string // enclosing function's CanonicalName
	Kind StepKind
	// InScope marks a hop in the code that was SCANNED, as opposed to a lowered
	// dependency. It is set from the engine's reportable scope, which is
	// authoritative, so it stays correct for every language rather than depending
	// on a consumer recognizing a package-manager path.
	InScope bool
}

// maxTrailHops bounds a trail defensively. First-seen-wins on every summary
// channel already stops a trail from containing its own storage slot, so depth is
// bounded by the call graph; this only guards a pathological program. The deepest
// chain observed in real code is under twenty hops.
const maxTrailHops = 128

// trail is an immutable, structurally shared linked list of hops, source-first
// (prev points toward the source). Immutability is what makes it cheap: one
// summary channel entry is shared by every path that flows through it, so the
// storage is one node per cross-function edge, not one slice per path.
type trail struct {
	prev *trail
	step FlowStep
	n    int
}

// push returns a trail with s appended sink-ward. A nil receiver is the empty
// trail, so a caller never needs to special-case the first hop.
//
// A hop with no position is DROPPED rather than recorded: it would render as
// ":0:0", which points a reader at nothing and reads as a broken path. Every
// frontend is required to populate Pos, so this is a backstop, not a licence —
// when it fires, the fix belongs in the frontend that emitted the instruction.
func (t *trail) push(s FlowStep) *trail {
	if s.Pos == nil {
		return t
	}
	n := 1
	if t != nil {
		if t.n >= maxTrailHops {
			return t
		}
		n = t.n + 1
	}
	return &trail{prev: t, step: s, n: n}
}

// pushAll appends hops given in source->sink order.
func (t *trail) pushAll(steps []FlowStep) *trail {
	for _, s := range steps {
		t = t.push(s)
	}
	return t
}

// steps materializes the trail in source->sink order, dropping a hop that
// repeats the previous one's position and function. Consecutive duplicates are
// routine — a call instruction and the return hop that lands on it share a
// position — and a repeated line reads as an analysis bug rather than as a flow.
// A duplicate carrying a source or sink label promotes the kept hop's kind
// instead of vanishing, so the endpoints stay labelled.
func (t *trail) steps() []FlowStep {
	if t == nil {
		return nil
	}
	rev := make([]FlowStep, 0, t.n)
	for n := t; n != nil; n = n.prev {
		rev = append(rev, n.step)
	}
	out := make([]FlowStep, 0, len(rev))
	for i := len(rev) - 1; i >= 0; i-- {
		s := rev[i]
		if n := len(out); n > 0 && out[n-1].Func == s.Func && samePos(out[n-1].Pos, s.Pos) {
			if s.Kind == StepSink || s.Kind == StepSource {
				out[n-1].Kind = s.Kind
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// taintFact is a taint origin together with the trail that delivered it. Every
// cross-function summary channel stores this rather than a bare *ir.Position, so
// an origin cannot cross a boundary without its provenance.
//
// The taint STATE (taintState) deliberately keeps bare positions: origin pointer
// identity is load-bearing there, for the validator-guard check in guards.go and
// for the interprocOrigins confidence downgrade.
type taintFact struct {
	origin *ir.Position
	trail  *trail
	// paths narrows the fact from the whole value to the one-level ACCESS PATHS
	// of it that actually carry the taint, and is recorded only by the return
	// channel. A multi-value return's element index and a struct field index
	// share one key space (fieldPathKey), so `v, err := f()` and `ticket.ID` are
	// discriminated by the same mechanism.
	//
	// Empty means the WHOLE value, which is both what every other channel records
	// and the fallback whenever the tainted part cannot be named — a nested field,
	// an array element. Narrower is never the safe default here: it would drop a
	// flow, so only a nameable path may narrow.
	paths []int32
	// params narrows the fact from every caller to the PARAMETERS the returned
	// taint depends on, and is recorded only by the return channel. A caller
	// pulls the summary only when it passed taint at one of them, so one caller
	// tainting a shared helper no longer hands taint back to every other caller
	// (ENG-14b).
	//
	// Empty means UNCONDITIONAL — the taint has no parameter to depend on (a
	// request accessor that reads the request inside the callee) or could not be
	// attributed to one. That is the pre-existing behaviour and the only safe
	// default: a parameter set narrower than the truth drops a real flow.
	params []int32
}

// whole reports whether f taints the entire returned value.
func (f taintFact) whole() bool { return f.origin != nil && len(f.paths) == 0 }

// maximal reports whether f is at the top of BOTH narrowing lattices — the whole
// value, pulled by every caller — so nothing can widen it further.
func (f taintFact) maximal() bool { return f.whole() && len(f.params) == 0 }

// widenTo merges src into f MONOTONICALLY and reports whether f grew, on either
// narrowing axis: a body with several returns summarizes all of them and a later
// worklist visit can widen what an earlier one narrowed. Growth is what
// re-enqueues a callee's callers; both unions are bounded by the function's
// arity, so the worklist still converges.
//
// The first origin and trail win, as they do on every other summary channel: they
// name one of the flows, and which one a reader is shown does not change whether
// the taint arrives.
func (f *taintFact) widenTo(src taintFact) bool {
	if src.origin == nil {
		return false
	}
	if f.origin == nil {
		*f = src
		return true
	}
	paths, pathsGrew := widenSet(f.paths, src.paths)
	params, paramsGrew := widenSet(f.params, src.params)
	f.paths, f.params = paths, params
	return pathsGrew || paramsGrew
}

// widenSet unions two of a taintFact's narrowing sets and reports whether dst
// grew. EMPTY is the maximal element on both axes — the whole value for paths,
// every caller for params — so it absorbs anything and is never narrowed back.
func widenSet(dst, src []int32) ([]int32, bool) {
	if len(dst) == 0 {
		return dst, false
	}
	if len(src) == 0 {
		return nil, true
	}
	out := slices.Clone(dst)
	for _, p := range src {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if len(out) == len(dst) {
		return dst, false
	}
	slices.Sort(out)
	return out, true
}

// step builds a hop in the function being analyzed.
func (fa *funcAnalysis) step(pos *ir.Position, kind StepKind) FlowStep {
	return FlowStep{Pos: pos, Func: fa.fn.GetCanonicalName(), Kind: kind, InScope: fa.funcReportable}
}

// localHops walks reg's def-use chain backward within this function and returns
// the hops crossed, SINK->SOURCE, along with the entry trail that delivered the
// taint into this function (nil when the taint originated here).
//
// It stops at a register whose taint came from OUTSIDE this function and hands
// back that register's trail rather than guessing at a source — which is what
// makes a path continue across a call instead of ending at the parameter.
//
// origin identifies WHICH flow is being traced; it is what stops the crossing
// out of a container from picking an unrelated source's write (see taintedStore).
func (fa *funcAnalysis) localHops(reg string, origin *ir.Position) (hops []FlowStep, entry *trail) {
	seen := map[string]bool{}
	for reg != "" && !seen[reg] {
		seen[reg] = true
		if t := fa.entryTrail[reg]; t != nil {
			return hops, t
		}
		def := fa.defs[reg]
		if def == nil {
			return hops, nil
		}
		if p := def.GetPos(); p != nil {
			hops = append(hops, fa.step(p, StepStep))
		}
		next := firstTaintedOperandReg(fa.tainted, def)
		if next == "" {
			site := fa.stores.taintedStore(fa.defs, fa.tainted, reg, origin)
			if site == nil {
				return hops, nil
			}
			if p := site.inst.GetPos(); p != nil {
				hops = append(hops, fa.step(p, StepStep))
			}
			next = site.val.GetRegName()
		}
		reg = next
	}
	return hops, nil
}

// trailTo returns the trail from the ultimate source up to reg's current taint:
// whatever delivered the taint into this function, followed by this function's
// own hops. When nothing delivered it, origin IS the source and opens the trail.
func (fa *funcAnalysis) trailTo(reg string, origin *ir.Position) *trail {
	hops, t := fa.localHops(reg, origin)
	if t == nil {
		t = t.push(FlowStep{Pos: origin, Func: fa.fn.GetCanonicalName(), Kind: StepSource, InScope: fa.funcReportable})
	}
	return t.pushAll(reverseHops(hops))
}

// localTrail is trailTo without the entry splice: only the hops inside this
// function. It is what a summary hands to a CALLER, which will supply its own
// prefix — splicing here would duplicate it.
func (fa *funcAnalysis) localTrail(reg string, origin *ir.Position) *trail {
	hops, _ := fa.localHops(reg, origin)
	return (*trail)(nil).pushAll(reverseHops(hops))
}

// reverseHops flips a sink->source hop list into source->sink order, in place.
func reverseHops(hops []FlowStep) []FlowStep {
	for i, j := 0, len(hops)-1; i < j; i, j = i+1, j-1 {
		hops[i], hops[j] = hops[j], hops[i]
	}
	return hops
}

// exportFact packages an origin with the trail that reaches inst, for handing to
// a cross-function summary channel. kind labels the boundary being crossed.
func (fa *funcAnalysis) exportFact(v *ir.Value, origin *ir.Position, inst *ir.Instruction, kind StepKind) taintFact {
	return taintFact{
		origin: origin,
		trail:  fa.trailTo(v.GetRegName(), origin).push(fa.step(inst.GetPos(), kind)),
	}
}

// pathTo builds the finding's full source->sink path for a sink at sinkPos
// reached through reg.
func (fa *funcAnalysis) pathTo(reg string, origin, sinkPos *ir.Position) []FlowStep {
	return fa.trailTo(reg, origin).push(fa.step(sinkPos, StepSink)).steps()
}

// importTaint records taint arriving from OUTSIDE this function: it marks the
// register, remembers the trail that delivered it, and flags the origin as
// having crossed a boundary (which is what makes the finding Medium). One helper
// for every import site, so none can record the taint without its provenance or
// without the confidence downgrade — they were separate lines at four sites, and
// a fifth site would have had to remember both.
//
// hop is where the taint materializes in THIS function: the call whose result it
// is, the load of the global, the call that filled the out-parameter.
func (fa *funcAnalysis) importTaint(state taintState, reg string, fact taintFact, hop FlowStep) {
	fa.recordEntry(state, reg, fact, fact.trail.push(hop))
}

// importParamTaint seeds a tainted parameter. No hop is added: the caller's trail
// already ends with the call that named this callee, and a parameter has no
// position of its own worth showing.
func (fa *funcAnalysis) importParamTaint(state taintState, reg string, fact taintFact) {
	fa.recordEntry(state, reg, fact, fact.trail)
}

func (fa *funcAnalysis) recordEntry(state taintState, reg string, fact taintFact, t *trail) {
	if reg == "" {
		return
	}
	markTainted(state, reg, fact.origin)
	fa.markInterproc(fact.origin)
	fa.recordEntryTrail(reg, t)
}

func (fa *funcAnalysis) recordEntryTrail(reg string, t *trail) {
	if reg == "" || t == nil {
		return
	}
	if fa.entryTrail == nil {
		fa.entryTrail = map[string]*trail{}
	}
	if _, seen := fa.entryTrail[reg]; !seen {
		fa.entryTrail[reg] = t
	}
}

// importPathTaint records taint arriving from a callee on specific ACCESS PATHS
// of reg rather than on the whole value: the precise key is what an in-frame
// field/element read consults, and the any-field marker is what the next call
// boundary consults, so cross-call recall is unchanged while a read of a
// different path stays clean.
//
// reg itself is left UNTAINTED — that is the point — but its entry trail is
// recorded anyway: path reconstruction walks def-use through plain register
// names, so without it a path would restart at this frame instead of continuing
// into the callee.
func (fa *funcAnalysis) importPathTaint(state taintState, reg string, fact taintFact, hop FlowStep) {
	if reg == "" {
		return
	}
	for _, idx := range fact.paths {
		fa.importTaint(state, fieldPathKey(reg, idx), fact, hop)
	}
	fa.importTaint(state, fieldAnyKey(reg), fact, hop)
	fa.recordEntryTrail(reg, fact.trail.push(hop))
}

// entryOf returns the first hop of a path that lies in scanned code — the line a
// reader can open and fix. A flow whose source is a framework's own request
// accessor begins inside a dependency, so without this the only location a
// finding offers is a file in the module cache.
func entryOf(steps []FlowStep) (*ir.Position, string) {
	for _, s := range steps {
		if s.InScope && s.Pos != nil {
			return s.Pos, s.Func
		}
	}
	return nil, ""
}

// PathCovers reports whether the finding's taint path visits lines in order, as
// a SUBSEQUENCE rather than a contiguous run. It backs the corpus `path:` oracle,
// whose whole point is that the MIDDLE of a flow survives: an added intermediate
// hop must not break a hand-written expectation, while a lost one must. Lines
// only, since a sample is one file; a nil expectation is vacuously covered.
func (f Finding) PathCovers(lines []int32) bool {
	i := 0
	for _, s := range f.Steps {
		if i < len(lines) && s.Pos.GetLine() == lines[i] {
			i++
		}
	}
	return i == len(lines)
}
