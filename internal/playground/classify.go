package playground

import (
	"sort"

	"github.com/bytevet/godzilla/internal/rules"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// How many of each pattern kind the UI opens with.
const (
	presetSinkCount   = 3
	presetSourceCount = 2
	presetPropCount   = 1
)

// probe answers "did THIS pattern match", which a rule cannot: MatchSink reports
// that some sink matched, not which one. One single-pattern rule/GlobSet per
// authored pattern recovers that WITHOUT a second matcher, so the badge stays
// internal/rules' verdict rather than a second reading of it.
type probe struct {
	pattern string
	sink    *rules.Rule    // single-sink probe; also yields the pinned indices
	glob    *rules.GlobSet // plain glob: sources, dangerous-call callees, propagators
}

// newSinkProbe carries the sink ENTRY across, not just its pattern text, and
// the owning rule's When with it: a sink inherits the rule-level guard, and
// SinksOf would rebuild a bare Sink that has none. A probe stripped of its
// guard reports a plain sink where the engine evaluates a condition and may
// suppress — the badge would then over-claim in exactly the direction this tool
// must never be wrong about.
func newSinkProbe(s rules.Sink, when string) probe {
	r := &rules.Rule{When: when, Sinks: []rules.Sink{s}}
	_ = r.Compile()
	return probe{pattern: s.Pattern, sink: r}
}

func newGlobProbe(pattern string) probe {
	return probe{pattern: pattern, glob: rules.NewGlobSet([]string{pattern})}
}

// match reports the pinned argument indices and whether the entry carries a
// `when:` guard — a guarded sink fires only if that condition holds, so the two
// are different verdicts and the UI says which it is.
func (p *probe) match(callee string) (args []int32, guarded, ok bool) {
	if p.sink != nil {
		var g *rules.Guard
		args, g, ok = p.sink.MatchSink(callee)
		return args, g != nil, ok
	}
	return nil, false, p.glob.Match(callee)
}

// ruleProbes keeps a rule's probes under the rule itself, so AppliesTo is asked
// once per rule rather than once per pattern on every instruction.
type ruleProbes struct {
	rule  *rules.Rule
	sinks []probe
	srcs  []probe
}

type classifier struct {
	rules []ruleProbes
	props []probe // presets only; the badge has no propagator kind
}

// newClassifier compiles every pattern in rs once. flag runs per instruction per
// file view, so nothing here may be rebuilt per call.
func newClassifier(rs *rules.RuleSet) *classifier {
	c := &classifier{}
	if rs == nil {
		return c
	}
	seenProp := map[string]bool{}
	addProp := func(pattern string) {
		if pattern == "" || seenProp[pattern] {
			return
		}
		seenProp[pattern] = true
		c.props = append(c.props, newGlobProbe(pattern))
	}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.IsSecret() {
			continue // matches string constants, never a callee
		}
		rp := ruleProbes{rule: r}
		for _, s := range r.Sinks {
			if s.Pattern != "" {
				rp.sinks = append(rp.sinks, newSinkProbe(s, r.When))
			}
		}
		// A dangerous-call rule declares no Sinks; its Callees are the call sites
		// the engine reports, so they earn the same badge. Globbed whole (never
		// through SinksOf), which is what the engine does with them.
		for _, cal := range r.Callees {
			if cal.Pattern != "" {
				rp.sinks = append(rp.sinks, newGlobProbe(cal.Pattern))
			}
		}
		for _, s := range r.Sources {
			if s != "" {
				rp.srcs = append(rp.srcs, newGlobProbe(s))
			}
		}
		c.rules = append(c.rules, rp)
		for _, p := range r.Propagators {
			addProp(p)
		}
	}
	for _, p := range rs.DefaultPropagators {
		addProp(p)
	}
	return c
}

// flag is the loaded rules' verdict on one instruction: the first sink pattern
// that matches its callee, else the first source pattern, else nothing.
func (c *classifier) flag(lang string, in *ir.Instruction) *flagView {
	callee := in.GetCall().GetCallee()
	if callee == "" {
		return nil
	}
	for i := range c.rules {
		rp := &c.rules[i]
		if !rp.rule.AppliesTo(lang) {
			continue
		}
		for j := range rp.sinks {
			args, guarded, ok := rp.sinks[j].match(callee)
			if !ok {
				continue
			}
			fv := &flagView{Kind: "sink", Rule: rp.rule.ID, CWE: rp.rule.CWE,
				Pattern: rp.sinks[j].pattern, Guarded: guarded}
			if len(args) > 0 {
				idx := args[0]
				fv.Idx = &idx
			}
			return fv
		}
	}
	for i := range c.rules {
		rp := &c.rules[i]
		if !rp.rule.AppliesTo(lang) {
			continue
		}
		for j := range rp.srcs {
			if _, _, ok := rp.srcs[j].match(callee); ok {
				return &flagView{Kind: "source", Rule: rp.rule.ID, CWE: rp.rule.CWE, Pattern: rp.srcs[j].pattern}
			}
		}
	}
	return nil
}

// presets picks the patterns the tester opens with. Only patterns matching a
// callee the tester can actually be RUN against qualify — so the callees come
// from the files in the tree, not the whole program: a pattern that only matches
// inside a lowered dependency would offer itself and then report nothing.
func (c *classifier) presets(callees map[string]bool) presetView {
	ci := newCalleeIndex(callees)
	var sinks, srcs []probe
	seenSink, seenSrc := map[string]bool{}, map[string]bool{}
	for i := range c.rules {
		for _, p := range c.rules[i].sinks {
			if !seenSink[p.pattern] {
				seenSink[p.pattern] = true
				sinks = append(sinks, p)
			}
		}
		for _, p := range c.rules[i].srcs {
			if !seenSrc[p.pattern] {
				seenSrc[p.pattern] = true
				srcs = append(srcs, p)
			}
		}
	}
	return presetView{
		Sinks:       topMatching(sinks, ci, presetSinkCount),
		Sources:     topMatching(srcs, ci, presetSourceCount),
		Propagators: topMatching(c.props, ci, presetPropCount),
	}
}

// calleeIndex groups callees by their "<lang>:" prefix, and keeps the flat list
// for patterns that have none. An anchored `py:` pattern cannot match a `go:`
// callee, so bucketing turns the ranking pass from probes x callees into probes
// x one language's callees — the difference between milliseconds and a second
// on a large program, on the path that blocks the listener.
type calleeIndex struct {
	all    []string
	byLang map[string][]string
}

func newCalleeIndex(callees map[string]bool) calleeIndex {
	ci := calleeIndex{all: make([]string, 0, len(callees)), byLang: map[string][]string{}}
	for c := range callees {
		ci.all = append(ci.all, c)
		if lang := patternLang(c); lang != "" {
			ci.byLang[lang] = append(ci.byLang[lang], c)
		}
	}
	return ci
}

// subjects returns the callees a pattern could possibly match. A pattern with
// no parseable language prefix — one that leads with '*' — has to see them all.
func (ci calleeIndex) subjects(pattern string) []string {
	if lang := patternLang(pattern); lang != "" {
		return ci.byLang[lang]
	}
	return ci.all
}

// topMatching returns the n patterns matching the most distinct callees. Ties
// break on the pattern text so the preset row does not reshuffle between runs.
func topMatching(ps []probe, ci calleeIndex, n int) []string {
	type scored struct {
		pattern string
		hits    int
	}
	var ranked []scored
	for i := range ps {
		hits := 0
		for _, callee := range ci.subjects(ps[i].pattern) {
			if _, _, ok := ps[i].match(callee); ok {
				hits++
			}
		}
		if hits > 0 {
			ranked = append(ranked, scored{pattern: ps[i].pattern, hits: hits})
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].hits != ranked[j].hits {
			return ranked[i].hits > ranked[j].hits
		}
		return ranked[i].pattern < ranked[j].pattern
	})
	out := []string{}
	for i := 0; i < len(ranked) && i < n; i++ {
		out = append(out, ranked[i].pattern)
	}
	return out
}
