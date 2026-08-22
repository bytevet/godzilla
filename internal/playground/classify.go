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
// authored pattern recovers that WITHOUT a second matcher — the badge is still
// internal/rules' verdict, so it cannot drift from the engine's.
type probe struct {
	pattern string
	sink    *rules.Rule    // single-sink probe; also yields the pinned indices
	glob    *rules.GlobSet // plain glob: sources, dangerous-call callees, propagators
}

func newSinkProbe(pattern string) probe {
	// A guard-less sink cannot fail to compile (CompileGuard("") is a no-op) and
	// a probe that somehow did would simply match nothing.
	r := &rules.Rule{Sinks: rules.SinksOf(pattern)}
	_ = r.Compile()
	return probe{pattern: pattern, sink: r}
}

func newGlobProbe(pattern string) probe {
	return probe{pattern: pattern, glob: rules.NewGlobSet([]string{pattern})}
}

func (p *probe) match(callee string) (args []int32, ok bool) {
	if p.sink != nil {
		args, _, ok = p.sink.MatchSink(callee)
		return args, ok
	}
	return nil, p.glob.Match(callee)
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
				rp.sinks = append(rp.sinks, newSinkProbe(s.Pattern))
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
			args, ok := rp.sinks[j].match(callee)
			if !ok {
				continue
			}
			fv := &flagView{Kind: "sink", Rule: rp.rule.ID, CWE: rp.rule.CWE, Pattern: rp.sinks[j].pattern}
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
			if _, ok := rp.srcs[j].match(callee); ok {
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
		Sinks:       topMatching(sinks, callees, presetSinkCount),
		Sources:     topMatching(srcs, callees, presetSourceCount),
		Propagators: topMatching(c.props, callees, presetPropCount),
	}
}

// topMatching returns the n patterns matching the most distinct callees. Ties
// break on the pattern text so the preset row does not reshuffle between runs.
func topMatching(ps []probe, callees map[string]bool, n int) []string {
	type scored struct {
		pattern string
		hits    int
	}
	var ranked []scored
	for i := range ps {
		hits := 0
		for callee := range callees {
			if _, ok := ps[i].match(callee); ok {
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
