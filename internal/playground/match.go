package playground

import (
	"strings"

	"github.com/bytevet/godzilla/internal/rules"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// maxMatchHits caps the listed hits; Count still reports every match.
const maxMatchHits = 12

type matchRequest struct {
	File    string `json:"file"`
	Pattern string `json:"pattern"`
}

type matchHit struct {
	Ord       int    `json:"ord"`
	PinnedIdx int32  `json:"pinnedIdx"`
	Pinned    string `json:"pinned,omitempty"`
}

type matchResult struct {
	Count       int        `json:"count"`
	Pinned      []int32    `json:"pinned,omitempty"`      // logical indices the #spec pinned; empty = every argument
	Matches     []matchHit `json:"matches"`               // capped at maxMatchHits
	ModuleLang  string     `json:"moduleLang,omitempty"`  // the module's language, e.g. "go"
	PatternLang string     `json:"patternLang,omitempty"` // the pattern's "<lang>:" prefix, e.g. "py"
	Error       string     `json:"error,omitempty"`
}

// Match tries one sink pattern against a file's calls, through the same
// internal/rules matching the engine uses — including the "#idx" spec, so a
// pattern that the loader would REJECT is reported as rejected here rather than
// silently widening to "every argument".
func (idx *Index) Match(fileID, pattern string) matchResult {
	res := matchResult{Matches: []matchHit{}}
	pat := strings.TrimSpace(pattern)
	res.PatternLang = patternLang(pat)

	fv := idx.View(fileID)
	if fv == nil {
		res.Error = "this file has no gIR, so no pattern can match in it"
		return res
	}
	res.ModuleLang = fv.Module.Language

	switch {
	case pat == "":
		res.Error = "enter a canonical-name pattern, e.g. go:*database/sql*.Query#0"
		return res
	case rules.InvalidSinkSpec(pat):
		res.Error = `bad injection point: "#" must be followed by non-negative logical argument indices, e.g. "#0" or "#0,1"`
		return res
	}
	r := &rules.Rule{Sinks: rules.SinksOf(pat)}
	if err := r.Compile(); err != nil {
		res.Error = err.Error()
		return res
	}

	for ord, in := range fv.ords {
		cc := in.GetCall()
		callee := cc.GetCallee()
		if callee == "" {
			continue
		}
		args, _, ok := r.MatchSink(callee)
		if !ok {
			continue
		}
		res.Count++
		if res.Count == 1 {
			res.Pinned = args
		}
		if len(res.Matches) >= maxMatchHits {
			continue
		}
		hit := matchHit{Ord: ord}
		if len(args) > 0 {
			hit.PinnedIdx = args[0]
			hit.Pinned = argText(pinnedArg(cc, args[0]))
		}
		res.Matches = append(res.Matches, hit)
	}
	return res
}

// pinnedArg resolves a LOGICAL injection-point index to the physical argument.
// A statically-resolved method call carries its receiver as args[0], so physical
// = logical + 1; an INVOKE keeps its receiver in Call.Value and the two indices
// coincide. Read off the IR rather than the callee's name shape, exactly as
// internal/analysis.logicalArgs does — showing the wrong argument here is the
// silent mis-pin this tool exists to expose.
func pinnedArg(cc *ir.CallCommon, logical int32) *ir.Value {
	args := cc.GetArgs()
	phys := int(logical)
	if !cc.GetIsInvoke() && cc.GetMethodName() != "" {
		phys++
	}
	if phys < 0 || phys >= len(args) {
		return nil
	}
	return args[phys]
}

func argText(v *ir.Value) string {
	vv := valView(v)
	if c := vv.Constant; c != nil {
		return c.StringVal
	}
	switch {
	case vv.RegName != "":
		return vv.RegName
	case vv.GlobalName != "":
		return vv.GlobalName
	case vv.FuncName != "":
		return vv.FuncName
	}
	return ""
}

// patternLang is the pattern's "<lang>:" prefix, so the UI can say a go: pattern
// is being tried against a python module instead of just reporting zero matches.
func patternLang(pattern string) string {
	prefix, _, ok := strings.Cut(pattern, ":")
	if !ok || prefix == "" {
		return ""
	}
	for _, r := range prefix {
		if r < 'a' || r > 'z' {
			return ""
		}
	}
	return prefix
}
