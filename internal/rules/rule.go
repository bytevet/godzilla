// Package rules defines Godzilla's rule model and matching primitives.
//
// A taint Rule says: untrusted data produced by any Source that reaches any
// Sink, without first passing through a Sanitizer, is a vulnerability. Callees
// are identified by canonical fully-qualified names (see the gIR CallCommon.callee
// field), e.g. "go:net/http.(*Request).FormValue", and matched against rule
// patterns as globs where '*' matches any run of characters (including '/' and
// '.'). This lets one rule span languages, e.g. sinks ["go:*.Query", "py:*.execute"].
package rules

import (
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Severity ranks a finding's importance and drives exit-code gating.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rank returns a comparable ordering for a severity (higher is worse).
func (s Severity) Rank() int {
	switch Severity(strings.ToLower(string(s))) {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

// Rule is a single taint rule loaded from YAML.
type Rule struct {
	ID         string   `yaml:"id"`
	Languages  []string `yaml:"languages"` // empty => applies to all languages
	Severity   Severity `yaml:"severity"`
	CWE        string   `yaml:"cwe"`
	Message    string   `yaml:"message"`
	Sources    []string `yaml:"sources"`
	Sanitizers []string `yaml:"sanitizers"`

	// RequestObjectSources are source globs whose value is an untrusted HTTP
	// request OBJECT (not a scalar), e.g. Go's synthetic "go:@net/http.Request".
	// A DEPENDENCY function that contains one internally (a framework accessor
	// reading *http.Request through a field, with no tainted argument) generates
	// request taint out of nowhere, so the engine seeds such a function when user
	// code calls it directly (buildReqSourceHosts) — otherwise the demand-driven
	// dependency scope would never analyze it. These are also ordinary sources
	// (list them in Sources too); this only tags the flavor.
	RequestObjectSources []string `yaml:"request_object_sources"`

	// Sinks are dangerous callee globs. Each entry may append an injection-point
	// spec directly to its pattern with a "#" suffix: "pattern#i[,j...]" limits
	// the sink to LOGICAL (source-level, receiver-excluded) argument indices
	// i,j,... — so taint reaching any OTHER argument is not a finding. A bare
	// pattern (no "#") means every argument is an injection point.
	//
	// This is what prevents parameterized-query false positives: for
	// "go:...Query#0" only the query-string argument is an injection point, so
	// db.Query("... = ?", taintedParam) — where taintedParam is a safe bound
	// placeholder at a later position — is correctly NOT flagged.
	Sinks []string `yaml:"sinks"`

	Propagators []string `yaml:"propagators"` // callees that pass taint arg->result (e.g. fmt.Sprintf)

	// Kind selects the rule's evaluation model. "" (or "taint") is the default
	// source->sink dataflow rule. "dangerous-call" (COV-4) is a non-dataflow,
	// call-site-syntactic check: any call to a Callee glob is a finding, optionally
	// gated on a constant string argument — for zero-noise categories like weak
	// crypto, weak ciphers, and insecure randomness that need no taint tracking.
	Kind string `yaml:"kind"`

	// Callees are the dangerous call globs for a kind: dangerous-call rule.
	Callees []string `yaml:"callees"`

	// ConstArg optionally restricts a dangerous-call match to calls whose constant
	// string argument at the LOGICAL index Index matches the Matches regexp — e.g.
	// the "MD5" literal in MessageDigest.getInstance("MD5"). Nil means any call to
	// a Callee fires regardless of arguments.
	ConstArg *ConstArg `yaml:"const_arg"`

	// Validators are guard/barrier callees (ENG-9): a boolean-returning check
	// (an allowlist test, a regexp match, a path-containment predicate like
	// filepath.IsLocal) that, when it dominates the branch leading to a sink,
	// clears the checked value's taint on that path. Unlike a Sanitizer — which
	// transforms a value and returns a clean result — a Validator returns a bool
	// and leaves the value unchanged; it neutralizes the finding by controlling
	// which path reaches the sink. Matched by canonical-FQN glob, like sinks.
	Validators []string `yaml:"validators"`

	// matchers holds the pattern lists precompiled to shape-matchers (built by
	// Compile). Unexported and not from YAML; nil until compiled, when the
	// matching methods fall back to the package-level cached path.
	matchers *ruleMatchers
}

// ConstArg is a dangerous-call rule's optional constant-argument condition.
type ConstArg struct {
	Index   int    `yaml:"index"`   // logical (receiver-excluded) argument index
	Matches string `yaml:"matches"` // regexp the constant string argument must match
}

// RuleSet is a collection of rules, matching the top-level YAML document shape.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// Compile precompiles every rule's patterns (see Rule.Compile). Call it once,
// single-threaded, before matching — in particular before running independent
// analysis passes concurrently over the same rule set, so they don't race
// building per-rule matchers (after this, all matcher access is read-only).
// Idempotent.
func (rs *RuleSet) Compile() {
	for i := range rs.Rules {
		rs.Rules[i].Compile()
	}
}

// IsDangerousCall reports whether the rule is a non-dataflow, call-site rule.
func (r *Rule) IsDangerousCall() bool { return strings.EqualFold(r.Kind, "dangerous-call") }

// MatchesDangerousCallee reports whether callee matches one of the rule's
// dangerous-call globs.
func (r *Rule) MatchesDangerousCallee(callee string) bool {
	if r.matchers != nil {
		return matchAnyCompiled(r.matchers.callees, callee)
	}
	return MatchAny(r.Callees, callee)
}

// AppliesTo reports whether the rule is active for the given source language
// (e.g. "go"). A rule with no declared Languages applies to every language.
func (r *Rule) AppliesTo(language string) bool {
	if len(r.Languages) == 0 {
		return true
	}
	return slices.ContainsFunc(r.Languages, func(l string) bool {
		return strings.EqualFold(l, language)
	})
}

// ruleMatchers holds a rule's pattern lists precompiled into shape-matchers, so
// the hot matching path (once per call-site × rule) is a plain slice walk with
// no per-call cache lookup, mutex, or "#idx" re-parse. Built once by Compile;
// nil until then, in which case the matching methods fall back to the
// package-level cached path (correct, just slower — used by tests and the
// non-hot dangerous-call scan).
type ruleMatchers struct {
	sources     []*compiledGlob
	sinks       []compiledSink
	sanitizers  []*compiledGlob
	propagators []*compiledGlob
	validators  []*compiledGlob
	callees     []*compiledGlob
}

// compiledSink pairs a sink's shape-matcher with its parsed injection-point
// argument indices (nil = all arguments).
type compiledSink struct {
	g    *compiledGlob
	args []int32
}

// Compile precompiles the rule's pattern lists into shape-matchers. Call it once
// (single-threaded) before matching a rule against many call sites — the engine
// does this for every rule before its parallel analysis. Idempotent.
func (r *Rule) Compile() {
	if r.matchers != nil {
		return
	}
	m := &ruleMatchers{
		sources:     classifyAll(r.Sources),
		sanitizers:  classifyAll(r.Sanitizers),
		propagators: classifyAll(r.Propagators),
		validators:  classifyAll(r.Validators),
		callees:     classifyAll(r.Callees),
	}
	for _, entry := range r.Sinks {
		pattern, idx := parseSink(entry)
		m.sinks = append(m.sinks, compiledSink{g: classifyGlob(pattern), args: idx})
	}
	r.matchers = m
}

func classifyAll(patterns []string) []*compiledGlob {
	out := make([]*compiledGlob, len(patterns))
	for i, p := range patterns {
		out[i] = classifyGlob(p)
	}
	return out
}

func matchAnyCompiled(gs []*compiledGlob, s string) bool {
	for _, g := range gs {
		if g.match(s) {
			return true
		}
	}
	return false
}

// IsSource reports whether callee matches any of the rule's source patterns.
func (r *Rule) IsSource(callee string) bool {
	if r.matchers != nil {
		return matchAnyCompiled(r.matchers.sources, callee)
	}
	return MatchAny(r.Sources, callee)
}

// IsSink reports whether callee matches any of the rule's sink patterns.
func (r *Rule) IsSink(callee string) bool {
	_, ok := r.SinkInjectionArgs(callee)
	return ok
}

// SinkInjectionArgs reports whether callee matches one of the rule's sinks and,
// if so, returns that sink's injection-point argument indices (LOGICAL,
// source-level). A nil/empty result with ok==true means every argument is an
// injection point (a bare pattern with no "#" spec).
func (r *Rule) SinkInjectionArgs(callee string) (args []int32, ok bool) {
	if r.matchers != nil {
		for _, s := range r.matchers.sinks {
			if s.g.match(callee) {
				return s.args, true
			}
		}
		return nil, false
	}
	for _, entry := range r.Sinks {
		pattern, idx := parseSink(entry)
		if MatchGlob(pattern, callee) {
			return idx, true
		}
	}
	return nil, false
}

// InvalidSinkSpec reports whether a sink entry carries a "#" injection-point
// spec that names no valid argument index — an empty spec ("...Query#") or one
// whose tokens are not all non-negative integers ("...Query#x", "...Query#-1",
// "...Query#0,"). Such an entry parses (leniently, at runtime) to zero indices,
// which is indistinguishable from a bare pattern and so silently widens the
// sink to "every argument is an injection point" — the false-positive-prone
// default an author who bothered to write "#" almost certainly did NOT intend
// (it reintroduces the parameterized-query false positive). The loader rejects
// it so a typo fails loud at load time instead of quietly weakening the sink.
func InvalidSinkSpec(entry string) bool {
	_, spec, ok := strings.Cut(entry, "#")
	if !ok {
		return false // bare pattern legitimately means "all arguments"
	}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true // "#" with nothing after it
	}
	for _, f := range strings.Split(spec, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err != nil || n < 0 {
			return true // a token that is not a non-negative integer
		}
	}
	return false
}

// parseSink splits a sink entry "pattern#i,j,..." into its glob pattern and the
// injection-point indices. A bare pattern (no "#") yields nil indices (all args).
func parseSink(entry string) (pattern string, args []int32) {
	pattern, spec, ok := strings.Cut(entry, "#")
	if !ok {
		return entry, nil
	}
	for _, f := range strings.Split(spec, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil && n >= 0 {
			args = append(args, int32(n))
		}
	}
	return pattern, args
}

// IsSanitizer reports whether callee matches any of the rule's sanitizer patterns.
func (r *Rule) IsSanitizer(callee string) bool {
	if r.matchers != nil {
		return matchAnyCompiled(r.matchers.sanitizers, callee)
	}
	return MatchAny(r.Sanitizers, callee)
}

// IsPropagator reports whether callee matches any of the rule's propagator patterns.
func (r *Rule) IsPropagator(callee string) bool {
	if r.matchers != nil {
		return matchAnyCompiled(r.matchers.propagators, callee)
	}
	return MatchAny(r.Propagators, callee)
}

// IsValidator reports whether callee matches any of the rule's validator (guard)
// patterns.
func (r *Rule) IsValidator(callee string) bool {
	if r.matchers != nil {
		return matchAnyCompiled(r.matchers.validators, callee)
	}
	return MatchAny(r.Validators, callee)
}

// HasValidators reports whether the rule declares any guard/barrier validators,
// so the engine can skip the (dominator) guard analysis entirely for rules that
// don't use the feature — keeping the common path free of extra work.
func (r *Rule) HasValidators() bool { return len(r.Validators) > 0 }

// MatchAny reports whether s matches any of the glob patterns.
func MatchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if MatchGlob(p, s) {
			return true
		}
	}
	return false
}

// MatchGlob reports whether s matches a canonical-name glob. The only
// metacharacter is '*', which matches any run of characters including '/' and
// '.'; everything else is matched literally. Matching is anchored (full string).
//
// The overwhelming majority of real canonical-name globs are pure literals
// (`ruby:system`) or a single `*` prefix/suffix (`c*:strcpy`, `go:*request*`).
// Running a backtracking regexp for those is wasteful — and glob matching is the
// hottest CPU cost in the engine, run once per (call-site × rule pattern), so it
// grows linearly with rule-pack size. compileGlob classifies each pattern by
// shape once (cached) and matches with plain string primitives; only genuinely
// multi-`*` patterns fall to the general segment walk. No regexp, no per-match
// allocation, identical semantics.
func MatchGlob(pattern, s string) bool {
	return compileGlob(pattern).match(s)
}

type globKind int

const (
	globExact        globKind = iota // no '*': s == a
	globPrefix                       // "a*": HasPrefix(s, a)
	globSuffix                       // "*a": HasSuffix(s, a)
	globPrefixSuffix                 // "a*b": HasPrefix(s,a) && HasSuffix(s,b)
	globContains                     // "*a*": Contains(s, a)
	globSegments                     // multiple '*': ordered-substring walk
	globAny                          // "*"/"**": matches anything
	globNever                        // invalid-UTF8 pattern: matches nothing (DoS guard)
)

// compiledGlob is a canonical-name glob classified by shape for fast matching.
type compiledGlob struct {
	kind      globKind
	a, b      string   // literal(s) for exact/prefix/suffix/contains (a) and prefixSuffix (a,b)
	segs      []string // non-empty literal segments between '*'s (globSegments)
	leadStar  bool     // pattern begins with '*'
	trailStar bool     // pattern ends with '*'
}

func (g *compiledGlob) match(s string) bool {
	switch g.kind {
	case globExact:
		return s == g.a
	case globPrefix:
		return strings.HasPrefix(s, g.a)
	case globSuffix:
		return strings.HasSuffix(s, g.a)
	case globPrefixSuffix:
		return len(s) >= len(g.a)+len(g.b) && strings.HasPrefix(s, g.a) && strings.HasSuffix(s, g.b)
	case globContains:
		return strings.Contains(s, g.a)
	case globAny:
		return true
	case globNever:
		return false
	default: // globSegments
		return g.matchSegments(s)
	}
}

// matchSegments matches a multi-'*' pattern: each literal segment must occur in
// order, with the first anchored at the start (unless the pattern led with '*')
// and the last anchored at the end (unless it trailed with '*').
func (g *compiledGlob) matchSegments(s string) bool {
	segs := g.segs
	rest := s
	if !g.leadStar {
		if !strings.HasPrefix(rest, segs[0]) {
			return false
		}
		rest = rest[len(segs[0]):]
		segs = segs[1:]
	}
	if !g.trailStar && len(segs) > 0 {
		last := segs[len(segs)-1]
		if !strings.HasSuffix(rest, last) {
			return false
		}
		rest = rest[:len(rest)-len(last)]
		segs = segs[:len(segs)-1]
	}
	for _, seg := range segs {
		i := strings.Index(rest, seg)
		if i < 0 {
			return false
		}
		rest = rest[i+len(seg):]
	}
	return true
}

var (
	globCacheMu sync.RWMutex
	globCache   = map[string]*compiledGlob{}
)

func compileGlob(pattern string) *compiledGlob {
	globCacheMu.RLock()
	g, ok := globCache[pattern]
	globCacheMu.RUnlock()
	if ok {
		return g
	}
	g = classifyGlob(pattern)
	globCacheMu.Lock()
	globCache[pattern] = g
	globCacheMu.Unlock()
	return g
}

func classifyGlob(pattern string) *compiledGlob {
	// A pattern with invalid UTF-8 bytes matched nothing under the old regexp
	// path (a fuzz-found DoS guard); preserve that exactly.
	if !utf8.ValidString(pattern) {
		return &compiledGlob{kind: globNever}
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return &compiledGlob{kind: globExact, a: pattern}
	}
	leadStar := parts[0] == ""
	trailStar := parts[len(parts)-1] == ""
	var segs []string
	for _, p := range parts {
		if p != "" {
			segs = append(segs, p)
		}
	}
	if len(segs) == 0 {
		return &compiledGlob{kind: globAny} // pattern is only '*'s
	}
	if len(parts) == 2 { // exactly one '*'
		switch {
		case leadStar:
			return &compiledGlob{kind: globSuffix, a: parts[1]}
		case trailStar:
			return &compiledGlob{kind: globPrefix, a: parts[0]}
		default:
			return &compiledGlob{kind: globPrefixSuffix, a: parts[0], b: parts[1]}
		}
	}
	if len(segs) == 1 && leadStar && trailStar { // "*x*"
		return &compiledGlob{kind: globContains, a: segs[0]}
	}
	return &compiledGlob{kind: globSegments, segs: segs, leadStar: leadStar, trailStar: trailStar}
}
