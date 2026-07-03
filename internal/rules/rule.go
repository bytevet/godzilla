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
	"regexp"
	"strconv"
	"strings"
	"sync"
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
}

// RuleSet is a collection of rules, matching the top-level YAML document shape.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// AppliesTo reports whether the rule is active for the given source language
// (e.g. "go"). A rule with no declared Languages applies to every language.
func (r *Rule) AppliesTo(language string) bool {
	if len(r.Languages) == 0 {
		return true
	}
	for _, l := range r.Languages {
		if strings.EqualFold(l, language) {
			return true
		}
	}
	return false
}

// IsSource reports whether callee matches any of the rule's source patterns.
func (r *Rule) IsSource(callee string) bool { return MatchAny(r.Sources, callee) }

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
func (r *Rule) IsSanitizer(callee string) bool { return MatchAny(r.Sanitizers, callee) }

// IsPropagator reports whether callee matches any of the rule's propagator patterns.
func (r *Rule) IsPropagator(callee string) bool { return MatchAny(r.Propagators, callee) }

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
func MatchGlob(pattern, s string) bool {
	return globRegexp(pattern).MatchString(s)
}

var (
	globCacheMu sync.RWMutex
	globCache   = map[string]*regexp.Regexp{}
)

func globRegexp(pattern string) *regexp.Regexp {
	globCacheMu.RLock()
	re, ok := globCache[pattern]
	globCacheMu.RUnlock()
	if ok {
		return re
	}

	// Translate the glob to an anchored regexp: quote each literal segment
	// between '*' metacharacters and join the segments with ".*".
	var b strings.Builder
	b.WriteString("^")
	for i, part := range strings.Split(pattern, "*") {
		if i > 0 {
			b.WriteString(".*")
		}
		b.WriteString(regexp.QuoteMeta(part))
	}
	b.WriteString("$")

	re = regexp.MustCompile(b.String())
	globCacheMu.Lock()
	globCache[pattern] = re
	globCacheMu.Unlock()
	return re
}
