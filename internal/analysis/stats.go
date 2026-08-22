package analysis

import "time"

// Stats is what one AnalyzeWithStats run observed about the program and about
// its own cost. Index, RuleSelect and Taint are disjoint wall spans that
// partition the run.
type Stats struct {
	// Functions is the call-graph node count — distinct canonical function
	// names, which is a smaller set than the raw IR functions when two collapse
	// onto one name.
	Functions int

	// RulesLive is the rules the engine actually seeded, which is only the
	// DATAFLOW rules: canProduceFinding rejects a rule with no sinks, i.e. every
	// `kind: secret` and `kind: dangerous-call` rule — and those are genuinely
	// evaluated, by ScanSecrets and ScanDangerousCalls. Never present it as the
	// number of rules that ran.
	Rules     int
	RulesLive int

	// SourceSites and SinkSites count the CALL SITES whose callee matches some
	// rule's source or sink glob. They are a workload figure, not a bound on
	// findings: a sink match here ignores `#idx` injection-point pinning and
	// every `when:` guard, and a source match sees only callee-glob matches — the
	// seeding that is not a call at all (addHTTPRequestSource,
	// buildReqSourceHosts, request-object provenance) is invisible to it.
	SourceSites int
	SinkSites   int

	Index      time.Duration // function/method index and call graph
	RuleSelect time.Duration // rule compile, the can-produce-a-finding prefilter, and the counts above
	Taint      time.Duration // the parallel per-rule worklist
}
