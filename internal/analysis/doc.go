// Package analysis implements Godzilla's taint analysis engine: it walks gIR
// programs and reports Findings for source-to-sink dataflows described by a
// rules.RuleSet, alongside two non-dataflow passes (dangerous-call and secrets).
//
// # Why the design is shaped this way
//
// One engine serves every language. Frontends lower Go, Python, JavaScript,
// Java, Ruby, Rust and C/C++ into the same IR, so nothing here may match on a
// language's callee names: anything language-specific arrives either as a
// canonical FQN a RULE matches, or as an intrinsic the frontends agree on
// (builtin.format, builtin.identity, builtin.kwarg,
// builtin.aggregate/builtin.aggregate_map). When a check seems to need
// a language check, the fix is almost always a new intrinsic or a rule glob.
//
// # The core loop
//
// Engine.Analyze (interproc.go) is an inter-procedural, context-insensitive
// worklist. Within a function, taint moves by SSA def-use plus the transfer
// helpers in taint.go; across functions it moves by summary — a tainted argument
// taints the callee's parameter, and a taint-returning callee taints its caller's
// call result. callgraph.go supplies CHA for dynamic dispatch, and its reverse
// edges re-enqueue a callee's callers when the callee becomes taint-returning.
//
// Findings carry a Confidence: intra-procedural is High, cross-function Medium.
// That is what the LLM reviewer triages on, and it is deliberately independent of
// severity, which is what the CI gate keys on.
//
// # Precision guards
//
// These are the parts most likely to be "simplified" into a regression; each is
// argued in full at its own definition:
//
//   - Sink-parameter summaries (funcResult.taintsParamSink) report a flow into a
//     dependency's sink wrapper at the USER call site, since the dep-internal
//     finding is scoped out. String-typed parameters only.
//
//   - Framework-agnostic HTTP request sources come from two complementary,
//     name-list-free mechanisms. A framework's own accessor is tainted at the CALL
//     SITE by a rule source glob — a deliberate performance choice, since seeding
//     the framework's context object would force taint through its whole request
//     pipeline. For frameworks layered on net/http, the stdlib request accessors
//     are default propagators, carrying request taint through internal parsing at
//     no false-positive cost.
//
//   - ssrf.go supplies the hostFixed() FACT, not a decision: whether it suppresses
//     anything is the RULE's choice, via `when: 'not hostFixed()'`. The engine
//     must not branch on CWE — that silently denies the reduction to a custom rule
//     tagged anything else, and to open-redirect.
//
//   - guards.go (dominator-based validator suppression) needs a real CFG, which
//     every frontend now emits. linearFn marks branch-free functions in any
//     language, where program order already is dominance.
//
// # Files
//
// interproc.go the worklist and call handling; taint.go transfer helpers;
// flow.go path reconstruction; guards.go dominator guards; callgraph.go CHA;
// ssrf.go host-fixedness; dangerous.go call-site rules; secrets.go CWE-798;
// fingerprint.go baseline identity; finding.go the shared Finding type.
package analysis
