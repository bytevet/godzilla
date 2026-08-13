package analysis

import (
	"fmt"
	"testing"

	"github.com/bytevet/godzilla/internal/rules"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// buildScaleProgram builds a synthetic program of nFunc functions, each a
// source → propagator → sink chain, so the engine has a realistic number of
// call sites to match every rule pattern against (the glob-matcher inner loop).
func buildScaleProgram(nFunc int) *ir.Program {
	mod := &ir.Module{Name: "bench", Language: "go"}
	for i := 0; i < nFunc; i++ {
		src := &ir.Instruction{
			Name: "t0", Op: ir.OpCode_OP_CODE_CALL,
			Call: &ir.CallCommon{Callee: "go:net/http.(*Request).FormValue"},
		}
		mid := &ir.Instruction{
			Name: "t1", Op: ir.OpCode_OP_CODE_CALL,
			Call: &ir.CallCommon{Callee: "go:strings.TrimSpace", Args: []*ir.Value{{Kind: &ir.Value_RegName{RegName: "t0"}}}},
		}
		sink := &ir.Instruction{
			Op: ir.OpCode_OP_CODE_CALL,
			Call: &ir.CallCommon{
				Callee: "go:os/exec.Command",
				Args:   []*ir.Value{{Kind: &ir.Value_RegName{RegName: "t1"}}},
			},
		}
		mod.Functions = append(mod.Functions, &ir.Function{
			Name:          fmt.Sprintf("h%d", i),
			CanonicalName: fmt.Sprintf("go:bench.h%d", i),
			Blocks:        []*ir.BasicBlock{{Index: 0, Instrs: []*ir.Instruction{src, mid, sink}}},
		})
	}
	return &ir.Program{Modules: []*ir.Module{mod}}
}

// scaleRules returns a rule set of `count` command-injection rules with distinct
// IDs but realistic glob patterns, modeling a large rule pack. The engine
// matches every call site against every rule's patterns, so this is the
// per-(call-site × pattern) cost the shape-specialized glob matcher targets
// (PERF-5: keep rule-pack growth cheap).
func scaleRules(count int) *rules.RuleSet {
	rs := &rules.RuleSet{}
	for i := 0; i < count; i++ {
		rs.Rules = append(rs.Rules, rules.Rule{
			ID:        fmt.Sprintf("bench-cmdi-%d", i),
			Languages: []string{"go"},
			Severity:  rules.SeverityCritical,
			CWE:       "CWE-78",
			Sources:   []string{"go:*.FormValue", "go:*.Query", "go:*request*"},
			Sinks:     rules.SinksOf("go:os/exec.Command", "go:*.CommandContext"),
			Propagators: []string{
				"go:strings.*", "go:fmt.Sprintf", "go:*.Join",
			},
		})
	}
	return rs
}

// BenchmarkEngine_RuleScaling measures Engine.Analyze as the rule pack grows.
// The dominant inner cost is glob matching per (call-site × pattern), which is
// what keeps competitive-scale rule packs affordable.
func BenchmarkEngine_RuleScaling(b *testing.B) {
	prog := buildScaleProgram(500)
	for _, n := range []int{1, 10, 50, 200} {
		rs := scaleRules(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				NewEngine(rs).Analyze(prog)
			}
		})
	}
}

// inertRules returns count rules that CANNOT produce a dataflow finding: they
// declare no sinks, the shape of a `kind: secret` or `kind: dangerous-call` rule
// as the taint engine sees it (both are evaluated by their own passes).
func inertRules(count int) *rules.RuleSet {
	rs := &rules.RuleSet{}
	for i := 0; i < count; i++ {
		rs.Rules = append(rs.Rules, rules.Rule{
			ID:       fmt.Sprintf("bench-inert-%d", i),
			Severity: rules.SeverityHigh,
			Kind:     "secret",
			Matches:  `\bAKIA[0-9A-Z]{16}\b`,
		})
	}
	return rs
}

// BenchmarkEngine_InertRules is a REGRESSION GUARD, not a target to optimise.
// A rule that cannot fire must cost no goroutine and no seeded worklist (see
// canProduceFinding in Analyze), so rule count must not matter here: all three
// sub-benchmarks should report essentially the same ns/op and allocs/op. If they
// start diverging, something has begun evaluating inert rules again.
func BenchmarkEngine_InertRules(b *testing.B) {
	prog := buildScaleProgram(120)
	for _, n := range []int{0, 14, 100} {
		rs := inertRules(n)
		if err := rs.Compile(); err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("inert=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				NewEngine(rs).Analyze(prog)
			}
		})
	}
}
