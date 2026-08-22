package analysis

import (
	"testing"

	"github.com/bytevet/godzilla/internal/rules"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

func matchProg() *ir.Program {
	call := func(callee string) *ir.Instruction {
		return &ir.Instruction{
			Op:   ir.OpCode_OP_CODE_CALL,
			Call: &ir.CallCommon{Callee: callee},
		}
	}
	return &ir.Program{Modules: []*ir.Module{{
		Name: "m", Language: "go",
		Functions: []*ir.Function{{
			CanonicalName: "go:m.f",
			Blocks: []*ir.BasicBlock{{Instrs: []*ir.Instruction{
				call("go:src.Get"), call("go:src.Get"), // two SITES, one callee
				call("go:db.Query"),
				call("go:fmt.Println"), // matches nothing
			}}},
		}},
	}}}
}

// TestStatsCountsCallSites: the workload figures report call SITES, not callee
// names, so a source called twice counts twice.
func TestStatsCountsCallSites(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:      "R",
		Sources: []string{"go:src.*"},
		Sinks:   []rules.Sink{{Pattern: "go:db.Query"}},
	}}}
	_, stats := NewEngine(rs).AnalyzeWithStats(matchProg())
	if stats.SourceSites != 2 || stats.SinkSites != 1 {
		t.Errorf("SourceSites=%d SinkSites=%d, want 2/1", stats.SourceSites, stats.SinkSites)
	}
}

// TestAnalyzeWithStatsMatchesAnalyze: Analyze is a wrapper, so the two must
// never disagree on findings — the stats are the only difference.
func TestAnalyzeWithStatsMatchesAnalyze(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:      "R",
		Sources: []string{"go:src.*"},
		Sinks:   []rules.Sink{{Pattern: "go:db.Query"}},
	}}}
	prog := matchProg()
	plain := NewEngine(rs).Analyze(prog)
	withStats, stats := NewEngine(rs).AnalyzeWithStats(prog)
	if len(plain) != len(withStats) {
		t.Errorf("Analyze returned %d findings, AnalyzeWithStats %d", len(plain), len(withStats))
	}
	if stats.Functions != 1 {
		t.Errorf("Functions = %d, want 1 call-graph node", stats.Functions)
	}
	if stats.Rules != 1 || stats.RulesLive != 1 {
		t.Errorf("Rules=%d RulesLive=%d, want 1/1", stats.Rules, stats.RulesLive)
	}
	if stats.Index <= 0 || stats.Taint <= 0 {
		t.Errorf("Index=%v Taint=%v, both phases must be timed", stats.Index, stats.Taint)
	}
	if _, empty := (&Engine{}).AnalyzeWithStats(nil); empty != (Stats{}) {
		t.Errorf("AnalyzeWithStats(nil) = %+v, want zero stats", empty)
	}
}
