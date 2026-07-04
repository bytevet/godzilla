package analysis

import (
	"sort"
	"testing"

	go_converter "godzilla/converters/go"
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// convertSQLInjectionSample loads and converts the sql_injection sample used
// by the converter's own tests into a gIR Program.
func convertSQLInjectionSample(t *testing.T) *ir.Program {
	t.Helper()
	conv := go_converter.NewConverter()
	prog, err := conv.ConvertFile("../../test/go/sql_injection/main.go")
	if err != nil {
		t.Fatalf("failed to convert sql_injection sample: %v", err)
	}
	if prog == nil {
		t.Fatal("converted program is nil")
	}
	return prog
}

// distinctCallees walks prog and returns every distinct non-empty
// inst.Call.Callee found, sorted for stable output.
func distinctCallees(prog *ir.Program) []string {
	seen := map[string]bool{}
	for _, mod := range prog.Modules {
		for _, fn := range mod.Functions {
			for _, blk := range fn.Blocks {
				for _, inst := range blk.Instrs {
					if inst.Call == nil {
						continue
					}
					if callee := inst.Call.GetCallee(); callee != "" {
						seen[callee] = true
					}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// sqlInjectionRuleSet is the RuleSet under test: a single Go SQL-injection
// rule. The glob patterns are derived from the *real* canonical callee names
// a Go SQL-injection handler produces: (net/url.Values).Get as the source,
// fmt.Sprintf as the propagator, (*database/sql.DB).Query* as the sink. See
// TestLogSQLInjectionCallees for how these were confirmed against the Go
// converter's actual naming scheme ("go:" + ssa.Function.String() /
// ssa.CallCommon.Method.FullName()).
func sqlInjectionRuleSet() *rules.RuleSet {
	return &rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID:          "GO-SQLI-001",
				Languages:   []string{"go"},
				Severity:    rules.SeverityHigh,
				CWE:         "CWE-89",
				Message:     "Untrusted HTTP query parameter flows into a SQL query without sanitization",
				Sources:     []string{"go:*Values*.Get"},
				Sinks:       []string{"go:*database/sql*.Query*"},
				Propagators: []string{"go:fmt.Sprintf"},
			},
		},
	}
}

// TestLogSQLInjectionCallees is a diagnostic test: it converts the real
// sql_injection sample and logs every distinct Call.Callee the Go converter
// actually produces today.
//
// This documents the real canonical-name scheme used to build the globs in
// sqlInjectionRuleSet. (Historical note: the converter originally walked only
// pkg.Members and dropped the anonymous http.HandleFunc closure where the
// vulnerability lives; converters/go now enumerates all functions via
// ssautil.AllFunctions, so that closure -- "godzilla/test/go/sql_injection.main$1"
// -- is lowered and the flow is detectable end-to-end.)
func TestLogSQLInjectionCallees(t *testing.T) {
	prog := convertSQLInjectionSample(t)
	callees := distinctCallees(prog)
	for _, c := range callees {
		t.Logf("callee: %s", c)
	}
	if len(callees) == 0 {
		t.Fatal("expected at least one Call.Callee in the converted program")
	}
}

// TestAnalyze_SQLInjection_RealConversion runs the engine against the *actual*
// output of go_converter for the sql_injection sample. The converter now lowers
// the vulnerable http.HandleFunc closure (SSA name main$1), so the full
// source -> propagator -> sink flow is present in the IR and must be detected
// end-to-end.
func TestAnalyze_SQLInjection_RealConversion(t *testing.T) {
	prog := convertSQLInjectionSample(t)
	engine := NewEngine(sqlInjectionRuleSet())
	findings := engine.Analyze(prog)

	var sqli *Finding
	for i := range findings {
		if findings[i].RuleID == "GO-SQLI-001" {
			sqli = &findings[i]
			break
		}
	}
	if sqli == nil {
		t.Fatalf("expected a GO-SQLI-001 finding from the real conversion, got %d finding(s): %v", len(findings), findings)
	}
	if sqli.SourcePos == nil || sqli.SinkPos == nil {
		t.Errorf("finding missing source/sink positions: %+v", *sqli)
	}
}

// TestAnalyze_SQLInjection_HandlerClosure exercises the taint engine against
// gIR modeling the http.HandleFunc closure from
// test/go/sql_injection/main.go:
//
//	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
//	    id := r.URL.Query().Get("id")
//	    query := fmt.Sprintf("SELECT name FROM users WHERE id = '%s'", id)
//	    rows, err := db.Query(query)
//	    ...
//	})
//
// It stands in for that closure once the converter is able to emit it (see
// TestLogSQLInjectionCallees) using the exact real canonical callee names.
// The shape mirrors the real SSA one-for-one for the relevant instructions:
// a call to (net/url.Values).Get (source) is fed as an argument to
// fmt.Sprintf (propagator), whose result is fed to (*database/sql.DB).Query
// (sink) -- the canonical SQL injection pattern in the sample.
func TestAnalyze_SQLInjection_HandlerClosure(t *testing.T) {
	const file = "../../test/go/sql_injection/main.go"
	pos := func(line, col int32) *ir.Position {
		return &ir.Position{Filename: file, Line: line, Column: col}
	}
	reg := func(name string) *ir.Value { return &ir.Value{Kind: &ir.Value_RegName{RegName: name}} }
	str := func(s string) *ir.Value {
		return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: s}}}}
	}

	const closureName = "go:godzilla/test/go/sql_injection.main$1"
	fn := &ir.Function{
		Name:          "godzilla/test/go/sql_injection.main$1",
		ObjectName:    "main$1",
		CanonicalName: closureName,
		Blocks: []*ir.BasicBlock{
			{
				Index: 0,
				Instrs: []*ir.Instruction{
					// id := r.URL.Query().Get("id")   -- SOURCE
					{
						Name: "t3",
						Op:   ir.OpCode_OP_CODE_CALL,
						Pos:  pos(14, 14),
						Call: &ir.CallCommon{
							Callee: "go:(net/url.Values).Get",
							Args:   []*ir.Value{str("id")},
						},
					},
					// query := fmt.Sprintf("SELECT name FROM users WHERE id = '%s'", id) -- PROPAGATOR
					{
						Name: "t7",
						Op:   ir.OpCode_OP_CODE_CALL,
						Pos:  pos(16, 11),
						Call: &ir.CallCommon{
							Callee: "go:fmt.Sprintf",
							Args:   []*ir.Value{str("SELECT name FROM users WHERE id = '%s'"), reg("t3")},
						},
					},
					// rows, err := db.Query(query) -- SINK
					{
						Name: "t9",
						Op:   ir.OpCode_OP_CODE_CALL,
						Pos:  pos(17, 20),
						Call: &ir.CallCommon{
							Callee: "go:(*database/sql.DB).Query",
							Args:   []*ir.Value{reg("t7")},
						},
					},
				},
			},
		},
	}

	prog := &ir.Program{
		Mode: "ssa",
		Modules: []*ir.Module{
			{
				Name:      "godzilla/test/go/sql_injection",
				Language:  "go",
				Functions: []*ir.Function{fn},
			},
		},
	}

	engine := NewEngine(sqlInjectionRuleSet())
	findings := engine.Analyze(prog)

	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got none")
	}

	found := false
	for _, f := range findings {
		t.Logf("finding: %s", f.String())
		if f.RuleID != "GO-SQLI-001" {
			continue
		}
		found = true
		if f.SourcePos == nil {
			t.Errorf("finding has nil SourcePos: %+v", f)
		}
		if f.SinkPos == nil {
			t.Errorf("finding has nil SinkPos: %+v", f)
		}
		if f.Function != closureName {
			t.Errorf("finding.Function = %q, want %q", f.Function, closureName)
		}
		if f.SinkCallee != "go:(*database/sql.DB).Query" {
			t.Errorf("finding.SinkCallee = %q, want %q", f.SinkCallee, "go:(*database/sql.DB).Query")
		}
	}
	if !found {
		t.Errorf("expected a finding with RuleID %q, got %+v", "GO-SQLI-001", findings)
	}
}

// TestAnalyze_Sanitizer verifies that a value passed through a sanitizer is
// no longer considered tainted, so a subsequent sink call is not flagged.
func TestAnalyze_Sanitizer(t *testing.T) {
	reg := func(name string) *ir.Value { return &ir.Value{Kind: &ir.Value_RegName{RegName: name}} }

	fn := &ir.Function{
		CanonicalName: "go:example.handler",
		Blocks: []*ir.BasicBlock{{Instrs: []*ir.Instruction{
			{Name: "t0", Op: ir.OpCode_OP_CODE_CALL, Pos: &ir.Position{Line: 1},
				Call: &ir.CallCommon{Callee: "go:source.Get"}},
			{Name: "t1", Op: ir.OpCode_OP_CODE_CALL, Pos: &ir.Position{Line: 2},
				Call: &ir.CallCommon{Callee: "go:sanitize.Escape", Args: []*ir.Value{reg("t0")}}},
			{Name: "t2", Op: ir.OpCode_OP_CODE_CALL, Pos: &ir.Position{Line: 3},
				Call: &ir.CallCommon{Callee: "go:sink.Exec", Args: []*ir.Value{reg("t1")}}},
		}}},
	}
	prog := &ir.Program{Modules: []*ir.Module{{Language: "go", Functions: []*ir.Function{fn}}}}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID: "SANI-1", Severity: rules.SeverityHigh,
		Sources: []string{"go:source.Get"}, Sinks: []string{"go:sink.Exec"},
		Sanitizers: []string{"go:sanitize.Escape"},
	}}}

	findings := NewEngine(rs).Analyze(prog)
	if len(findings) != 0 {
		t.Fatalf("expected no findings (value was sanitized), got %+v", findings)
	}
}

// TestAnalyze_PhiFixpoint verifies that taint reaching a PHI node's operand
// via a back-edge (loop) is picked up by fixpoint iteration, even when the
// PHI textually precedes the instruction that taints one of its operands. The
// CFG is a real loop — header (block 0, the phi) <-> body (block 2, the source
// and sink) — with the predecessor/successor edges a frontend always emits;
// the flow-sensitive dataflow needs them to carry the body's taint back to the
// header phi across a second pass.
func TestAnalyze_PhiFixpoint(t *testing.T) {
	reg := func(name string) *ir.Value { return &ir.Value{Kind: &ir.Value_RegName{RegName: name}} }

	fn := &ir.Function{
		CanonicalName: "go:example.loop",
		Blocks: []*ir.BasicBlock{
			{Index: 0, Succs: []int32{2}, Preds: []int32{2}, Instrs: []*ir.Instruction{
				// loop header: t2 = phi [b1: t0, b2: t3]
				{Name: "t2", Op: ir.OpCode_OP_CODE_PHI,
					Operands: []*ir.Value{reg("t0"), reg("t3")},
					Blocks:   []string{"b1", "b2"}},
			}},
			{Index: 2, Succs: []int32{0}, Preds: []int32{0}, Instrs: []*ir.Instruction{
				// t0 = source.Get() -- defined "later" in block order than the phi
				// that consumes it via a back-edge, forcing a second fixpoint pass.
				{Name: "t0", Op: ir.OpCode_OP_CODE_CALL, Pos: &ir.Position{Line: 1},
					Call: &ir.CallCommon{Callee: "go:source.Get"}},
				{Name: "t9", Op: ir.OpCode_OP_CODE_CALL, Pos: &ir.Position{Line: 2},
					Call: &ir.CallCommon{Callee: "go:sink.Exec", Args: []*ir.Value{reg("t2")}}},
			}},
		},
	}
	prog := &ir.Program{Modules: []*ir.Module{{Language: "go", Functions: []*ir.Function{fn}}}}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID: "PHI-1", Severity: rules.SeverityMedium,
		Sources: []string{"go:source.Get"}, Sinks: []string{"go:sink.Exec"},
	}}}

	findings := NewEngine(rs).Analyze(prog)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding via fixpoint propagation, got %+v", findings)
	}
	if findings[0].SourcePos == nil || findings[0].SourcePos.Line != 1 {
		t.Errorf("expected SourcePos.Line == 1, got %+v", findings[0].SourcePos)
	}
}

// TestAnalyze_DedupeAndRuleIsolation verifies that (a) a sink reached
// through multiple tainted paths across fixpoint iterations is reported
// only once, and (b) taint state does not leak across rules.
func TestAnalyze_DedupeAndRuleIsolation(t *testing.T) {
	reg := func(name string) *ir.Value { return &ir.Value{Kind: &ir.Value_RegName{RegName: name}} }

	fn := &ir.Function{
		CanonicalName: "go:example.dedupe",
		Blocks: []*ir.BasicBlock{{Instrs: []*ir.Instruction{
			{Name: "t0", Op: ir.OpCode_OP_CODE_CALL, Pos: &ir.Position{Line: 1},
				Call: &ir.CallCommon{Callee: "go:source.Get"}},
			{Name: "t1", Op: ir.OpCode_OP_CODE_CALL, Pos: &ir.Position{Line: 2},
				Call: &ir.CallCommon{Callee: "go:source.Get"}},
			// sink takes two tainted args from the same rule; must only report once.
			{Name: "t2", Op: ir.OpCode_OP_CODE_CALL, Pos: &ir.Position{Line: 3},
				Call: &ir.CallCommon{Callee: "go:sink.Exec", Args: []*ir.Value{reg("t0"), reg("t1")}}},
		}}},
	}
	prog := &ir.Program{Modules: []*ir.Module{{Language: "go", Functions: []*ir.Function{fn}}}}

	rs := &rules.RuleSet{Rules: []rules.Rule{
		{ID: "R1", Severity: rules.SeverityLow, Sources: []string{"go:source.Get"}, Sinks: []string{"go:sink.Exec"}},
		{ID: "R2-nomatch", Severity: rules.SeverityLow, Sources: []string{"go:other.Source"}, Sinks: []string{"go:sink.Exec"}},
	}}

	findings := NewEngine(rs).Analyze(prog)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one deduped finding for R1 and none for R2-nomatch, got %+v", findings)
	}
	if findings[0].RuleID != "R1" {
		t.Errorf("expected finding from R1, got %q", findings[0].RuleID)
	}
}
