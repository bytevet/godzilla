package java_converter

import (
	"testing"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// TestBranchMerge_TernaryKeepsTaint is a hermetic guard (no JDK) for FE-4. It
// hand-builds the bytecode of `host = (name == null) ? "localhost" : name`
// feeding a sink, where `name` comes from a source. The tainted arm and the
// constant arm reach a control-flow join (label 2) before the STORE; the
// block-structured operand-stack simulation must PHI-merge them so the sink sees
// the tainted value. The old linear walk kept only the textually-last push (the
// constant) and dropped the finding.
func TestBranchMerge_TernaryKeepsTaint(t *testing.T) {
	instrs := []dumpInstr{
		{Op: "INVOKE", Kind: "INVOKESTATIC", Owner: "X", Mname: "source", Mdesc: "()Ljava/lang/String;", Line: 1},
		{Op: "STORE", Slot: 0, Line: 1},
		{Op: "LOAD", Slot: 0, Line: 2},
		{Op: "BRANCH", Kind: "IFNULL", Target: 1, Line: 2}, // name==null -> L1
		{Op: "LOAD", Slot: 0, Line: 2},                     // else: push tainted name
		{Op: "BRANCH", Kind: "GOTO", Target: 2, Line: 2},   // -> L2
		{Op: "LABEL", ID: 1, Line: 2},                      // L1
		{Op: "CONST", Cst: "localhost", Line: 2},           // push constant
		{Op: "LABEL", ID: 2, Line: 2},                      // L2 (join): PHI(name, const)
		{Op: "STORE", Slot: 1, Line: 2},                    // host = phi
		{Op: "LOAD", Slot: 1, Line: 3},
		{Op: "INVOKE", Kind: "INVOKESTATIC", Owner: "X", Mname: "sink", Mdesc: "(Ljava/lang/String;)V", Line: 3},
		{Op: "RETURN", Kind: "RETURN", Line: 3},
	}
	fn := convertMethod("X", dumpMethod{Name: "handle", Descriptor: "()V", Static: true, Instrs: instrs}, "X.java")
	mod := &ir.Module{Name: "X", Language: "java", Functions: []*ir.Function{fn}}
	prog := &ir.Program{Modules: []*ir.Module{mod}}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "java-ternary-test",
		Languages: []string{"java"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "tainted value survives a ternary join",
		Sources:   []string{"java:X.source"},
		Sinks:     []string{"java:X.sink"},
	}}}

	findings := analysis.NewEngine(rs).Analyze(prog)
	got := false
	for _, f := range findings {
		if f.RuleID == "java-ternary-test" {
			got = true
		}
	}
	if !got {
		t.Fatalf("expected taint to survive the ternary operand-stack join into the sink; got %d finding(s): %v", len(findings), findings)
	}
}

// TestSplitBlocks_TernaryCFG checks the CFG reconstruction directly: the ternary
// above must split into four blocks wired A->{B,C}, B->D, C->D, so the join D
// has two predecessors (which is what triggers the PHI merge).
func TestSplitBlocks_TernaryCFG(t *testing.T) {
	instrs := []dumpInstr{
		{Op: "LOAD", Slot: 0},                     // 0  A
		{Op: "BRANCH", Kind: "IFNULL", Target: 1}, // 1  A end
		{Op: "LOAD", Slot: 0},                     // 2  B
		{Op: "BRANCH", Kind: "GOTO", Target: 2},   // 3  B end
		{Op: "LABEL", ID: 1},                      // 4  C
		{Op: "CONST", Cst: "x"},                   // 5  C
		{Op: "LABEL", ID: 2},                      // 6  D
		{Op: "STORE", Slot: 1},                    // 7  D
	}
	blocks, labelIdx := splitBlocks(instrs)
	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks, got %d", len(blocks))
	}
	blockAt := map[int]int{}
	for bi, b := range blocks {
		blockAt[b.start] = bi
	}
	preds := make([][]int, len(blocks))
	for bi, b := range blocks {
		for _, sc := range blockSuccs(b, blockAt, labelIdx) {
			preds[sc] = append(preds[sc], bi)
		}
	}
	// The join block is the one starting at the LABEL id 2 (instr index 6).
	joinIdx := blockAt[labelIdx[2]]
	if len(preds[joinIdx]) != 2 {
		t.Errorf("expected the ternary join to have 2 predecessors, got %d (%v)", len(preds[joinIdx]), preds[joinIdx])
	}
}
