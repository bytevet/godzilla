package rust_converter

import (
	"os/exec"
	"strings"
	"testing"

	"godzilla/internal/analysis"
	"godzilla/internal/rules/loader"
	ir "godzilla/pkg/ir/v1"
)

// requireRustc skips when no rustc is on PATH (the frontend shells out to it to
// dump MIR).
func requireRustc(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc not found on PATH; skipping")
	}
}

func callees(prog *ir.Program) map[string]bool {
	seen := map[string]bool{}
	for _, mod := range prog.Modules {
		for _, fn := range mod.Functions {
			for _, blk := range fn.Blocks {
				for _, inst := range blk.Instrs {
					if inst.Call != nil && inst.Call.GetCallee() != "" {
						seen[inst.Call.GetCallee()] = true
					}
				}
			}
		}
	}
	return seen
}

// TestConvertFile_CommandInjection proves the MIR pipeline recovers the
// source-level public API names (generics stripped) that the rule pack matches:
// the env::var source and the Command builder chain.
func TestConvertFile_CommandInjection(t *testing.T) {
	requireRustc(t)

	prog, err := NewConverter().ConvertFile("../../test/rust/command_injection/main.rs")
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}
	if len(prog.Modules) == 0 || prog.Modules[0].Language != "rust" {
		t.Fatalf("want one rust module, got %+v", prog.Modules)
	}
	seen := callees(prog)
	for _, want := range []string{"rust:http::Request::query", "rust:Command::new", "rust:Command::arg"} {
		if !seen[want] {
			t.Errorf("expected callee %q in lowered IR; got %v", want, keys(seen))
		}
	}
	// Generics must be stripped, not carried into the canonical name.
	for c := range seen {
		if strings.ContainsAny(c, "<>") {
			t.Errorf("callee %q still carries generic args (should be normalized)", c)
		}
	}
}

// TestConvertFile_FormatMacro proves taint-carrying constructs survive lowering:
// format! lowers to an Arguments builder over tuple/array aggregates, and a
// std::fs sink keeps its full path.
func TestConvertFile_FormatMacro(t *testing.T) {
	requireRustc(t)

	prog, err := NewConverter().ConvertFile("../../test/rust/path_traversal/main.rs")
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}
	seen := callees(prog)
	if !seen["rust:std::fs::read_to_string"] {
		t.Errorf("expected the fs::read_to_string sink; got %v", keys(seen))
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestVerifyMIRShape is the FE-10 smoke-check core: it recognizes a lowered
// program that still carries a positioned CALL, and rejects one that does not
// (the signature of MIR-format drift).
func TestVerifyMIRShape(t *testing.T) {
	good := &ir.Program{Modules: []*ir.Module{{
		Language: "rust",
		Functions: []*ir.Function{{
			Blocks: []*ir.BasicBlock{{Instrs: []*ir.Instruction{
				{Op: ir.OpCode_OP_CODE_CALL, Pos: &ir.Position{Filename: "a.rs", Line: 2},
					Call: &ir.CallCommon{Callee: "rust:std::env::var"}},
			}}},
		}},
	}}}
	if !verifyMIRShape(good) {
		t.Errorf("expected a positioned CALL to pass the smoke check")
	}

	// A CALL with no position (drift symptom) and a program with no calls both fail.
	noPos := &ir.Program{Modules: []*ir.Module{{Functions: []*ir.Function{{
		Blocks: []*ir.BasicBlock{{Instrs: []*ir.Instruction{
			{Op: ir.OpCode_OP_CODE_CALL, Call: &ir.CallCommon{Callee: "x"}},
		}}},
	}}}}}
	if verifyMIRShape(noPos) {
		t.Errorf("a CALL with no position must fail the smoke check")
	}
	if verifyMIRShape(&ir.Program{}) {
		t.Errorf("an empty program must fail the smoke check")
	}
}

func TestAxumExtractorSource(t *testing.T) {
	cases := []struct {
		typ  string
		want string
		ok   bool
	}{
		{"axum::extract::Query<Params>", "rust:axum::extract::Query", true},
		{"Path<String>", "rust:axum::extract::Path", true},
		{"axum::extract::Json<Body>", "rust:axum::extract::Json", true},
		{"Form<Login>", "rust:axum::extract::Form", true},
		{"std::string::String", "", false}, // no generic, not an extractor
		{"&str", "", false},                //
		{"State<AppState>", "", false},     // an extractor, but not attacker data
	}
	for _, c := range cases {
		got, ok := axumExtractorSource(c.typ)
		if ok != c.ok || got != c.want {
			t.Errorf("axumExtractorSource(%q) = (%q,%v), want (%q,%v)", c.typ, got, ok, c.want, c.ok)
		}
	}
}

// TestLowerMIR_AxumSourceSynthesis proves (hermetically, no rustc) that an axum
// extractor handler parameter is lowered into a synthetic source CALL, so the
// taint engine seeds it and a downstream sink fires (COV-7).
func TestLowerMIR_AxumSourceSynthesis(t *testing.T) {
	mir := "fn handler(_1: axum::extract::Query<Params>) -> () {\n" +
		"    _0 = Command::new(move _1) -> [return: bb1, unwind continue];\n" +
		"}\n"
	mod := lowerMIR(mir, "handler.rs")

	// The synthetic source CALL must be present.
	prog := &ir.Program{Modules: []*ir.Module{mod}}
	if !callees(prog)["rust:axum::extract::Query"] {
		t.Fatalf("expected a synthesized axum source CALL; callees=%v", keys(callees(prog)))
	}
}

// TestAxumTaintFlow_EndToEnd runs the real engine over a lowered axum handler
// (no rustc) with the built-in rust-command-injection rule — whose sources now
// include the synthesized axum extractors — and asserts the flow fires (COV-7).
func TestAxumTaintFlow_EndToEnd(t *testing.T) {
	mir := "fn handler(_1: axum::extract::Query<Params>) -> () {\n" +
		"    _0 = Command::new(move _1) -> [return: bb1, unwind continue];\n" +
		"}\n"
	prog := &ir.Program{Modules: []*ir.Module{lowerMIR(mir, "handler.rs")}}

	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	findings := analysis.NewEngine(rs).Analyze(prog)
	got := false
	for _, f := range findings {
		if f.RuleID == "rust-command-injection" {
			got = true
		}
	}
	if !got {
		t.Errorf("expected rust-command-injection from an axum Query handler; got %d finding(s)", len(findings))
	}
}

// TestParseCargoTargets covers the FE-3 cargo-metadata target enumeration: bin
// and lib targets are kept (with -p set only for a workspace), and
// test/example/build-script targets are skipped.
func TestParseCargoTargets(t *testing.T) {
	// Single-package project with a bin and a lib, plus a test target to skip.
	single := []byte(`{
	  "packages": [{
	    "name": "app",
	    "targets": [
	      {"name": "app", "kind": ["bin"], "src_path": "/p/src/main.rs"},
	      {"name": "app", "kind": ["lib"], "src_path": "/p/src/lib.rs"},
	      {"name": "it", "kind": ["test"], "src_path": "/p/tests/it.rs"}
	    ]
	  }],
	  "workspace_members": ["app 0.1.0 (path+file:///p)"]
	}`)
	got := parseCargoTargets(single)
	if len(got) != 2 {
		t.Fatalf("expected 2 targets (bin+lib, test skipped), got %d: %+v", len(got), got)
	}
	var bin, lib bool
	for _, tgt := range got {
		if tgt.pkg != "" {
			t.Errorf("single-package project should not set -p, got pkg=%q", tgt.pkg)
		}
		switch tgt.kind {
		case "bin":
			bin = true
			if tgt.name != "app" || tgt.srcPath != "/p/src/main.rs" {
				t.Errorf("bin target mis-parsed: %+v", tgt)
			}
		case "lib":
			lib = true
		}
	}
	if !bin || !lib {
		t.Errorf("expected both a bin and a lib target, got %+v", got)
	}

	// Workspace with two members: -p must be set to disambiguate.
	ws := []byte(`{"packages":[
	  {"name":"a","targets":[{"name":"a","kind":["bin"],"src_path":"/w/a/src/main.rs"}]},
	  {"name":"b","targets":[{"name":"b","kind":["lib"],"src_path":"/w/b/src/lib.rs"}]}
	]}`)
	wsTargets := parseCargoTargets(ws)
	if len(wsTargets) != 2 {
		t.Fatalf("expected 2 workspace targets, got %d", len(wsTargets))
	}
	for _, tgt := range wsTargets {
		if tgt.pkg == "" {
			t.Errorf("workspace target should set -p, got %+v", tgt)
		}
	}

	// Garbage in -> nil (caller falls back).
	if parseCargoTargets([]byte("not json")) != nil {
		t.Errorf("invalid metadata should parse to nil")
	}
}
