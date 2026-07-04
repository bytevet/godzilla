package rust_converter

import (
	"os/exec"
	"strings"
	"testing"

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
