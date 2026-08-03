package go_converter

import (
	"os"
	"path/filepath"
	"testing"

	ir "godzilla/pkg/ir/v1"
)

// TestFormatMarkerExactCalleeMatch is the regression guard for the
// builtin.format tagging in convertInstructionInto: the marker must be keyed by
// the EXACT canonical FQNs in goFormatCallees, never a callee-name shape. The
// old heuristic (strings.Contains(callee, "Sprintf")) let a user function
// merely named like a formatter (MySprintf) claim "Args[0] is the template"
// semantics, wrongly prove a fixed host via hostFixed(), and suppress a real
// SSRF finding.
//
// (a) go:fmt.Sprintf / go:fmt.Sprint keep the builtin.format marker;
// (b) the user MySprintf — and fmt.Println, a fmt call outside the
// string-returning trio — carry NO marker.
func TestFormatMarkerExactCalleeMatch(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(rel, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", "module tmpmod\n\ngo 1.21\n")
	writeFile("main.go", `package main

import "fmt"

// MySprintf is named to trip the old name-shape heuristic; it must NOT be
// tagged builtin.format.
func MySprintf(format string, args ...any) string { return format }

func main() {
	a := fmt.Sprintf("https://host.example/%s", "x")
	b := fmt.Sprint("https://host.example/", "y")
	c := MySprintf("https://host.example/%s", "z")
	fmt.Println(a, b, c)
}
`)

	prog, err := NewConverter().ConvertFile(dir)
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}

	// callee -> set of intrinsic markers seen on its CALL instructions.
	marks := map[string]map[string]bool{}
	for _, mod := range prog.Modules {
		for _, f := range mod.Functions {
			for _, b := range f.Blocks {
				for _, inst := range b.Instrs {
					if inst.Op != ir.OpCode_OP_CODE_CALL && inst.Op != ir.OpCode_OP_CODE_INVOKE {
						continue
					}
					callee := inst.Call.GetCallee()
					if callee == "" {
						continue
					}
					if marks[callee] == nil {
						marks[callee] = map[string]bool{}
					}
					marks[callee][inst.Intrinsic] = true
				}
			}
		}
	}

	requireMark := func(callee, want string) {
		t.Helper()
		got, ok := marks[callee]
		if !ok {
			t.Errorf("no CALL to %q found in the lowered IR", callee)
			return
		}
		if len(got) != 1 || !got[want] {
			t.Errorf("calls to %q carry intrinsics %v, want exactly %q", callee, got, want)
		}
	}

	requireMark("go:fmt.Sprintf", "builtin.format")
	requireMark("go:fmt.Sprint", "builtin.format")
	requireMark("go:tmpmod.MySprintf", "") // user fn named like a formatter: no marker
	requireMark("go:fmt.Println", "")      // fmt, but not in the string-returning trio
}
