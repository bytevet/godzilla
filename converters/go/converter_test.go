package go_converter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	ir "godzilla/pkg/ir/v1"
)

func TestConvertFile(t *testing.T) {
	conv := NewConverter()
	prog, err := conv.ConvertFile("../../test/go/sql_injection/main.go")
	if err != nil {
		t.Fatalf("failed to convert file: %v", err)
	}

	if prog == nil {
		t.Fatal("program is nil")
	}

	foundMain := false
	for _, mod := range prog.Modules {
		for _, f := range mod.Functions {
			t.Logf("Found function: %s (pkg: %s, obj: %s)", f.Name, f.PackageName, f.ObjectName)
			if f.ObjectName == "main" {
				foundMain = true
			}
		}
	}

	if !foundMain {
		t.Error("could not find main function in converted IR")
	}
}

func TestConvertComplexFile(t *testing.T) {
	conv := NewConverter()
	prog, err := conv.ConvertFile("../../test/go/complex_logic/main.go")
	if err != nil {
		t.Fatalf("failed to convert file: %v", err)
	}

	if prog == nil {
		t.Fatal("program is nil")
	}

	// Verify no "unsupported instruction" comments
	for _, mod := range prog.Modules {
		for _, f := range mod.Functions {
			for _, b := range f.Blocks {
				for _, inst := range b.Instrs {
					if inst.Comment != "" && (len(inst.Comment) > 23 && inst.Comment[:23] == "unsupported instruction") {
						t.Errorf("unsupported instruction in function %s: %s", f.Name, inst.Comment)
					}
				}
			}
		}
	}
}

func TestGIRv2Metadata(t *testing.T) {
	conv := NewConverter()
	prog, err := conv.ConvertFile("../../test/go/sql_injection/main.go")
	if err != nil {
		t.Fatalf("failed to convert file: %v", err)
	}

	if prog == nil {
		t.Fatal("program is nil")
	}

	foundGoLanguage := false
	foundCallee := false

	for _, mod := range prog.Modules {
		if mod.Language == "go" {
			foundGoLanguage = true
		}

		for _, f := range mod.Functions {
			if !f.Synthetic {
				if f.CanonicalName == "" {
					t.Errorf("function %s has empty CanonicalName", f.Name)
				} else if !strings.HasPrefix(f.CanonicalName, "go:") {
					t.Errorf("function %s has CanonicalName %q, want prefix \"go:\"", f.Name, f.CanonicalName)
				}
			}

			for _, b := range f.Blocks {
				for _, inst := range b.Instrs {
					if (inst.Op == ir.OpCode_OP_CODE_CALL || inst.Op == ir.OpCode_OP_CODE_INVOKE) &&
						inst.Call != nil && inst.Call.Callee != "" {
						foundCallee = true
					}

					if inst.Op == ir.OpCode_OP_CODE_UNSPECIFIED && inst.Comment == "" {
						t.Errorf("instruction in function %s has OP_CODE_UNSPECIFIED with no comment", f.Name)
					}
				}
			}
		}
	}

	if !foundGoLanguage {
		t.Error("expected at least one module with Language == \"go\"")
	}
	if !foundCallee {
		t.Error("expected at least one CALL/INVOKE instruction with a non-empty Call.Callee")
	}
}

// TestConvertFile_ResilientToBrokenPackage locks in graceful degradation: when
// a directory contains one package that fails to parse/typecheck, ConvertFile
// must NOT abort — it skips the broken package (SSA can't be built for it) and
// still converts the packages that are fine. This mirrors the per-file
// resilience of the Python/JS frontends, adapted to Go's package-level model,
// and matters for scanning real repos that may hold a generated or partial
// file. The broken package can't live under test/go/* (it would break the
// sample-module build test), so the fixture is built in a temp module.
func TestConvertFile_ResilientToBrokenPackage(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", "module tmpmod\n\ngo 1.21\n")
	writeFile("good/good.go", "package good\n\nimport \"os/exec\"\n\nfunc Run(cmd string) { exec.Command(\"sh\", \"-c\", cmd).Run() }\n")
	writeFile("bad/bad.go", "package bad\nfunc Broken( {\n") // syntax error

	prog, err := NewConverter().ConvertFile(dir)
	if err != nil {
		t.Fatalf("ConvertFile must tolerate a broken sibling package, got error: %v", err)
	}
	if prog == nil {
		t.Fatal("ConvertFile returned a nil program")
	}

	var foundGood bool
	for _, mod := range prog.Modules {
		for _, fn := range mod.Functions {
			if fn.GetObjectName() == "Run" {
				foundGood = true
			}
		}
	}
	if !foundGood {
		t.Error("the valid package's function Run did not convert; a broken sibling aborted the good package")
	}
}
