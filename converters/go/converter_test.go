package go_converter

import (
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
