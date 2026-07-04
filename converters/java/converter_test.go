package java_converter

import (
	"os/exec"
	"testing"
)

// requireJava skips when no JDK `java` launcher is on PATH (the frontend runs
// the embedded JavaDump.java single-file program via it).
func requireJava(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("java not found on PATH; skipping")
	}
}

// TestConvertFile_CommandInjectionSample proves the bytecode pipeline recovers a
// call graph: the command-injection sample lowers to a function whose body
// contains the Runtime.exec sink call, keyed by its java: canonical name.
func TestConvertFile_CommandInjectionSample(t *testing.T) {
	requireJava(t)

	prog, err := NewConverter().ConvertFile("../../test/java/command_injection")
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}
	if len(prog.Modules) == 0 {
		t.Fatal("no modules produced")
	}

	var sawExec, sawSource bool
	for _, mod := range prog.Modules {
		if mod.Language != "java" {
			t.Errorf("module %q language = %q, want java", mod.Name, mod.Language)
		}
		for _, fn := range mod.Functions {
			for _, blk := range fn.Blocks {
				for _, inst := range blk.Instrs {
					if inst.Call == nil {
						continue
					}
					switch inst.Call.GetCallee() {
					case "java:java/lang/Runtime.exec":
						sawExec = true
					case "java:javax/servlet/http/HttpServletRequest.getParameter":
						sawSource = true
					}
				}
			}
		}
	}
	if !sawSource {
		t.Error("expected a java:javax/servlet/http/HttpServletRequest.getParameter source call in the lowered IR")
	}
	if !sawExec {
		t.Error("expected a java:java/lang/Runtime.exec sink call in the lowered IR")
	}
}

// TestConvertFile_SpringParamAnnotationSource proves the frontend synthesizes a
// source CALL for a parameter carrying a Spring binding annotation
// (@RequestParam / @PathVariable), so annotated controller parameters seed taint
// even though the engine only introduces taint at a CALL matching a source glob.
// The sample stubs the annotations, so it compiles with the JDK alone.
func TestConvertFile_SpringParamAnnotationSource(t *testing.T) {
	requireJava(t)

	prog, err := NewConverter().ConvertFile("../../test/java/spring_annotation")
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}

	want := map[string]bool{
		"java:org/springframework/web/bind/annotation/RequestParam": false,
		"java:org/springframework/web/bind/annotation/PathVariable": false,
	}
	for _, mod := range prog.Modules {
		for _, fn := range mod.Functions {
			for _, blk := range fn.Blocks {
				for _, inst := range blk.Instrs {
					if inst.Call == nil {
						continue
					}
					if _, ok := want[inst.Call.GetCallee()]; ok {
						want[inst.Call.GetCallee()] = true
					}
				}
			}
		}
	}
	for callee, saw := range want {
		if !saw {
			t.Errorf("expected a synthesized parameter-source call %q in the lowered IR", callee)
		}
	}
}

// TestParseJavaMajor covers the `java -version` parser used by the FE-9 version
// guard, including the legacy "1.8" scheme and unparseable input.
func TestParseJavaMajor(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want int
		ok   bool
	}{
		{"jdk24", `openjdk version "24.0.1" 2025-04-15`, 24, true},
		{"jdk21", `openjdk version "21.0.3" 2024-04-16`, 21, true},
		{"legacy 1.8", `java version "1.8.0_401"`, 8, true},
		{"early access", `openjdk version "25-ea" 2025-09-16`, 25, true},
		{"no version", "some unrelated output", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseJavaMajor(c.out)
			if ok != c.ok || (ok && got != c.want) {
				t.Errorf("parseJavaMajor(%q) = (%d,%v), want (%d,%v)", c.out, got, ok, c.want, c.ok)
			}
		})
	}
}
