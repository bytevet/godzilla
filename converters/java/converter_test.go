package java_converter

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ir "godzilla/pkg/ir/v1"
)

// requireJava skips when no JDK `java` launcher is on PATH (the frontend runs
// the embedded JavaDump.java single-file program via it).
func requireJava(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("java not found on PATH; skipping")
	}
}

// eachInstr visits every lowered instruction in a program.
func eachInstr(prog *ir.Program, fn func(*ir.Instruction)) {
	for _, mod := range prog.Modules {
		for _, f := range mod.Functions {
			for _, b := range f.Blocks {
				for _, in := range b.Instrs {
					fn(in)
				}
			}
		}
	}
}

// eachCallee visits the callee of every CALL/INVOKE instruction.
func eachCallee(prog *ir.Program, fn func(callee string)) {
	eachInstr(prog, func(in *ir.Instruction) {
		if in.Call != nil {
			fn(in.Call.GetCallee())
		}
	})
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

	for _, mod := range prog.Modules {
		if mod.Language != "java" {
			t.Errorf("module %q language = %q, want java", mod.Name, mod.Language)
		}
	}
	var sawExec, sawSource bool
	eachCallee(prog, func(callee string) {
		switch callee {
		case "java:java/lang/Runtime.exec":
			sawExec = true
		case "java:javax/servlet/http/HttpServletRequest.getParameter":
			sawSource = true
		}
	})
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
	eachCallee(prog, func(callee string) {
		if _, ok := want[callee]; ok {
			want[callee] = true
		}
	})
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

// TestResolveJavaSource covers FE-8's SourceFile -> path resolution.
func TestResolveJavaSource(t *testing.T) {
	idx := map[string]string{"Login.java": "/proj/src/com/x/Login.java"}
	if got := resolveJavaSource("/proj", idx, "Login.java"); got != "/proj/src/com/x/Login.java" {
		t.Errorf("known source should resolve to its path, got %q", got)
	}
	// Unknown / empty source falls back to the scan path so a Pos is always set.
	if got := resolveJavaSource("/proj", idx, "Other.java"); got != "/proj" {
		t.Errorf("unknown source should fall back to scan path, got %q", got)
	}
	if got := resolveJavaSource("/proj", idx, ""); got != "/proj" {
		t.Errorf("empty source should fall back to scan path, got %q", got)
	}
}

// TestClassOutputDirs guards the build-output discovery: Maven's target/classes
// and Gradle's build/classes/java/main live under directories (target, build)
// that the source-scan ignore set skips. classOutputDirs must still descend into
// them — otherwise every project build is silently discarded as "no classes" and
// the frontend falls back to a depless source compile (losing framework sinks).
// A nested ignored tree (node_modules) must still be pruned.
func TestClassOutputDirs(t *testing.T) {
	mavenSuffix := filepath.Join("target", "classes")
	gradleSuffix := filepath.Join("build", "classes", "java", "main")
	root := t.TempDir()
	mkClass := func(parts ...string) string {
		dir := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "App.class"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	mavenDir := mkClass("target", "classes")
	// second reactor module, so a multi-module walk must return both
	moduleDir := mkClass("sub", "target", "classes")
	gradleDir := mkClass("build", "classes", "java", "main")
	// a vendored dependency's own build output must NOT be reported
	mkClass("node_modules", "pkg", "target", "classes")

	contains := func(dirs []string, want string) bool {
		for _, d := range dirs {
			if d == want {
				return true
			}
		}
		return false
	}

	maven := classOutputDirs(root, mavenSuffix)
	if !contains(maven, mavenDir) || !contains(maven, moduleDir) {
		t.Errorf("maven: want both %q and %q, got %v", mavenDir, moduleDir, maven)
	}
	for _, d := range maven {
		if filepath.Base(filepath.Dir(filepath.Dir(d))) == "node_modules" ||
			containsSegment(d, "node_modules") {
			t.Errorf("maven: vendored node_modules output must be pruned, got %q", d)
		}
	}
	if gradle := classOutputDirs(root, gradleSuffix); !contains(gradle, gradleDir) {
		t.Errorf("gradle: want %q, got %v", gradleDir, gradle)
	}
}

func containsSegment(p, seg string) bool {
	for _, s := range strings.Split(p, string(filepath.Separator)) {
		if s == seg {
			return true
		}
	}
	return false
}

// TestJavaSourceFilePositions is the FE-8 end-to-end guard: a two-file Java
// project's findings/positions must anchor to each class's OWN .java file, not
// the scan directory.
func TestJavaSourceFilePositions(t *testing.T) {
	requireJava(t)
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("Alpha.java", "public class Alpha {\n  public String greet() { return \"a\"; }\n}\n")
	write("Beta.java", "public class Beta {\n  public String hello() { return \"b\"; }\n}\n")

	prog, err := NewConverter().ConvertFile(dir)
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}
	seen := map[string]bool{}
	eachInstr(prog, func(in *ir.Instruction) {
		if in.Pos == nil || in.Pos.GetFilename() == "" {
			return
		}
		base := filepath.Base(in.Pos.GetFilename())
		seen[base] = true
		if base == filepath.Base(dir) {
			t.Errorf("position anchored to the scan directory, not a source file: %s", in.Pos.GetFilename())
		}
	})
	if !seen["Alpha.java"] || !seen["Beta.java"] {
		t.Errorf("expected positions in both Alpha.java and Beta.java, saw %v", seen)
	}
}
