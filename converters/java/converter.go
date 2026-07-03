// Package java_converter lowers Java to Godzilla's gIR by analyzing compiled JVM
// bytecode. It runs an embedded single-file Java helper (JavaDump.java) via the
// system `java` launcher — which compiles .java sources in-process (JDK compiler
// API) and reads .class files with the standard java.lang.classfile API — to get
// a JSON dump of every method's bytecode, then simulates the operand stack to
// recover SSA-style values that the language-neutral taint engine understands
// (see lower.go).
//
// Input may be a single .java/.class file or a directory (walked for both).
// Self-contained (JDK-only-API) sources compile standalone; sources needing a
// classpath are best scanned as compiled .class/.jar. A directory carrying a
// Maven (pom.xml) or Gradle (build.gradle[.kts]) build is compiled with its own
// build tool first — so third-party dependencies (e.g. a Spring app's
// spring-web / spring-jdbc) are on the classpath — and the resulting bytecode is
// analyzed (see resolveInputs). Requires a JDK 24+ `java` on PATH (for the
// java.lang.classfile API), mirroring how the Python frontend needs `python3`.
package java_converter

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	ir "godzilla/pkg/ir/v1"
)

//go:embed JavaDump.java
var javaDumpSource []byte

// Converter lowers Java source/bytecode into gIR.
type Converter struct{}

// NewConverter returns a Java frontend.
func NewConverter() *Converter { return &Converter{} }

// dumpDoc mirrors the JSON emitted by JavaDump.java.
type dumpDoc struct {
	Classes []dumpClass `json:"classes"`
}

type dumpClass struct {
	Name    string       `json:"name"`
	Methods []dumpMethod `json:"methods"`
}

type dumpMethod struct {
	Name       string      `json:"name"`
	Descriptor string      `json:"descriptor"`
	Static     bool        `json:"static"`
	Instrs     []dumpInstr `json:"instrs"`
	// ParamAnnotations holds each source-level parameter's runtime-visible
	// annotation internal names (index-aligned with the descriptor's params,
	// `this` excluded), e.g. [["org/springframework/web/bind/annotation/RequestParam"], []].
	ParamAnnotations [][]string `json:"paramAnnotations"`
}

type dumpInstr struct {
	Op    string `json:"op"`
	Kind  string `json:"kind"`
	Owner string `json:"owner"`
	Mname string `json:"mname"`
	Mdesc string `json:"mdesc"`
	Fname string `json:"fname"`
	Fdesc string `json:"fdesc"`
	Type  string `json:"type"`
	Cst   string `json:"cst"`
	Slot  int    `json:"slot"`
	Line  int    `json:"line"`
}

// ConvertFile lowers the Java at path (a file or directory) into a gIR program:
// one ir.Module per class, one ir.Function per method.
func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	javaExe, err := exec.LookPath("java")
	if err != nil {
		return nil, fmt.Errorf("java not found on PATH (JDK 24+ required for the Java frontend): %w", err)
	}

	scriptPath, cleanup, err := writeHelperScript()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	inputs := resolveInputs(abs)

	args := append([]string{scriptPath}, inputs...)
	cmd := exec.Command(javaExe, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("java dump failed for %s: %w", path, err)
	}

	var doc dumpDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parsing java dump for %s: %w", path, err)
	}

	filename := abs
	prog := &ir.Program{Mode: "bytecode"}
	for _, cl := range doc.Classes {
		prog.Modules = append(prog.Modules, convertClass(cl, filename))
	}
	return prog, nil
}

// writeHelperScript writes the embedded JavaDump.java to a temp file so `java`
// can run it as a single-file source program.
func writeHelperScript() (string, func(), error) {
	dir, err := os.MkdirTemp("", "godzilla-java")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "JavaDump.java")
	if err := os.WriteFile(path, javaDumpSource, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

// resolveInputs decides which paths to hand the JavaDump helper for the scan
// target. If the target is a directory holding a Maven (pom.xml) or Gradle
// (build.gradle[.kts]) build, it builds the project first — so third-party
// dependencies (e.g. a Spring app's spring-web / spring-jdbc) land on the
// compile classpath — and returns the compiled .class output directories, which
// the helper reads as bytecode. Otherwise the target is returned unchanged for
// the helper's in-process best-effort javac (JDK-only sources / loose .class).
//
// A missing build tool, or a build that fails, is non-fatal: it warns on stderr
// and falls back to the in-process source compile (which yields no classes for
// dependency-bearing code, but never aborts the scan).
func resolveInputs(abs string) []string {
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		return []string{abs}
	}
	sys, ok := detectBuildSystem(abs)
	if !ok {
		return []string{abs}
	}
	outputs, err := buildProject(abs, sys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "godzilla: java: %s build failed under %s: %v; falling back to in-process source compile\n", sys.name, abs, err)
		return []string{abs}
	}
	if len(outputs) == 0 {
		fmt.Fprintf(os.Stderr, "godzilla: java: %s build produced no classes under %s; falling back to in-process source compile\n", sys.name, abs)
		return []string{abs}
	}
	return outputs
}

// buildSystem identifies a JVM build tool and how to invoke it.
type buildSystem struct {
	name        string   // "maven" or "gradle" (for messages)
	wrapper     string   // committed wrapper script filename, preferred when present
	tool        string   // fallback executable looked up on PATH
	args        []string // compile-only invocation
	classSuffix string   // path tail of a compiled-main output directory
}

// detectBuildSystem reports the build tool rooted at dir, if any.
func detectBuildSystem(dir string) (buildSystem, bool) {
	if fileExists(filepath.Join(dir, "pom.xml")) {
		return buildSystem{
			name:        "maven",
			wrapper:     "mvnw",
			tool:        "mvn",
			args:        []string{"-q", "-B", "-DskipTests", "compile"},
			classSuffix: filepath.Join("target", "classes"),
		}, true
	}
	for _, f := range []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"} {
		if fileExists(filepath.Join(dir, f)) {
			return buildSystem{
				name:    "gradle",
				wrapper: "gradlew",
				tool:    "gradle",
				// `compileJava` builds only the root project's main source set;
				// unlike Maven's `compile` it does not aggregate a multi-module
				// reactor's subprojects. Sufficient for a single-project app (the
				// spring_boot sample); a multi-module Gradle target would need
				// per-subproject `:sub:compileJava` (or the `classes` lifecycle).
				args:        []string{"--console=plain", "-q", "compileJava"},
				classSuffix: filepath.Join("build", "classes", "java", "main"),
			}, true
		}
	}
	return buildSystem{}, false
}

// buildProject runs the build tool in dir (preferring a committed wrapper for a
// pinned toolchain) and returns the compiled-class output directories (one per
// module for a multi-module reactor).
func buildProject(dir string, sys buildSystem) ([]string, error) {
	var name string
	if wp := filepath.Join(dir, sys.wrapper); fileExists(wp) {
		name = wp
	} else if tool, err := exec.LookPath(sys.tool); err == nil {
		name = tool
	} else {
		return nil, fmt.Errorf("neither ./%s wrapper nor %s on PATH", sys.wrapper, sys.tool)
	}

	cmd := exec.Command(name, sys.args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s %v: %w\n%s", name, sys.args, err, tail(out, 2000))
	}
	return classOutputDirs(dir, sys.classSuffix), nil
}

// classOutputDirs finds every compiled-main output directory under root; a
// multi-module reactor has one per module.
func classOutputDirs(root, suffix string) []string {
	var dirs []string
	// WalkDir visits each directory exactly once, so no dedup is needed.
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		switch d.Name() {
		case ".git", ".gradle", "node_modules":
			return filepath.SkipDir
		}
		if strings.HasSuffix(p, suffix) {
			dirs = append(dirs, p)
		}
		return nil
	})
	return dirs
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// tail returns the last n bytes of b, for truncating build output in an error.
func tail(b []byte, n int) []byte {
	if len(b) > n {
		return b[len(b)-n:]
	}
	return b
}
