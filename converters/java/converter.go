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
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"godzilla/internal/buildpolicy"
	"godzilla/internal/proc"
	"godzilla/internal/walkignore"
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
	Source  string       `json:"source"` // SourceFile attribute, e.g. "Login.java" (FE-8)
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
	Cst   string `json:"cst"`
	Slot  int    `json:"slot"`
	Line  int    `json:"line"`
	// Control-flow fields (FE-4). A LABEL pseudo-instruction carries ID (the
	// branch-target identifier bound at this position). A BRANCH carries Target
	// (the label id it jumps to). A SWITCH carries Default + Targets (the label
	// ids of its default and case arms). These let lower.go rebuild the CFG and
	// merge the operand stack / locals at control-flow joins with OP_CODE_PHI.
	ID      int   `json:"id"`
	Target  int   `json:"target"`
	Default int   `json:"default"`
	Targets []int `json:"targets"`
}

// ConvertFile lowers the Java at path (a file or directory) into a gIR program:
// one ir.Module per class, one ir.Function per method.
// minJDK is the lowest JDK the Java frontend supports: JavaDump.java uses the
// java.lang.classfile API, standardized in JDK 24.
const minJDK = 24

func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	javaExe, err := exec.LookPath("java")
	if err != nil {
		return nil, fmt.Errorf("java not found on PATH (JDK %d+ required for the Java frontend): %w", minJDK, err)
	}

	// Probe the JDK version up front: the common CI JDK (Temurin 17/21) is too
	// old for the classfile API, and the failure would otherwise surface as an
	// opaque compile error. Only hard-fail on a POSITIVE too-old detection; if the
	// probe itself can't run, proceed and let the dump report the real error.
	// The probe result is cached per launcher path — spawning a JVM just to read
	// its version (~150ms) is pure overhead on every scan after the first.
	if major, ok := javaMajorCached(javaExe); ok && major < minJDK {
		return nil, fmt.Errorf("the Java frontend requires JDK %d+ (JavaDump.java uses the java.lang.classfile API); found Java %d at %s — install a JDK %d+ or set JAVA_HOME to one", minJDK, major, javaExe, minJDK)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	inputs := resolveInputs(abs)

	// Prefer the once-per-process precompiled helper: running `java
	// JavaDump.java` (source-file mode) bootstraps the compiler and recompiles
	// the helper on EVERY invocation (~0.5-1s); `java -cp <classes> JavaDump`
	// skips that entirely. Identical helper source, identical JSON — only the
	// launch mode differs. Falls back to source-file mode if javac is
	// unavailable or the one-time compile failed.
	var args []string
	if classDir := compiledHelperDir(javaExe); classDir != "" {
		args = append([]string{"-cp", classDir, "JavaDump"}, inputs...)
	} else {
		scriptPath, cleanup, err := writeHelperScript()
		if err != nil {
			return nil, err
		}
		defer cleanup()
		args = append([]string{scriptPath}, inputs...)
	}
	ctx, cancel := proc.ParseContext()
	defer cancel()
	cmd := exec.CommandContext(ctx, javaExe, args...)
	out, err := cmd.Output()
	if err != nil {
		// cmd.Output() puts the helper's stderr (the actual javac/classfile
		// diagnostic) on ExitError.Stderr; surface it instead of a bare exit code.
		detail := ""
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			detail = "\n" + string(tail(ee.Stderr, 2000))
		}
		return nil, fmt.Errorf("java dump failed for %s: %w%s", path, err, detail)
	}

	var doc dumpDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parsing java dump for %s: %w", path, err)
	}

	// Resolve each class's SourceFile ("Login.java") to a real path under the
	// scan root so findings anchor to the source file instead of the scan
	// directory (FE-8). Fall back to the scan path when the source is unknown.
	sourceIdx := indexJavaSources(abs)
	prog := &ir.Program{Mode: "bytecode"}
	for _, cl := range doc.Classes {
		prog.Modules = append(prog.Modules, convertClass(cl, resolveJavaSource(abs, sourceIdx, cl.Source)))
	}
	return prog, nil
}

// indexJavaSources maps each .java file's base name to its path, under root (or
// root's directory when root is a file). First match wins on a name collision.
func indexJavaSources(root string) map[string]string {
	idx := map[string]string{}
	base := root
	if fi, err := os.Stat(root); err == nil && !fi.IsDir() {
		base = filepath.Dir(root)
	}
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if walkignore.SkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".java") {
			if _, seen := idx[d.Name()]; !seen {
				idx[d.Name()] = p
			}
		}
		return nil
	})
	return idx
}

// resolveJavaSource picks the source path for a class: its SourceFile base name
// matched against the index, else the scan path (so a Pos is always populated).
func resolveJavaSource(scanPath string, idx map[string]string, source string) string {
	if p, ok := idx[source]; ok {
		return p
	}
	return scanPath
}

// javaMajorCached memoizes javaMajor per launcher path for the process
// lifetime: the JDK under a fixed path does not change mid-run, and the probe
// costs a full JVM spawn.
func javaMajorCached(javaExe string) (int, bool) {
	type probe struct {
		major int
		ok    bool
	}
	if v, ok := javaProbeCache.Load(javaExe); ok {
		p := v.(probe)
		return p.major, p.ok
	}
	major, ok := javaMajor(javaExe)
	javaProbeCache.Store(javaExe, probe{major, ok})
	return major, ok
}

var javaProbeCache sync.Map // launcher path -> probe

// compiledHelperDir returns a directory containing the compiled JavaDump.class,
// or "" — in which case the caller uses source-file mode, exactly as before.
//
// The compiled helper lives in a persistent per-user cache keyed by the helper
// source hash + JDK major, so every later scan — including a fresh CLI process
// — skips source-file mode's per-invocation helper recompile (~0.5-1s). On a
// cache miss the CURRENT invocation still uses source-file mode (never slower
// than the status quo) while ONE background goroutine compiles and atomically
// publishes the cache for everyone after. Any failure (no javac, no cache dir,
// compile error) simply leaves the cache unpublished: the fallback path always
// works and reports the real diagnostic.
func compiledHelperDir(javaExe string) string {
	major, ok := javaMajorCached(javaExe)
	if !ok || major < minJDK {
		return "" // unknown/too-old JDK: no stable cache key, use the fallback
	}
	dir := helperCacheDir(major)
	if dir == "" {
		return ""
	}
	if fi, err := os.Stat(filepath.Join(dir, "JavaDump.class")); err == nil && fi.Size() > 0 {
		return dir
	}
	if _, loaded := helperCompiles.LoadOrStore(dir, struct{}{}); !loaded {
		go compileHelperInto(javaExe, dir)
	}
	return ""
}

// helperCompiles ensures at most one background helper compile per cache dir
// per process.
var helperCompiles sync.Map // cache dir -> started marker

// helperCacheDir is the per-user cache directory for the compiled helper,
// keyed by the embedded source's hash and the JDK major so a helper update or
// JDK switch never reuses stale classes. "" if no cache location is available.
func helperCacheDir(major int) string {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	if base == "" {
		return ""
	}
	sum := sha256.Sum256(javaDumpSource)
	return filepath.Join(base, "godzilla", fmt.Sprintf("javadump-%x-jdk%d", sum[:8], major))
}

// compileHelperInto compiles the embedded JavaDump.java with the launcher's
// sibling javac (falling back to PATH) into a temp dir and atomically renames
// it to dir. Losing a publish race to a concurrent process is fine — the
// winner's classes are identical by construction (same source hash in the key).
func compileHelperInto(javaExe, dir string) {
	javacExe := filepath.Join(filepath.Dir(javaExe), "javac")
	if _, err := os.Stat(javacExe); err != nil {
		if javacExe, err = exec.LookPath("javac"); err != nil {
			return
		}
	}
	srcPath, cleanup, err := writeHelperScript()
	if err != nil {
		return
	}
	defer cleanup()
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return
	}
	tmpDir, err := os.MkdirTemp(filepath.Dir(dir), filepath.Base(dir)+".tmp-")
	if err != nil {
		return
	}
	ctx, cancel := proc.ParseContext()
	defer cancel()
	if err := exec.CommandContext(ctx, javacExe, "-d", tmpDir, srcPath).Run(); err != nil {
		_ = os.RemoveAll(tmpDir)
		return
	}
	if err := os.Rename(tmpDir, dir); err != nil {
		_ = os.RemoveAll(tmpDir) // a concurrent process already published
	}
}

// javaMajor returns the launcher's major version. It first tries the JDK's
// `release` file (standard since JDK 9; avoids a ~30-40ms JVM spawn per fresh
// process) and falls back to spawning `java -version`. The bool is false if
// neither probe could determine the version.
func javaMajor(javaExe string) (int, bool) {
	if major, ok := javaMajorFromReleaseFile(javaExe); ok {
		return major, true
	}
	ctx, cancel := proc.ParseContext()
	defer cancel()
	// `java -version` prints to stderr; CombinedOutput captures it.
	out, err := exec.CommandContext(ctx, javaExe, "-version").CombinedOutput()
	if err != nil {
		return 0, false
	}
	return parseJavaMajor(string(out))
}

// parseJavaMajor extracts the major version from `java -version` output, e.g.
// `openjdk version "24.0.1" 2025-...` -> 24, or the legacy `java version
// "1.8.0_401"` -> 8. Returns false when no version token is found.
func parseJavaMajor(out string) (int, bool) {
	i := strings.Index(out, "version \"")
	if i < 0 {
		return 0, false
	}
	rest := out[i+len("version \""):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return 0, false
	}
	parts := strings.FieldsFunc(rest[:j], func(r rune) bool { return r == '.' || r == '_' || r == '-' })
	if len(parts) == 0 {
		return 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, false
	}
	// The legacy "1.N" scheme (JDK <= 8): the real major is the second field.
	if major == 1 && len(parts) > 1 {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			major = n
		}
	}
	return major, true
}

// javaMajorFromReleaseFile reads the major version from the JDK's `release`
// file (<jdk>/release, sibling of the launcher's bin/ directory; standard
// since JDK 9), whose JAVA_VERSION="..." line carries the same version string
// `java -version` prints. Returns false on any failure (missing file, no
// JAVA_VERSION line, unparseable value) so the caller falls back to spawning
// the JVM.
func javaMajorFromReleaseFile(javaExe string) (int, bool) {
	resolved, err := filepath.EvalSymlinks(javaExe)
	if err != nil {
		return 0, false
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(resolved), "..", "release"))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		val, ok := strings.CutPrefix(strings.TrimSpace(line), `JAVA_VERSION="`)
		if !ok {
			continue
		}
		val, ok = strings.CutSuffix(val, `"`)
		if !ok {
			return 0, false
		}
		// Reuse the `java -version` parser on the quoted value.
		return parseJavaMajor(`version "` + val + `"`)
	}
	return 0, false
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
	// Running the project's own build tool executes arbitrary code from the
	// scanned repo (Maven plugins, Gradle build logic). Off by default; without
	// opt-in, fall back to the in-process JDK-only compile.
	if !buildpolicy.Allowed() {
		fmt.Fprintf(os.Stderr, "godzilla: java: %s build not run under %s (set %s=1 or pass -allow-build to enable); using in-process source compile\n", sys.name, abs, buildpolicy.EnvAllowBuild)
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

	ctx, cancel := proc.BuildContext()
	defer cancel()
	cmd := exec.CommandContext(ctx, name, sys.args...)
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
		if walkignore.SkipDir(d.Name()) {
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
	return b[max(0, len(b)-n):]
}
