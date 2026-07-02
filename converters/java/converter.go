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
// classpath are best scanned as compiled .class/.jar. Requires a JDK 24+ `java`
// on PATH (for the java.lang.classfile API), mirroring how the Python frontend
// needs `python3`.
package java_converter

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

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

	cmd := exec.Command(javaExe, scriptPath, abs)
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
