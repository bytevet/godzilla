//go:build llvm

// Package cpp_converter is Godzilla's C/C++ frontend. It compiles each
// translation unit to LLVM IR with clang (`-O1 -g -S -emit-llvm`) and lowers the
// IR to gIR via converters/llvm. Built only under the `llvm` tag (cgo/libLLVM);
// the default build uses the stub in converter_stub.go.
package cpp_converter

import (
	"cmp"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	llvm_converter "godzilla/converters/llvm"
	"godzilla/internal/proc"
	ir "godzilla/pkg/ir/v1"
)

type Converter struct{}

func NewConverter() *Converter { return &Converter{} }

// ConvertFile lowers the C/C++ at path (a file or directory) to gIR. Per-file
// compile failures (e.g. missing headers) are tolerated, mirroring the directory
// mode of the Python/JS frontends.
func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	files, err := collect(path)
	if err != nil {
		return nil, err
	}
	prog := &ir.Program{Mode: "llvm"}
	for _, f := range files {
		mod, err := lowerOne(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", f, err)
			continue
		}
		prog.Modules = append(prog.Modules, mod)
	}
	if len(prog.Modules) == 0 {
		return nil, fmt.Errorf("no C/C++ translation units compiled under %s", path)
	}
	return prog, nil
}

var cppExts = map[string]bool{".c": true, ".cc": true, ".cpp": true, ".cxx": true, ".c++": true}

func collect(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var out []string
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if cppExts[strings.ToLower(filepath.Ext(p))] {
			out = append(out, p)
		}
		return nil
	})
	return out, nil
}

func lowerOne(src string) (*ir.Module, error) {
	isCpp := strings.ToLower(filepath.Ext(src)) != ".c"
	cc := compilerFor(isCpp)

	tmp, err := os.CreateTemp("", "godzilla-*.ll")
	if err != nil {
		return nil, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	// -O1 runs mem2reg (SSA registers) without heavy inlining; -g provides source
	// positions; -w silences warnings.
	args := []string{"-O1", "-g", "-w", "-S", "-emit-llvm", "-o", tmp.Name(), src}
	ctx, cancel := proc.ParseContext()
	defer cancel()
	out, err := exec.CommandContext(ctx, cc, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("clang: %v: %s", err, strings.TrimSpace(string(out)))
	}

	lang, prefix, dem := "c", "c:", llvm_converter.CDemangle
	if isCpp {
		lang, prefix, dem = "cpp", "cpp:", llvm_converter.CppDemangle
	}
	return llvm_converter.Lower(tmp.Name(), src, lang, prefix, dem)
}

// compilerFor picks the C or C++ driver, honoring GODZILLA_CC / GODZILLA_CXX
// overrides (e.g. to pin the clang whose LLVM version matches the linked
// libLLVM).
func compilerFor(isCpp bool) string {
	if isCpp {
		return cmp.Or(os.Getenv("GODZILLA_CXX"), "clang++")
	}
	return cmp.Or(os.Getenv("GODZILLA_CC"), "clang")
}
