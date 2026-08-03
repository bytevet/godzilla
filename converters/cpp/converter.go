//go:build llvm

// Package cpp_converter is Godzilla's C/C++ frontend. It compiles each
// translation unit to LLVM IR with clang (`-O1 -g -S -emit-llvm`) and lowers the
// IR to gIR via converters/llvm. Built only under the `llvm` tag (cgo/libLLVM);
// the default build uses the stub in converter_stub.go.
package cpp_converter

import (
	"cmp"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"godzilla/converters/frontend"
	llvm_converter "godzilla/converters/llvm"
	"godzilla/internal/proc"
	ir "godzilla/pkg/ir/v1"
)

// Converter lowers C/C++ sources into gIR: the shared frontend.Driver surface
// (ConvertFile/ConvertInventory/Skipped) over C/C++'s batch hooks (see batch).
// Per-file compile failures (e.g. missing headers) are tolerated in directory
// mode, mirroring the Python/JS frontends.
type Converter struct {
	frontend.Driver[cppFileResult]
}

func NewConverter() *Converter {
	c := &Converter{}
	c.NewBatch = c.batch
	return c
}

// batch builds the shared frontend.Batch driver with C/C++'s hooks. The file
// predicate is IsCppFile (lang.go, untagged) — the same one internal/scan uses
// for language detection.
func (c *Converter) batch() *frontend.Batch[cppFileResult] {
	return &frontend.Batch[cppFileResult]{
		Label: "cpp_converter",
		Lang:  "C/C++",
		Mode:  "llvm",
		Match: IsCppFile,
		Parse: frontend.PerFile(func(_, f string) cppFileResult {
			mod, err := lowerOne(f)
			return cppFileResult{mod: mod, err: err}
		}),
		Result: func(r *cppFileResult) (*ir.Module, error) { return r.mod, r.err },
	}
}

// cppFileResult is one file's outcome within a batch conversion.
type cppFileResult struct {
	mod *ir.Module
	err error
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
