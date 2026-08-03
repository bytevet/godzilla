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
	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

type Converter struct {
	skipped int // files this run could not lower; see Skipped
}

// Skipped reports how many source files this converter could not lower. The scan
// layer surfaces it per language, so a run that dropped most of a project is
// visible instead of reading as clean coverage (see scan.LangCoverage.Skipped).
func (c *Converter) Skipped() int { return c.skipped }

func NewConverter() *Converter { return &Converter{} }

// ConvertFile lowers the C/C++ at path (a file or directory) to gIR via the
// shared frontend.Batch driver: per-file compile failures (e.g. missing
// headers) are tolerated in directory mode, mirroring the Python/JS frontends.
func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	b := c.batch()
	prog, skipped, err := b.Convert(path)
	c.skipped += skipped
	return prog, err
}

// ConvertInventory lowers the C/C++ files of a pre-walked scan-root inventory
// (see walkignore.Inventory), skipping the directory walk ConvertFile's
// directory mode would repeat.
func (c *Converter) ConvertInventory(inv *walkignore.Inventory) (*ir.Program, error) {
	b := c.batch()
	prog, skipped, err := b.ConvertInventory(inv)
	c.skipped += skipped
	return prog, err
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
