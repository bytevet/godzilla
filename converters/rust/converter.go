//go:build llvm

// Package rust_converter is Godzilla's Rust frontend. It compiles each .rs file
// to LLVM IR with rustc (`--emit=llvm-ir -Copt-level=1 -Cdebuginfo=2`) and lowers
// the IR to gIR via converters/llvm. Built only under the `llvm` tag; the default
// build uses the stub in converter_stub.go. (Cargo-crate support is a follow-up;
// single .rs files are compiled directly.)
package rust_converter

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	llvm_converter "godzilla/converters/llvm"
	ir "godzilla/pkg/ir/v1"
)

type Converter struct{}

func NewConverter() *Converter { return &Converter{} }

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
		return nil, fmt.Errorf("no Rust source compiled under %s", path)
	}
	return prog, nil
}

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
		if strings.EqualFold(filepath.Ext(p), ".rs") {
			out = append(out, p)
		}
		return nil
	})
	return out, nil
}

func lowerOne(src string) (*ir.Module, error) {
	rustc := "rustc"
	if v := os.Getenv("GODZILLA_RUSTC"); v != "" {
		rustc = v
	}
	tmp, err := os.CreateTemp("", "godzilla-*.ll")
	if err != nil {
		return nil, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	args := []string{"--emit=llvm-ir", "-Copt-level=1", "-Cdebuginfo=2", "-Cpanic=abort", "-o", tmp.Name(), src}
	out, err := exec.Command(rustc, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("rustc: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return llvm_converter.Lower(tmp.Name(), src, "rust", "rust:", llvm_converter.RustDemangle)
}
