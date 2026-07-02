// Package rust_converter is Godzilla's Rust frontend. It compiles each .rs file
// to rustc's textual MIR (Mid-level IR) and lowers that to gIR.
//
// MIR — not LLVM IR — is the right substrate for Rust taint analysis. rustc's
// LLVM IR routes returned values through `sret` out-pointers and stack memory,
// and exposes only internal monomorphized symbols (`std::env::__var`,
// `std::sys::process::unix::common::Command::arg`) that are unstable across
// compiler versions. MIR instead names the source-level public API
// (`std::env::var`, `Command::arg`) and assigns call results directly to
// locals, so a straight-line value-forwarding pass (mir.go) recovers clean SSA
// with no cgo, no libLLVM, and no memory modeling. Emitting MIR also skips
// codegen, so it is fast.
//
// Scope: std-based flows compile standalone (env / fs / process / io). Sources
// or sinks that live in third-party crates (web frameworks, DB drivers) need
// those crates available at scan time, like Godzilla's other compiled-language
// frontends; single .rs files are compiled directly here (Cargo-crate driving
// is a follow-up).
package rust_converter

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	ir "godzilla/pkg/ir/v1"
)

type Converter struct{}

func NewConverter() *Converter { return &Converter{} }

// ConvertFile lowers a single .rs file or every .rs file under a directory.
func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	files, err := collect(path)
	if err != nil {
		return nil, err
	}
	prog := &ir.Program{Mode: "mir"}
	for _, f := range files {
		mir, err := emitMIR(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", f, err)
			continue
		}
		prog.Modules = append(prog.Modules, lowerMIR(mir, f))
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

// emitMIR runs rustc to dump textual MIR for one source file. Spans are enabled
// (-Zmir-include-spans=on) so every instruction gets a source position;
// RUSTC_BOOTSTRAP=1 unlocks that flag on the stable toolchain (the MIR text
// format is itself explicitly unstable, so this is not a new stability
// assumption). --crate-type lib lets a file without `fn main` compile, and
// --cap-lints allow silences sample warnings.
func emitMIR(src string) (string, error) {
	rustc := "rustc"
	if v := os.Getenv("GODZILLA_RUSTC"); v != "" {
		rustc = v
	}
	tmp, err := os.CreateTemp("", "godzilla-*.mir")
	if err != nil {
		return "", err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	cmd := exec.Command(rustc,
		"--emit=mir", "-Zmir-include-spans=on",
		"--crate-type", "lib", "--cap-lints", "allow",
		"-o", tmp.Name(), src)
	cmd.Env = append(os.Environ(), "RUSTC_BOOTSTRAP=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("rustc: %v: %s", err, strings.TrimSpace(string(out)))
	}
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		return "", err
	}
	return string(data), nil
}
