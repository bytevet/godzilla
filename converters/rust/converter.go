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

	"godzilla/internal/buildpolicy"
	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

type Converter struct{}

func NewConverter() *Converter { return &Converter{} }

// ConvertFile lowers a single .rs file, a directory of standalone .rs files, or
// a Cargo project. A directory with a Cargo.toml at its root is built with cargo
// (so its dependency crates — a web framework, etc. — resolve); otherwise each
// .rs file is compiled standalone with rustc.
func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		if fileExists(filepath.Join(path, "Cargo.toml")) {
			// `cargo` executes arbitrary code from the scanned repo (build.rs,
			// proc-macros, and every dependency crate's build script). Off by
			// default; without opt-in, fall through to per-file rustc, which
			// compiles the project's own sources with no dependency resolution
			// and no build-script execution.
			if buildpolicy.Allowed() {
				return convertCargo(path)
			}
			fmt.Fprintf(os.Stderr, "warning: rust: cargo build not run under %s (set %s=1 or pass -allow-build to enable); lowering source files directly without dependency resolution\n", path, buildpolicy.EnvAllowBuild)
		}
	}

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
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if walkignore.SkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(filepath.Ext(p), ".rs") {
			if info, e := d.Info(); e == nil && walkignore.TooBig(info.Size()) {
				return nil
			}
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
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmp.Name()) }()

	cmd := exec.Command(rustc,
		"--emit=mir", "-Zmir-include-spans=on",
		"--crate-type", "lib", "--cap-lints", "allow",
		"-o", tmp.Name(), src)
	return runMIR(cmd, tmp.Name(), "rustc")
}

// runMIR runs cmd — which must be configured to emit MIR to outPath — and returns
// the emitted MIR text. It sets RUSTC_BOOTSTRAP=1, the escape hatch that unlocks
// -Zmir-include-spans on the stable toolchain (the MIR text format is itself
// unstable, so this adds no new stability assumption). label names the tool for
// the error message.
func runMIR(cmd *exec.Cmd, outPath, label string) (string, error) {
	cmd.Env = append(os.Environ(), "RUSTC_BOOTSTRAP=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%s: %v: %s", label, err, strings.TrimSpace(string(out)))
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// convertCargo builds a Cargo project with `cargo rustc -- --emit=mir` so its
// dependency crates (a web framework, etc.) are resolved and on the path, then
// lowers the top-level crate's MIR. cargo passes the trailing args to ONLY the
// final crate's rustc invocation, so dependency MIR is not emitted — the analyzed
// module is exactly the project's own code, with framework calls named by their
// real crate paths. A build failure (e.g. a dependency that can't be fetched
// offline) is surfaced as an error, which the directory merge / CLI treats as a
// skipped frontend. --emit=mir=<path> pins the output; RUSTC_BOOTSTRAP=1 unlocks
// the span flag on stable (the MIR text format is already unstable).
func convertCargo(dir string) (*ir.Program, error) {
	cargo := "cargo"
	if v := os.Getenv("GODZILLA_CARGO"); v != "" {
		cargo = v
	}
	tmp, err := os.CreateTemp("", "godzilla-cargo-*.mir")
	if err != nil {
		return nil, err
	}
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmp.Name()) }()

	cmd := exec.Command(cargo, "rustc", "--lib", "--",
		"--emit=mir="+tmp.Name(), "-Zmir-include-spans=on", "--cap-lints", "allow")
	cmd.Dir = dir
	data, err := runMIR(cmd, tmp.Name(), fmt.Sprintf("cargo rustc in %s", dir))
	if err != nil {
		return nil, err
	}
	mod := lowerMIR(data, filepath.Join(dir, "src", "lib.rs"))
	return &ir.Program{Mode: "mir", Modules: []*ir.Module{mod}}, nil
}
