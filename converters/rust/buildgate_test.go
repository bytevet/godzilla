package rust_converter

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCargoBuildGated is the TRUST-1 guard for Rust: a Cargo project must NOT be
// analyzed by running `cargo` unless build execution is explicitly allowed.
// Running cargo executes arbitrary repo code (build.rs, proc-macros). With the
// gate off (default), ConvertFile falls back to per-file rustc and must not
// invoke cargo — proven here by pointing GODZILLA_CARGO at a non-existent binary
// that would make any cargo call fail loudly.
func TestCargoBuildGated(t *testing.T) {
	requireRustc(t)

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Cargo.toml"), "[package]\nname=\"g\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
	writeFile(t, filepath.Join(dir, "src", "main.rs"), `use std::process::Command;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    Command::new("sh").arg("-c").arg(&a[1]).status().unwrap();
}
`)

	// Make any cargo invocation fail, so a fallback that (wrongly) runs cargo
	// would error instead of silently succeeding.
	t.Setenv("GODZILLA_CARGO", filepath.Join(dir, "no-such-cargo"))

	// Gate OFF (default): must fall back to per-file rustc, not cargo.
	t.Setenv("GODZILLA_ALLOW_BUILD", "")
	prog, err := NewConverter().ConvertFile(dir)
	if err != nil {
		t.Fatalf("with build disabled, ConvertFile must fall back to per-file rustc (not cargo), got error: %v", err)
	}
	if prog == nil || len(prog.Modules) == 0 {
		t.Fatalf("expected the fallback to lower src/main.rs into at least one module")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
