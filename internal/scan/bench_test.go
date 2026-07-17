package scan

import (
	"os/exec"
	"strings"
	"testing"

	"godzilla/internal/rules/loader"
)

// benchScanLang benchmarks a full-pipeline scan of one language's sample so
// benchstat can compare per-language performance base-vs-head with the same
// statistical rigor as the Go engine benchmarks — a reliable replacement for
// noisy wall-clock timing. `tool` is the frontend's required external toolchain
// ("" for the in-binary JS frontend); the benchmark skips when it is absent, so
// a runner missing rustc/java/ruby degrades gracefully instead of failing.
func benchScanLang(b *testing.B, dir, tool string) {
	b.Helper()
	if tool != "" {
		if _, err := exec.LookPath(tool); err != nil {
			b.Skipf("%s not installed", tool)
		}
	}
	rs, err := loader.Builtin()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Scan(dir, rs); err != nil {
			b.Fatal(err)
		}
	}
}

// Per-language full-pipeline scan benchmarks. Each scans that language's
// command_injection sample (present for every frontend). Together with the Go
// benchmarks above, these give benchstat a per-language performance signal that
// covers the frontend/lowering cost — including the subprocess frontends
// (python3/rustc/java/ruby) — not just the shared engine.
func BenchmarkScan_Python(b *testing.B) {
	benchScanLang(b, "../../test/python/command_injection", "python3")
}
func BenchmarkScan_JS(b *testing.B)   { benchScanLang(b, "../../test/js/command_injection", "") }
func BenchmarkScan_Rust(b *testing.B) { benchScanLang(b, "../../test/rust/command_injection", "rustc") }
func BenchmarkScan_Java(b *testing.B) { benchScanLang(b, "../../test/java/command_injection", "java") }
func BenchmarkScan_Ruby(b *testing.B) { benchScanLang(b, "../../test/ruby/command_injection", "ruby") }

// BenchmarkScan_GoWithDeps scans a dependency-bearing Go sample (gin + gorm).
// Dependency bodies are now lowered so taint flows through them; the cost is kept
// in check by demand-driven analysis (a dependency function is analyzed only when
// taint reaches it — see Engine.ScopeSeed). A large regression shows up here.
func BenchmarkScan_GoWithDeps(b *testing.B) {
	rs, err := loader.Builtin()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Scan("../../test/go/gin_gorm", rs); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScan_GoSimple scans a minimal Go sample as a baseline.
func BenchmarkScan_GoSimple(b *testing.B) {
	rs, err := loader.Builtin()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Scan("../../test/go/command_injection", rs); err != nil {
			b.Fatal(err)
		}
	}
}

// TestGoFindingsScopedToUserCode is the invariant for dependency lowering: the
// Go frontend DOES lower third-party bodies (so taint flows through gin/gorm),
// so the converted program is large — but every reported finding must sit in
// USER code, never inside a lowered dependency. If the finding-scope regressed,
// analyzing library internals would surface library-internal noise.
func TestGoFindingsScopedToUserCode(t *testing.T) {
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	res, err := Scan("../../test/go/gin_gorm", rs)
	if err != nil {
		t.Fatalf("scan gin_gorm: %v", err)
	}
	// Dependency bodies are lowered now (the feature) — the program is large.
	n := 0
	for _, m := range res.Program.Modules {
		n += len(m.Functions)
	}
	if n < 100 {
		t.Errorf("expected dependency bodies to be lowered (thousands of functions); got %d — "+
			"dep-lowering (two-phase load: non-stdlib packages as explicit syntax roots) may have regressed", n)
	}
	// But no finding may be scoped into a dependency.
	if len(res.Findings) == 0 {
		t.Fatal("expected findings in gin_gorm")
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Package, "gin-gonic") || strings.Contains(f.Package, "gorm.io") ||
			strings.Contains(f.Package, "golang.org/x/") {
			t.Errorf("finding scoped into a dependency package %q: %s in %s", f.Package, f.RuleID, f.Function)
		}
	}
}
