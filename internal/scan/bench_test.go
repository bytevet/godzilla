package scan

import (
	"testing"

	go_converter "godzilla/converters/go"
	"godzilla/internal/rules/loader"
)

// BenchmarkScan_GoWithDeps scans a dependency-bearing Go sample (gin + gorm). It
// tracks the PERF-2 win (analysis scoped to the target package, not the whole
// dependency closure); a regression here shows up as a large slowdown.
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

// TestGoAnalysisScopedToTargetPackages is a DETERMINISTIC perf-regression guard
// for PERF-2 (non-flaky, unlike a wall-clock assertion). The Go frontend must
// build SSA only for the scanned package(s), not the transitive dependency
// closure. gin_gorm imports gin + gorm (thousands of functions); if scoping
// regressed to ssautil.AllPackages/LoadAllSyntax, the converted program would
// balloon to thousands of functions. A tight bound catches that.
func TestGoAnalysisScopedToTargetPackages(t *testing.T) {
	prog, err := go_converter.NewConverter().ConvertFile("../../test/go/gin_gorm")
	if err != nil {
		t.Fatalf("convert gin_gorm: %v", err)
	}
	n := 0
	for _, m := range prog.Modules {
		n += len(m.Functions)
	}
	if n > 100 {
		t.Errorf("Go analysis is not scoped to the target package: %d functions converted "+
			"for gin_gorm (expected a handful). PERF-2 (LoadSyntax + ssautil.Packages) may have regressed.", n)
	}
}
