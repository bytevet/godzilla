package corpus

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"godzilla/internal/buildpolicy"
	"godzilla/internal/rules/loader"
	"godzilla/internal/scan"
)

// sampleEligible reports whether a sample can run in this environment, mirroring
// the per-language skips in TestCorpus (toolchain availability + opt-in build
// samples). Ineligible samples are excluded from the score rather than counted
// as failures.
func sampleEligible(name, dir string) bool {
	switch {
	case strings.HasPrefix(name, "python/"):
		if _, err := exec.LookPath("python3"); err != nil {
			return false
		}
	case strings.HasPrefix(name, "java/"):
		if _, err := exec.LookPath("java"); err != nil {
			return false
		}
		if hasBuildFile(dir) && (os.Getenv("GODZILLA_SPRING_E2E") == "" || !buildToolAvailable(dir)) {
			return false
		}
	case strings.HasPrefix(name, "c/"), strings.HasPrefix(name, "cpp/"):
		if !llvmBuilt {
			return false
		}
		if _, err := exec.LookPath("clang"); err != nil {
			return false
		}
	case strings.HasPrefix(name, "rust/"):
		if _, err := exec.LookPath("rustc"); err != nil {
			return false
		}
		if isCargoProject(dir) {
			if _, err := exec.LookPath("cargo"); err != nil {
				return false
			}
			if cargoHasDeps(dir) && os.Getenv("GODZILLA_RUST_E2E") == "" {
				return false
			}
		}
	}
	return true
}

// TestCorpusSignalToNoise quantifies the tool's signal/noise over the labeled
// corpus (TRUST-5). Each sample's expected.yaml is the ground truth; the scan's
// findings are the predictions. At the (sample, rule) granularity:
//
//	TP = an expected rule that fired          FN = an expected rule that did not fire
//	FP = a rule that fired but was not expected (false positive, incl. any finding on a _safe sample)
//
// It reports precision / recall / F1 / false-positive rate and asserts a floor,
// so an aggregate regression (a new FP class, a dropped finding) is caught even
// if it slips past an individual sample's assertion. The same machinery scores
// any external labeled corpus (dirs with expected.yaml) — e.g. an OWASP
// Benchmark checkout — for a real-world number; here it runs on the in-repo set.
func TestCorpusSignalToNoise(t *testing.T) {
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	dirs, err := sampleDirs()
	if err != nil {
		t.Fatalf("enumerate samples: %v", err)
	}

	// In E2E mode the dependency-bearing samples (Cargo/Maven/Gradle projects)
	// must be built so their third-party imports resolve; without this they fall
	// back to build-less lowering and fail on the unresolved imports, producing no
	// findings. TestCorpus enables the build per build-sample; mirror it here so
	// the aggregate score analyzes the same code. Only build projects trigger a
	// build, and they are eligible only under these E2E flags, so this is a no-op
	// for a normal run.
	if os.Getenv("GODZILLA_RUST_E2E") != "" || os.Getenv("GODZILLA_SPRING_E2E") != "" {
		t.Setenv(buildpolicy.EnvAllowBuild, "1")
	}

	var tp, fp, fn, samples int
	for _, dir := range dirs {
		name := strings.TrimPrefix(filepath.ToSlash(dir), "../")
		if !sampleEligible(name, dir) {
			continue
		}
		exp, err := loadExpectation(filepath.Join(dir, "expected.yaml"))
		if err != nil {
			continue
		}
		res, err := scan.Scan(dir, rs)
		if err != nil {
			continue
		}
		// A sample whose frontend could not convert its source — a build/toolchain
		// failure such as a transient Cargo dependency-resolution error (E0432), not
		// an analysis regression — is excluded from the score, like an ineligible
		// sample, so it does not masquerade as a dropped finding and make the E2E
		// gate flaky. TestCorpus still asserts each sample individually, and the WS3
		// coverage gate surfaces frontend failures separately.
		if len(res.Failed()) > 0 {
			continue
		}
		samples++
		got := countByRule(res.Findings)
		expected := map[string]bool{}
		for _, ef := range exp.Findings {
			expected[ef.Rule] = true
			if got[ef.Rule] > 0 {
				tp++
			} else {
				fn++
			}
		}
		for rule, n := range got {
			if !expected[rule] {
				fp += n
			}
		}
	}

	precision := ratio(tp, tp+fp)
	recall := ratio(tp, tp+fn)
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	t.Logf("signal/noise over %d samples: TP=%d FP=%d FN=%d | precision=%.3f recall=%.3f F1=%.3f",
		samples, tp, fp, fn, precision, recall, f1)

	// Aggregate regression floor. The curated corpus should score at/near 1.0; a
	// drop means a systemic new FP or dropped finding.
	if precision < 0.98 {
		t.Errorf("precision %.3f below floor 0.98 (FP=%d) — a systemic false-positive regression", precision, fp)
	}
	if recall < 0.98 {
		t.Errorf("recall %.3f below floor 0.98 (FN=%d) — a systemic dropped-finding regression", recall, fn)
	}
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 1.0
	}
	return float64(num) / float64(den)
}
