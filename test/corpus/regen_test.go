package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytevet/godzilla/internal/rules/loader"
	"github.com/bytevet/godzilla/internal/scan"

	"gopkg.in/yaml.v3"
)

// TestRegenerateManifests (re)writes an expected.yaml into every sample dir from
// the CURRENT scan output. It is a maintenance helper — skipped unless
// GODZILLA_REGEN is set — so run it deliberately after a rule change, then
// review the diff before committing:
//
//	GODZILLA_REGEN=1 go test ./test/corpus/ -run RegenerateManifests -v
func TestRegenerateManifests(t *testing.T) {
	if os.Getenv("GODZILLA_REGEN") == "" {
		t.Skip("set GODZILLA_REGEN=1 to regenerate expected.yaml manifests")
	}

	rs, err := loader.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := sampleDirs()
	if err != nil {
		t.Fatal(err)
	}

	for _, dir := range dirs {
		res, err := scan.Scan(dir, rs)
		if err != nil {
			t.Errorf("scan %s: %v (leaving manifest untouched)", dir, err)
			continue
		}
		if lang, ok := unconverted(res); ok {
			t.Logf("scan %s: the %s frontend did not convert (%s); leaving manifest untouched", dir, lang, coverageErr(res, lang))
			continue
		}
		path := filepath.Join(dir, "expected.yaml")
		prev, _ := loadExpectation(path)
		exp := expectationFrom(res.Findings, prev)
		body, err := yaml.Marshal(exp)
		if err != nil {
			t.Fatal(err)
		}
		header := "# Expected findings for this sample (see test/README.md). Regenerate with:\n" +
			"#   GODZILLA_REGEN=1 go test ./test/corpus/ -run RegenerateManifests\n"
		out := header + string(body)
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s -> %v", path, countByRule(res.Findings))
	}
}

// TestRegeneratePositionGoldens rewrites the per-language position goldens the
// corpus asserts against. Separate from the manifests so each can be
// regenerated without rewriting the other, and behind the same env gate so the
// gates themselves stay pure assertions.
func TestRegeneratePositionGoldens(t *testing.T) {
	if os.Getenv("GODZILLA_REGEN") == "" {
		t.Skip("set GODZILLA_REGEN=1 to regenerate the position goldens")
	}
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := sampleDirs()
	if err != nil {
		t.Fatal(err)
	}
	positions := newPosCollector()
	for _, dir := range dirs {
		res, err := scan.Scan(dir, rs)
		if err != nil {
			t.Errorf("scan %s: %v (leaving its golden rows untouched)", dir, err)
			continue
		}
		// A frontend that could not run reports zero findings, which is
		// indistinguishable from a clean sample. Recording that would retire the
		// oracle for every language whose toolchain this machine lacks.
		if lang, ok := unconverted(res); ok {
			t.Logf("scan %s: the %s frontend did not convert (%s); leaving its golden rows untouched", dir, lang, coverageErr(res, lang))
			continue
		}
		positions.add(t, filepath.ToSlash(strings.TrimPrefix(dir, "../")), res.Findings)
	}
	positions.writeGoldens(t)
}

// unconverted names a language the target contains but the frontend failed to
// lower.
func unconverted(res scan.Result) (string, bool) {
	for _, c := range res.Coverage {
		if c.Detected && !c.Converted {
			return c.Language, true
		}
	}
	return "", false
}

func coverageErr(res scan.Result, lang string) string {
	for _, c := range res.Coverage {
		if c.Language == lang {
			return c.Err
		}
	}
	return ""
}
