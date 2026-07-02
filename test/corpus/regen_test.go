package corpus

import (
	"os"
	"path/filepath"
	"testing"

	"godzilla/internal/rules/loader"
	"godzilla/internal/scan"

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
		exp := expectationFrom(res.Findings)
		body, err := yaml.Marshal(exp)
		if err != nil {
			t.Fatal(err)
		}
		header := "# Expected findings for this sample (see test/README.md). Regenerate with:\n" +
			"#   GODZILLA_REGEN=1 go test ./test/corpus/ -run RegenerateManifests\n"
		out := header + string(body)
		path := filepath.Join(dir, "expected.yaml")
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s -> %v", path, countByRule(res.Findings))
	}
}
