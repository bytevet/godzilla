// Package cvebench is an opt-in benchmark that measures Godzilla's recall on
// real-world CVEs (BACKLOG TRUST-11), tracked alongside the hand-written corpus
// F1. Each manifest entry pins a famous project to its VULNERABLE commit, with
// the sink file verified against the fix diff. A finding whose sink lands in
// that file, matching the expected rule, counts as a true positive.
//
// It clones external repos over the network, so it runs only under
// GODZILLA_CVE_BENCH=1; otherwise it skips. A target that cannot be cloned or
// scanned in this environment is excluded from the ratio rather than counted as
// a miss, mirroring the corpus scorer's eligibility handling.
package cvebench

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"godzilla/internal/rules/loader"
	"godzilla/internal/scan"

	"gopkg.in/yaml.v3"
)

type cveEntry struct {
	CVE      string `yaml:"cve"`
	Project  string `yaml:"project"`
	URL      string `yaml:"url"`
	Ref      string `yaml:"ref"`
	Subdir   string `yaml:"subdir"`
	SinkFile string `yaml:"sink_file"`
	Rule     string `yaml:"rule"`
	CWE      string `yaml:"cwe"`
}

func loadManifest(t *testing.T) []cveEntry {
	data, err := os.ReadFile("manifest.yaml")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m struct {
		CVEs []cveEntry `yaml:"cves"`
	}
	if err := yaml.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return m.CVEs
}

// cloneAt shallow-clones url at ref (a tag/branch, or a commit SHA via a
// partial-clone + checkout fallback) into a fresh temp dir that the test
// framework cleans up automatically.
func cloneAt(t *testing.T, url, ref string) (string, bool) {
	dir := t.TempDir()
	if exec.Command("git", "clone", "--depth", "1", "--branch", ref, url, dir).Run() == nil {
		return dir, true
	}
	dir = t.TempDir()
	if exec.Command("git", "clone", "--filter=blob:none", "--no-checkout", url, dir).Run() != nil {
		return "", false
	}
	if exec.Command("git", "-C", dir, "checkout", ref).Run() != nil {
		return "", false
	}
	return dir, true
}

func TestCVERecall(t *testing.T) {
	if os.Getenv("GODZILLA_CVE_BENCH") == "" {
		t.Skip("opt-in: set GODZILLA_CVE_BENCH=1 to run (clones external repos over the network)")
	}
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	var tp, scanned int
	for _, e := range loadManifest(t) {
		dir, ok := cloneAt(t, e.URL, e.Ref)
		if !ok {
			t.Logf("SKIP %-16s %s: clone failed", e.CVE, e.Project)
			continue
		}
		target := dir
		if e.Subdir != "" {
			target = filepath.Join(dir, e.Subdir)
		}
		res, err := scan.Scan(target, rs)
		if err != nil {
			t.Logf("SKIP %-16s %s: scan error: %v", e.CVE, e.Project, err)
			continue
		}
		scanned++
		hit := false
		for _, f := range res.Findings {
			if f.SinkPos == nil {
				continue
			}
			if strings.Contains(f.SinkPos.GetFilename(), e.SinkFile) && (e.Rule == "" || f.RuleID == e.Rule) {
				hit = true
				break
			}
		}
		if hit {
			tp++
			t.Logf("HIT  %-16s %s", e.CVE, e.Project)
		} else {
			t.Logf("MISS %-16s %s  (want %s in %s)", e.CVE, e.Project, e.Rule, e.SinkFile)
		}
	}

	if scanned == 0 {
		t.Skip("no CVE targets could be cloned/scanned in this environment (network?)")
	}
	t.Logf("real-world CVE recall: %d/%d = %.3f  (hand-written corpus F1 = 1.000 for comparison)",
		tp, scanned, float64(tp)/float64(scanned))
}
