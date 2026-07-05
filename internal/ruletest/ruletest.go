// Package ruletest runs a directory of vulnerable sample projects against a
// rule set and checks each against a hand-written expected.yaml, giving rule
// authors a `godzilla rules test <dir>` workflow (CI-7) without cloning the repo
// or running `go test`. It is the same oracle shape the in-repo corpus uses —
// every expected rule must fire (at least `min` times, optionally at a given
// sink line/callee) and no unexpected rule may fire — packaged for reuse by the
// CLI.
package ruletest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	"godzilla/internal/scan"

	"gopkg.in/yaml.v3"
)

// Expectation is a sample's expected.yaml. An empty Findings list means the
// sample must produce NO findings (a clean-code / false-positive control).
type Expectation struct {
	Findings []Expected `yaml:"findings"`
}

// Expected asserts a rule fires at least Min times (default 1), optionally at a
// sink Line and/or a sink callee containing Sink.
type Expected struct {
	Rule string `yaml:"rule"`
	Min  int    `yaml:"min"`
	Line int32  `yaml:"line,omitempty"`
	Sink string `yaml:"sink,omitempty"`
}

// Result is the outcome of checking one sample directory.
type Result struct {
	Sample   string   // sample directory name
	Pass     bool     // true if every assertion held
	Failures []string // human-readable assertion failures (empty when Pass)
	Skipped  string   // non-empty reason if the sample could not be evaluated
}

// RunDir scans every immediate subdirectory of root that contains an
// expected.yaml and checks it against rs. It returns one Result per such sample,
// sorted by name. A directory with no expected.yaml is ignored (not a sample).
func RunDir(root string, rs *rules.RuleSet) ([]Result, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var results []Result
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "expected.yaml")); err != nil {
			continue // not a sample
		}
		results = append(results, checkSample(e.Name(), dir, rs))
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Sample < results[j].Sample })
	return results, nil
}

// checkSample scans one sample dir and compares to its expected.yaml.
func checkSample(name, dir string, rs *rules.RuleSet) Result {
	res := Result{Sample: name, Pass: true}
	exp, err := loadExpectation(filepath.Join(dir, "expected.yaml"))
	if err != nil {
		return Result{Sample: name, Skipped: fmt.Sprintf("invalid expected.yaml: %v", err)}
	}
	scanRes, err := scan.Scan(dir, rs)
	if err != nil {
		return Result{Sample: name, Skipped: fmt.Sprintf("scan failed: %v", err)}
	}
	got := countByRule(scanRes.Findings)

	expected := map[string]bool{}
	for _, ef := range exp.Findings {
		min := ef.Min
		if min < 1 {
			min = 1
		}
		expected[ef.Rule] = true
		if got[ef.Rule] < min {
			res.fail(fmt.Sprintf("rule %q: want >= %d finding(s), got %d", ef.Rule, min, got[ef.Rule]))
		}
		if !matchesLocation(ef, scanRes.Findings) {
			res.fail(fmt.Sprintf("rule %q: no finding matched the expected location (line=%d sink=%q)", ef.Rule, ef.Line, ef.Sink))
		}
	}
	for rule, n := range got {
		if !expected[rule] {
			res.fail(fmt.Sprintf("unexpected finding: rule %q fired %d time(s) but is not in expected.yaml (false positive?)", rule, n))
		}
	}
	return res
}

func (r *Result) fail(msg string) {
	r.Pass = false
	r.Failures = append(r.Failures, msg)
}

func matchesLocation(ef Expected, findings []analysis.Finding) bool {
	if ef.Line == 0 && ef.Sink == "" {
		return true
	}
	for _, f := range findings {
		if f.RuleID != ef.Rule {
			continue
		}
		if ef.Line != 0 && (f.SinkPos == nil || f.SinkPos.GetLine() != ef.Line) {
			continue
		}
		if ef.Sink != "" && !strings.Contains(f.SinkCallee, ef.Sink) {
			continue
		}
		return true
	}
	return false
}

func countByRule(findings []analysis.Finding) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		counts[f.RuleID]++
	}
	return counts
}

func loadExpectation(path string) (Expectation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Expectation{}, err
	}
	var e Expectation
	if err := yaml.Unmarshal(data, &e); err != nil {
		return Expectation{}, err
	}
	return e, nil
}
