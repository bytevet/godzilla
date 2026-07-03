// Package corpus turns the vulnerable samples under test/{go,python,js} into
// first-class tests: each sample dir carries an expected.yaml declaring which
// rules must fire, and corpus_test.go asserts the real scan pipeline reproduces
// exactly that. This gives every sample a precise oracle — a dropped finding or
// a new false positive on any sample fails the build.
package corpus

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"godzilla/internal/analysis"

	"gopkg.in/yaml.v3"
)

// sampleLangs are the language subtrees under test/ scanned by the corpus,
// relative to this package's directory (Go tests run with CWD = package dir).
var sampleLangs = []string{"go", "python", "js", "java", "c", "cpp", "rust"}

// sampleDirs returns every immediate sample directory under test/{go,python,js},
// as paths relative to this package (e.g. "../go/sql_injection").
func sampleDirs() ([]string, error) {
	var dirs []string
	for _, lang := range sampleLangs {
		root := filepath.Join("..", lang)
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				dirs = append(dirs, filepath.Join(root, e.Name()))
			}
		}
	}
	return dirs, nil
}

// buildFiles are the Maven/Gradle project markers that make a Java sample
// dependency-bearing (compiled by its own build tool rather than in-process).
var buildFiles = []string{"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}

// hasBuildFile reports whether dir is the root of a Maven/Gradle project.
func hasBuildFile(dir string) bool {
	for _, f := range buildFiles {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

// buildToolAvailable reports whether a build tool can compile dir: a committed
// wrapper, or mvn/gradle on PATH.
func buildToolAvailable(dir string) bool {
	for _, w := range []string{"mvnw", "gradlew"} {
		if _, err := os.Stat(filepath.Join(dir, w)); err == nil {
			return true
		}
	}
	for _, tool := range []string{"mvn", "gradle"} {
		if _, err := exec.LookPath(tool); err == nil {
			return true
		}
	}
	return false
}

// Expectation is a sample's expected.yaml. An empty (or absent) Findings list
// means the sample must produce NO findings (a clean-code / false-positive guard).
type Expectation struct {
	Findings []ExpectedFinding `yaml:"findings"`
}

// ExpectedFinding says a rule must fire at least Min times (Min defaults to 1).
type ExpectedFinding struct {
	Rule string `yaml:"rule"`
	Min  int    `yaml:"min"`
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

// countByRule tallies findings per rule ID.
func countByRule(findings []analysis.Finding) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.RuleID]++
	}
	return counts
}

// expectationFrom builds the Expectation that matches a scan's actual output,
// used by the guarded manifest generator (see RegenerateManifests).
func expectationFrom(findings []analysis.Finding) Expectation {
	counts := countByRule(findings)
	rules := make([]string, 0, len(counts))
	for r := range counts {
		rules = append(rules, r)
	}
	sort.Strings(rules)

	e := Expectation{}
	for _, r := range rules {
		e.Findings = append(e.Findings, ExpectedFinding{Rule: r, Min: counts[r]})
	}
	return e
}
