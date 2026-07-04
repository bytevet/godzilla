// Package triage applies deterministic, user-directed suppression to findings
// AFTER analysis: inline `godzilla:ignore` source directives and a fingerprint
// baseline file. Both are the recourse a CI gate needs — a legacy codebase can
// be baselined so only NEW findings block a PR, and a reviewed false positive
// can be silenced at the source — without disabling a rule globally. Suppressed
// findings are RETAINED and flagged (analysis.Finding.Suppressed), not deleted,
// so they stay auditable, mirroring the LLM reviewer's behavior.
package triage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"godzilla/internal/analysis"
)

// ignoreToken is the directive that suppresses a finding when it appears in a
// comment on the finding's sink line or the line immediately above it. A
// bracketed, comma-separated rule list scopes it: `godzilla:ignore[go-sql-
// injection]` suppresses only that rule; a bare `godzilla:ignore` suppresses
// any finding on the line.
const ignoreToken = "godzilla:ignore"

// ApplyInlineIgnores marks any finding whose sink line (or the line directly
// above it) carries a godzilla:ignore directive as suppressed. It returns the
// same slice with the matched findings flagged. Source files are read at most
// once each. A finding already suppressed (e.g. by the LLM reviewer) is left
// as-is.
func ApplyInlineIgnores(findings []analysis.Finding) []analysis.Finding {
	fileLines := map[string][]string{}
	readLines := func(path string) []string {
		if lines, ok := fileLines[path]; ok {
			return lines
		}
		data, err := os.ReadFile(path)
		if err != nil {
			fileLines[path] = nil
			return nil
		}
		lines := strings.Split(string(data), "\n")
		fileLines[path] = lines
		return lines
	}

	for i := range findings {
		f := &findings[i]
		if f.Suppressed || f.SinkPos == nil {
			continue
		}
		lines := readLines(f.SinkPos.GetFilename())
		if lines == nil {
			continue
		}
		line := int(f.SinkPos.GetLine())
		// Check the sink line and the line above (a directive is commonly placed
		// on the preceding line).
		for _, ln := range []int{line, line - 1} {
			if ln < 1 || ln > len(lines) {
				continue
			}
			if directiveMatches(lines[ln-1], f.RuleID) {
				f.Suppressed = true
				f.SuppressedBy = "inline"
				f.SuppressionReason = "godzilla:ignore directive at " + f.SinkPos.GetFilename()
				break
			}
		}
	}
	return findings
}

// directiveMatches reports whether a source line carries a godzilla:ignore
// directive that applies to ruleID. A bare directive applies to every rule; a
// bracketed list applies only to the rules it names.
func directiveMatches(line, ruleID string) bool {
	idx := strings.Index(line, ignoreToken)
	if idx < 0 {
		return false
	}
	rest := line[idx+len(ignoreToken):]
	if !strings.HasPrefix(rest, "[") {
		return true // bare directive: suppress any rule on this line
	}
	end := strings.Index(rest, "]")
	if end < 0 {
		return true // malformed list, treat as bare
	}
	for _, r := range strings.Split(rest[1:end], ",") {
		if strings.TrimSpace(r) == ruleID {
			return true
		}
	}
	return false
}

// ApplyBaseline marks findings whose fingerprint appears in the baseline as
// suppressed. Fingerprints are matched as a MULTISET: a baseline entry that
// appears twice suppresses at most two matching findings, so a genuinely new
// duplicate at the same location still surfaces. Findings are processed in a
// deterministic order so the choice of which duplicate is suppressed is stable.
func ApplyBaseline(findings []analysis.Finding, baseline []string) []analysis.Finding {
	remaining := map[string]int{}
	for _, fp := range baseline {
		remaining[fp]++
	}

	order := make([]int, len(findings))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return analysis.Fingerprint(findings[order[a]]) < analysis.Fingerprint(findings[order[b]])
	})

	for _, i := range order {
		f := &findings[i]
		if f.Suppressed {
			continue
		}
		fp := analysis.Fingerprint(*f)
		if remaining[fp] > 0 {
			remaining[fp]--
			f.Suppressed = true
			f.SuppressedBy = "baseline"
			f.SuppressionReason = "present in baseline (fingerprint " + fp + ")"
		}
	}
	return findings
}

// Baseline is the on-disk baseline document: a list of finding fingerprints
// (with duplicates) captured from a prior scan.
type Baseline struct {
	Tool         string   `json:"tool"`
	Fingerprints []string `json:"fingerprints"`
}

// WriteBaseline writes the fingerprints of all non-suppressed findings to w as
// a Baseline JSON document, sorted for deterministic output.
func WriteBaseline(w io.Writer, findings []analysis.Finding) error {
	fps := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		fps = append(fps, analysis.Fingerprint(f))
	}
	sort.Strings(fps)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Baseline{Tool: "godzilla", Fingerprints: fps})
}

// LoadBaseline reads a Baseline document from path and returns its fingerprints.
func LoadBaseline(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var b Baseline
	if err := json.NewDecoder(bufio.NewReader(f)).Decode(&b); err != nil {
		return nil, fmt.Errorf("parsing baseline %s: %w", path, err)
	}
	return b.Fingerprints, nil
}
