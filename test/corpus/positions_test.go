package corpus

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/rules/loader"
	"github.com/bytevet/godzilla/internal/scan"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// goldenPositions pins the EXACT source and sink line/column of every JavaScript
// finding in the corpus.
//
// expected.yaml asserts rule counts, and only a handful of JS samples carry a
// `line:`. That leaves a systematic position shift -- an off-by-one column, a
// line-terminator the index does not recognise -- passing the corpus silently
// while every reported location is wrong. Positions are the part of a finding a
// human acts on, so they get an assertion of their own.
//
// Regenerate deliberately after a change that is MEANT to move positions, then
// read the diff line by line:
//
//	GODZILLA_REGEN=1 go test ./test/corpus/ -run TestJSFindingPositions
const goldenPositions = "testdata/js_positions.golden"

func TestJSFindingPositions(t *testing.T) {
	rs, err := loader.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	res, err := scan.Scan("../js", rs)
	if err != nil {
		t.Fatalf("scan ../js: %v", err)
	}

	got := renderPositions(t, res.Findings)

	if os.Getenv("GODZILLA_REGEN") != "" {
		if err := os.MkdirAll(filepath.Dir(goldenPositions), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPositions, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d findings)", goldenPositions, strings.Count(got, "\n"))
		return
	}

	want, err := os.ReadFile(goldenPositions)
	if err != nil {
		t.Fatalf("read golden: %v (regenerate with GODZILLA_REGEN=1)", err)
	}
	if got == string(want) {
		return
	}
	for _, d := range diffLines(strings.Split(strings.TrimRight(string(want), "\n"), "\n"),
		strings.Split(strings.TrimRight(got, "\n"), "\n")) {
		t.Error(d)
	}
}

// renderPositions renders one stable line per finding. Sorted, so a change in
// scan or merge ORDER never shows up as a diff -- only a real change in what was
// found or where.
func renderPositions(t *testing.T, findings []analysis.Finding) string {
	t.Helper()
	rows := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Language != "javascript" {
			continue
		}
		rows = append(rows, fmt.Sprintf("%s|%s|%s|src=%s|sink=%s",
			f.RuleID, f.Function, f.SinkCallee, relPos(t, f.SourcePos), relPos(t, f.SinkPos)))
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n") + "\n"
}

// relPos renders a position repo-relative so the golden does not encode the
// absolute path of whoever ran the test.
func relPos(t *testing.T, p *ir.Position) string {
	t.Helper()
	if p == nil {
		return "-"
	}
	file := p.GetFilename()
	if abs, err := filepath.Abs("../.."); err == nil {
		if rel, err := filepath.Rel(abs, file); err == nil {
			file = rel
		}
	}
	return fmt.Sprintf("%s:%d:%d", filepath.ToSlash(file), p.GetLine(), p.GetColumn())
}

// diffLines reports lines present on only one side. Set-based rather than
// positional: one inserted finding would otherwise misalign the rest and bury
// the real change in noise.
func diffLines(want, got []string) []string {
	in := func(ss []string) map[string]bool {
		m := make(map[string]bool, len(ss))
		for _, s := range ss {
			m[s] = true
		}
		return m
	}
	w, g := in(want), in(got)
	var out []string
	for _, s := range want {
		if !g[s] {
			out = append(out, "lost:  "+s)
		}
	}
	for _, s := range got {
		if !w[s] {
			out = append(out, "added: "+s)
		}
	}
	return out
}
