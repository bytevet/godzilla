package corpus

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bytevet/godzilla/internal/analysis"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// The position golden pins the EXACT source and sink line/column of every
// corpus finding, one file per language.
//
// expected.yaml asserts rule counts, and only a handful of samples carry a
// `line:`. That leaves a systematic position shift — an off-by-one column, a
// line-terminator the index does not recognise — passing the corpus silently
// while every reported location is wrong. Positions are the part of a finding a
// human acts on, so they get an assertion of their own. Ruby shipped a
// zero-based column for its whole life; this is what would have caught it.
//
// Rows are keyed by sample, so a language whose toolchain is missing simply
// contributes nothing and the rest still assert. Rendering piggybacks on
// TestCorpus's scans — the oracle costs no extra work.
//
// Regenerate deliberately after a change that is MEANT to move positions, then
// read the diff line by line. Regeneration lives in TestRegenerateManifests, so
// that this gate can only ever assert: one that rewrites its own oracle when an
// env var is set reports green on exactly the run that was supposed to show you
// the damage.
//
//	GODZILLA_REGEN=1 go test ./test/corpus/ -run RegenerateManifests
func goldenPositions(lang string) string {
	return filepath.Join("testdata", "positions", lang+".golden")
}

// posCollector accumulates one rendered row per finding as the corpus is
// scanned, grouped by language.
type posCollector struct {
	rows map[string][]string // language -> rows
	seen map[string][]string // language -> samples actually scanned
}

func newPosCollector() *posCollector {
	return &posCollector{rows: map[string][]string{}, seen: map[string][]string{}}
}

// langOf maps a sample name ("ruby/rails_query_sqli") to its language.
func langOf(sample string) string { return strings.SplitN(sample, "/", 2)[0] }

func (p *posCollector) add(t *testing.T, sample string, findings []analysis.Finding) {
	lang := langOf(sample)
	p.seen[lang] = append(p.seen[lang], sample)
	for _, f := range findings {
		p.rows[lang] = append(p.rows[lang], fmt.Sprintf("%s|%s|%s|%s|src=%s|sink=%s",
			sample, f.RuleID, f.Function, f.SinkCallee, relPos(t, f.SourcePos), relPos(t, f.SinkPos)))
	}
}

// assert compares each language's rows against its golden, restricted to the
// samples that were actually scanned: a skipped sample must neither fail the
// gate nor let a golden row for it go unchecked forever.
func (p *posCollector) assert(t *testing.T) {
	t.Helper()
	for lang, scanned := range p.seen {
		t.Run("positions/"+lang, func(t *testing.T) {
			want, err := os.ReadFile(goldenPositions(lang))
			if err != nil {
				t.Fatalf("read golden: %v (regenerate with GODZILLA_REGEN=1)", err)
			}
			got := p.rows[lang]
			sort.Strings(got)
			for _, d := range diffLines(rowsFor(splitRows(string(want)), scanned), got) {
				t.Error(d)
			}
		})
	}
}

// rowsFor keeps the golden rows belonging to the given samples.
func rowsFor(rows, samples []string) []string {
	want := make(map[string]bool, len(samples))
	for _, s := range samples {
		want[s] = true
	}
	var out []string
	for _, r := range rows {
		if want[strings.SplitN(r, "|", 2)[0]] {
			out = append(out, r)
		}
	}
	return out
}

func splitRows(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// writeGoldens rewrites each language's golden, keeping the rows of samples this
// run did not scan. Dropping them would silently retire the oracle for every
// language whose toolchain the regenerating machine happens to lack.
func (p *posCollector) writeGoldens(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(goldenPositions("x")), 0o755); err != nil {
		t.Fatal(err)
	}
	for lang, scanned := range p.seen {
		path := goldenPositions(lang)
		old, _ := os.ReadFile(path)
		keep := make(map[string]bool, len(scanned))
		for _, s := range scanned {
			keep[s] = true
		}
		rows := p.rows[lang]
		for _, r := range splitRows(string(old)) {
			if !keep[strings.SplitN(r, "|", 2)[0]] {
				rows = append(rows, r)
			}
		}
		sort.Strings(rows)
		body := ""
		if len(rows) > 0 {
			body = strings.Join(rows, "\n") + "\n"
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d rows)", path, len(rows))
	}
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
