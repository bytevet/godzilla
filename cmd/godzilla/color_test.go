package main

import (
	"strings"
	"testing"
	"time"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/rules"
)

// Off, every helper is the identity. That is the property the piped-output
// contract rests on: run_campaign.py and the CLI tests parse this text.
func TestStylerOffIsTheIdentity(t *testing.T) {
	var off styler
	const s = "coverage: go=ok, python=FAILED, ruby=PARTIAL(3/9 files)"
	for name, got := range map[string]string{
		"bold": off.bold(s), "dim": off.dim(s), "good": off.good(s), "bad": off.bad(s),
		"severity": off.severity(rules.SeverityCritical, s), "coverage": off.coverage(s),
	} {
		if got != s {
			t.Errorf("%s changed the text with colour off: %q", name, got)
		}
	}
}

// On, the text still reads the same once the escapes are stripped — colour is
// added around the grammar, never in place of it.
func TestStylerOnPreservesTheText(t *testing.T) {
	on := styler{on: true}
	const s = "coverage: go=ok, python=FAILED, ruby=PARTIAL(3/9 files)"
	got := on.coverage(s)
	if got == s {
		t.Fatal("colour was not applied")
	}
	if stripped := stripSGR(got); stripped != s {
		t.Errorf("colouring changed the text:\n got %q\nwant %q", stripped, s)
	}
	for _, v := range rules.Severities {
		if stripSGR(on.severity(v, "["+string(v)+"]")) != "["+string(v)+"]" {
			t.Errorf("severity %q: colouring changed the tag", v)
		}
	}
}

func stripSGR(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// The piped layout is a contract: the CLI tests, run_campaign.py and anything
// else reading a scan's stdout were written against these exact field labels.
// The terminal layout is free to change; this one is not.
func TestPipedFindingLayoutIsUnchanged(t *testing.T) {
	f := analysis.Finding{
		Severity: rules.SeverityHigh, RuleID: "go-sql-injection", CWE: "CWE-89",
		Confidence: analysis.ConfidenceHigh, Message: "Untrusted input flows into a query.",
		SinkCallee: "go:(*database/sql.DB).Query", Function: "go:example.Handler",
	}
	var b strings.Builder
	printFinding(&b, 1, 1, f, styler{})

	want := "[high] go-sql-injection (CWE-89, confidence: high)\n" +
		"  Untrusted input flows into a query.\n" +
		"  sink:   <unknown>  ->  go:(*database/sql.DB).Query\n" +
		"  source: <unknown>\n" +
		"  in:     go:example.Handler\n\n"
	if got := b.String(); got != want {
		t.Errorf("piped finding layout changed:\n got %q\nwant %q", got, want)
	}
}

// Wrapping is the interactive path only, and it must never lose a word.
func TestWrapPreservesEveryWord(t *testing.T) {
	const msg = "Untrusted input flows into a database/sql query without parameterized " +
		"arguments, which may allow SQL injection. Use placeholder parameters instead."
	if got := (styler{}).wrap(msg, 6); len(got) != 1 || got[0] != msg {
		t.Errorf("the piped layout must not wrap: %q", got)
	}
	lines := styler{rich: true, width: 60}.wrap(msg, 6)
	if len(lines) < 2 {
		t.Fatalf("nothing was wrapped: %q", lines)
	}
	for _, l := range lines {
		if n := len([]rune(l)); n > 54 {
			t.Errorf("line is %d columns, over the 54 available: %q", n, l)
		}
	}
	if strings.Join(lines, " ") != msg {
		t.Errorf("wrapping changed the text:\n%q", strings.Join(lines, " "))
	}
}

// Colour and layout are different questions. NO_COLOR on a real terminal turns
// painting off while the display keeps drawing — it has a colourless rung — so
// the report must still be laid out for the terminal, not printed in the shape
// tooling parses.
func TestLayoutDoesNotDependOnColour(t *testing.T) {
	plain := styler{rich: true, width: 80}
	var b strings.Builder
	printFinding(&b, 1, 1, analysis.Finding{
		Severity: rules.SeverityHigh, RuleID: "go-sql-injection", CWE: "CWE-89",
		Confidence: analysis.ConfidenceHigh, Message: "Untrusted input reaches a query.",
	}, plain)
	got := b.String()
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("colour leaked with painting off: %q", got)
	}
	if !strings.Contains(got, "1/1") {
		t.Errorf("the terminal layout was dropped along with the colour: %q", got)
	}
	if strings.Contains(got, "sink:   ") {
		t.Errorf("the piped layout was used on a terminal: %q", got)
	}
}

// The llm-review row must line up with report/coverage/exit, which all pad their
// label to 12 columns. The findings line above deliberately pads to 13, so eyeing
// the block is not enough to catch a drifted label — pin the column instead.
func TestSummaryLLMRowAlignsWithTheLabelledRows(t *testing.T) {
	var plain styler // colour off: the identity, so the text is the layout
	var b strings.Builder
	summary{
		st:     plain,
		counts: map[rules.Severity]int{rules.SeverityHigh: 1},
		total:  1,
		llm:    &llmSummary{provider: "claude", reviewed: 12, suppressed: 3, dur: 41200 * time.Millisecond},
		code:   3, reason: "findings at or above -fail-on=medium",
	}.write(&b)

	labelled := map[string]bool{"llm review": true, "coverage": true, "exit 3": true}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
		for k := range labelled {
			if !strings.HasPrefix(line, "  "+k) {
				continue
			}
			seen[k] = true
			// Two-space indent, then a label padded to exactly 12 columns, so every
			// value starts at column 14. Assert on the field itself rather than
			// searching for the value: a substring search finds column 14 whether or
			// not the padding is right, and would pass vacuously.
			if len(line) < 14 {
				t.Errorf("%q: row is shorter than the label field: %q", k, line)
				continue
			}
			if field := line[2:14]; strings.TrimRight(field, " ") != k || field[len(field)-1] != ' ' {
				t.Errorf("%q: label field is %q, want %q padded to 12 columns", k, field, k)
			}
		}
	}
	for k := range labelled {
		if !seen[k] {
			t.Errorf("summary did not render the %q row", k)
		}
	}
}

// The row states the provider, because "3 suppressed" means something different
// coming from a local CLI than from a frontier model over HTTP.
func TestSummaryLLMRowNamesTheProvider(t *testing.T) {
	got := llmSummary{provider: "claude", reviewed: 12, suppressed: 3, errors: 1,
		dur: 41200 * time.Millisecond}.line()
	for _, want := range []string{"claude", "12 reviewed", "3 suppressed", "1 error(s)", "41.2s"} {
		if !strings.Contains(got, want) {
			t.Errorf("llm row %q is missing %q", got, want)
		}
	}
}
