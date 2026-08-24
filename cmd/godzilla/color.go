package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/scan"
)

// styler colours the findings report when stdout is an interactive terminal.
//
// It is deliberately its own decision, taken on STDOUT, rather than a byproduct
// of the progress display being up on stderr: `godzilla scan > report.txt` from
// a terminal must still write a plain file, and a scan whose stdout is a pipe —
// which is every CI invocation and every test — is byte for byte what it has
// always been.
//
// 16-colour SGR only. The report is read on whatever the user's terminal is,
// and there is no palette here worth a truecolor escape.
// on and rich are separate questions and must stay so. NO_COLOR on a real
// terminal turns colour OFF while the display keeps drawing — it has a
// colourless rung — so using "may I paint?" to decide the report's SHAPE would
// print the piped layout under a live TUI.
type styler struct {
	on    bool // may paint
	rich  bool // stdout is an interactive terminal: lay the report out for it
	width int  // terminal columns, for laying the message out; 0 when unknown
}

func (s styler) sgr(code, text string) string {
	if !s.on || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s styler) bold(text string) string { return s.sgr("1", text) }
func (s styler) dim(text string) string  { return s.sgr("90", text) }
func (s styler) good(text string) string { return s.sgr("32", text) }
func (s styler) bad(text string) string  { return s.sgr("31", text) }

// severity maps a finding's severity onto the usual traffic ordering, so the
// list can be triaged by colour before it is read.
func (s styler) severity(v rules.Severity, text string) string {
	switch v {
	case rules.SeverityCritical:
		return s.sgr("1;91", text)
	case rules.SeverityHigh:
		return s.sgr("91", text)
	case rules.SeverityMedium:
		return s.sgr("33", text)
	case rules.SeverityLow:
		return s.sgr("36", text)
	}
	return s.dim(text)
}

// coverage colours the per-language verdicts inside the summary line. The line's
// TEXT is untouched — run_campaign.py parses this grammar off piped stdout, and
// a pipe never gets here.
func (s styler) coverage(line string) string {
	if !s.on {
		return line
	}
	lang, rest, ok := strings.Cut(line, ": ")
	if !ok {
		return line
	}
	parts := strings.Split(rest, ", ")
	for i, p := range parts {
		name, status, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		paint := s.good
		switch {
		case status == "FAILED":
			paint = s.bad
		case strings.HasPrefix(status, "PARTIAL"):
			paint = func(t string) string { return s.sgr("33", t) }
		}
		parts[i] = s.dim(name+"=") + paint(status)
	}
	return s.dim(lang+": ") + strings.Join(parts, s.dim(", "))
}

// wrap breaks text onto lines of at most width columns, each continuation line
// carrying indent spaces. A finding's message is a paragraph — unwrapped, it is
// one 300-column line that the terminal folds at an arbitrary point with no
// indent, which is what makes a long report unreadable.
//
// Only the interactive path wraps. Piped output stays one line per field,
// because that is the shape anything parsing it was written against.
func (s styler) wrap(text string, indent int) []string {
	limit := s.width - indent
	if !s.rich || limit < 24 {
		return []string{text}
	}
	var lines []string
	cur := ""
	for _, word := range strings.Fields(text) {
		switch {
		case cur == "":
			cur = word
		case len([]rune(cur))+1+len([]rune(word)) <= limit:
			cur += " " + word
		default:
			lines = append(lines, cur)
			cur = word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// loc and callee separate the two halves of a data-flow line: where it is in
// the user's tree, and what it reaches. They are the two things a reader scans
// for, and undifferentiated they read as one long path.
func (s styler) loc(text string) string    { return s.sgr("36", text) }
func (s styler) callee(text string) string { return s.sgr("33", text) }

// summary is the block that closes an interactive run: what was found, where the
// report went, whether the scan actually covered the code, and the exit code
// WITH its reason.
//
// The exit code is spelled out because the CLI has four and a CI condition that
// treats any non-zero alike cannot tell a working gate from a broken scanner —
// 3 is "findings at or above -fail-on", 1 is "the scanner failed".
type summary struct {
	st       styler
	counts   map[rules.Severity]int
	total    int
	reports  []string
	coverage []scan.LangCoverage
	failed   []scan.LangCoverage // scan's own verdict, not a second reading of it
	rules    int
	langs    int
	code     int
	reason   string
}

func (s summary) write(w io.Writer) {
	label := func(k string) string { return s.st.dim(fmt.Sprintf("%-12s", k)) }

	if s.total == 0 {
		fmt.Fprintf(w, "  %s%s\n", s.st.good(fmt.Sprintf("%-13s", "no findings")),
			s.st.dim(fmt.Sprintf("%d rules over %d languages, all sinks clean", s.rules, s.langs)))
	} else {
		var parts []string
		for _, sev := range rules.Severities {
			if sev == rules.SeverityInfo {
				continue // the gate never turns on info; the strip stays four wide
			}
			n := s.counts[sev]
			text := fmt.Sprintf("%d %s", n, sev)
			if n == 0 {
				parts = append(parts, s.st.dim(text))
				continue
			}
			parts = append(parts, s.st.severity(sev, text))
		}
		fmt.Fprintf(w, "  %s%s\n",
			s.st.bad(fmt.Sprintf("%-13s", fmt.Sprintf("%d findings", s.total))), strings.Join(parts, "  "))
	}
	for _, r := range s.reports {
		fmt.Fprintf(w, "  %s%s\n", label("report"), s.st.loc(r))
	}

	// Coverage is repeated here on purpose: three findings from a scan that
	// skipped 47 Java files is a different claim from three from a clean scan.
	if line, clean := coverageLine(s.st, s.coverage, s.failed); clean {
		fmt.Fprintf(w, "  %s%s\n", label("coverage"), line)
	} else {
		fmt.Fprintf(w, "  %s%s\n", label("incomplete"), line)
	}
	fmt.Fprintf(w, "  %s%s\n", label(fmt.Sprintf("exit %d", s.code)), s.st.dim(s.reason))
}

// coverageLine names the languages that did not fully land, or says so when they
// all did. "No findings" is only trustworthy next to a statement of what was
// actually analysed.
func coverageLine(st styler, cov, failedCov []scan.LangCoverage) (string, bool) {
	// Which languages FAILED is scan's call — Result.Failed also gates -strict,
	// and a second reading of the same fields here could disagree with the exit
	// code the same run produces.
	failedSet := make(map[string]bool, len(failedCov))
	var failed []string
	for _, c := range failedCov {
		failedSet[c.Language] = true
		failed = append(failed, c.Language)
	}
	var partial []string
	var files, lowered int
	for _, c := range cov {
		files += c.Files
		lowered += c.Files - c.Skipped
		if !failedSet[c.Language] && c.Skipped > 0 {
			partial = append(partial, c.Language)
		}
	}
	if len(partial) == 0 && len(failed) == 0 {
		return st.good("complete") + st.dim(fmt.Sprintf(" — %d of %d files lowered", lowered, files)), true
	}
	out := strings.Join(partial, ", ")
	if len(failed) > 0 {
		if out != "" {
			out += " — "
		}
		out += st.bad(strings.Join(failed, ", ") + " failed")
	}
	return out, false
}
