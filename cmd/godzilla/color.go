package main

import (
	"strings"

	"github.com/bytevet/godzilla/internal/rules"
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
type styler struct {
	on    bool
	width int // terminal columns, for laying the message out; 0 when unknown
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
	if !s.on || limit < 24 {
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
