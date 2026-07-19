// Package report renders a slice of analysis.Finding values into a
// self-contained, standalone HTML document. The report has no external
// assets (CSS is inlined) and uses html/template so that untrusted content
// coming from analyzed source code (messages, callee names, code snippets,
// etc.) can never make the report itself vulnerable to XSS.
package report

import (
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"

	"html/template"
)

// severityOrder lists severities from worst to best; it drives both sort
// order and the fixed ordering of the summary table.
var severityOrder = []rules.Severity{
	rules.SeverityCritical,
	rules.SeverityHigh,
	rules.SeverityMedium,
	rules.SeverityLow,
	rules.SeverityInfo,
}

// confidenceOrder lists confidences from most to least certain.
var confidenceOrder = []analysis.Confidence{
	analysis.ConfidenceHigh,
	analysis.ConfidenceMedium,
	analysis.ConfidenceLow,
}

// snippetContext is how many lines of source to show before/after the
// highlighted line when rendering best-effort code context.
const snippetContext = 3

// WriteHTML renders findings as a complete standalone HTML document to w.
// Findings are sorted worst-severity-first, then by sink location. All
// finding-derived text is rendered through html/template, which
// context-escapes it, so the resulting report is safe to open in a browser
// even when findings embed attacker-controlled strings.
func WriteHTML(w io.Writer, findings []analysis.Finding) error {
	sorted := sortedFindings(findings)

	data := reportData{
		Title:            "Godzilla SAST Report",
		GeneratedAt:      time.Now().Format(time.RFC1123),
		Total:            len(sorted),
		SeverityCounts:   severityCounts(sorted),
		ConfidenceCounts: confidenceCounts(sorted),
	}
	for _, f := range sorted {
		data.Findings = append(data.Findings, newFindingView(f))
	}

	return reportTemplate.Execute(w, data)
}

// sortedFindings returns a copy of findings ordered worst-severity-first, then
// by sink location. All three report writers (HTML, JSON, SARIF) share this
// ordering so their output is deterministic and mutually consistent.
func sortedFindings(findings []analysis.Finding) []analysis.Finding {
	sorted := slices.Clone(findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := sorted[i].Severity.Rank(), sorted[j].Severity.Rank()
		if ri != rj {
			return ri > rj // worst (highest rank) first
		}
		return sinkSortKey(sorted[i]) < sinkSortKey(sorted[j])
	})
	return sorted
}

// sinkSortKey builds a comparable string key for ordering findings by sink
// location (filename, then line, then column) when severities tie.
func sinkSortKey(f analysis.Finding) string {
	p := f.SinkPos
	if p == nil {
		return "\xff\xff\xff" // sort unknown-location findings last within their severity
	}
	return fmt.Sprintf("%s:%09d:%09d", p.GetFilename(), p.GetLine(), p.GetColumn())
}

// reportData is the top-level structure fed to the HTML template.
type reportData struct {
	Title            string
	GeneratedAt      string
	Total            int
	SeverityCounts   []countRow
	ConfidenceCounts []countRow
	Findings         []findingView
}

// countRow is one row of a summary table: a label, its CSS badge class, and
// the finding count.
type countRow struct {
	Label string
	Class string
	Count int
}

// summaryRows tallies findings by a normalized string key and emits one
// countRow per value in order (fixed order, zeros included).
func summaryRows[T ~string](findings []analysis.Finding, order []T, keyOf func(analysis.Finding) T, class func(T) string) []countRow {
	counts := make(map[T]int, len(order))
	for _, f := range findings {
		counts[keyOf(f)]++
	}
	rows := make([]countRow, 0, len(order))
	for _, v := range order {
		rows = append(rows, countRow{
			Label: strings.ToUpper(string(v)),
			Class: class(v),
			Count: counts[v],
		})
	}
	return rows
}

func severityCounts(findings []analysis.Finding) []countRow {
	return summaryRows(findings, severityOrder,
		func(f analysis.Finding) rules.Severity { return normalizeSeverity(f.Severity) }, severityClass)
}

func confidenceCounts(findings []analysis.Finding) []countRow {
	return summaryRows(findings, confidenceOrder,
		func(f analysis.Finding) analysis.Confidence { return normalizeConfidence(f.Confidence) }, confidenceClass)
}

// findingView is the per-finding data made available to the template; it
// pre-formats everything so the template stays logic-free.
type findingView struct {
	SeverityLabel     string
	SeverityClass     string
	ConfidenceLabel   string
	ConfidenceClass   string
	RuleID            string
	CWE               string
	Message           string
	Function          string
	SinkCallee        string
	SinkLocation      string
	SourceLocation    string
	Snippet           *codeSnippet
	Suppressed        bool
	SuppressionReason string
}

func newFindingView(f analysis.Finding) findingView {
	// severityClass/confidenceClass normalize their input, so pass the raw values.
	return findingView{
		SeverityLabel:     strings.ToUpper(string(f.Severity)),
		SeverityClass:     severityClass(f.Severity),
		ConfidenceLabel:   strings.ToUpper(string(f.Confidence)),
		ConfidenceClass:   confidenceClass(f.Confidence),
		RuleID:            f.RuleID,
		CWE:               f.CWE,
		Message:           f.Message,
		Function:          f.Function,
		SinkCallee:        f.SinkCallee,
		SinkLocation:      formatPosition(f.SinkPos),
		SourceLocation:    formatPosition(f.SourcePos),
		Snippet:           buildSnippet(f.SinkPos),
		Suppressed:        f.Suppressed,
		SuppressionReason: f.SuppressionReason,
	}
}

// formatPosition renders an *ir.Position as "file:line:col", or "<unknown>"
// when pos is nil.
func formatPosition(pos *ir.Position) string {
	if pos == nil {
		return "<unknown>"
	}
	return fmt.Sprintf("%s:%d:%d", pos.GetFilename(), pos.GetLine(), pos.GetColumn())
}

// normalizeSeverity maps an arbitrary/unknown severity string down to one of
// the known rules.Severity values (lower-cased), defaulting to info so it
// still renders sensibly.
func normalizeSeverity(s rules.Severity) rules.Severity {
	lower := rules.Severity(strings.ToLower(string(s)))
	for _, known := range severityOrder {
		if lower == known {
			return known
		}
	}
	return rules.SeverityInfo
}

func normalizeConfidence(c analysis.Confidence) analysis.Confidence {
	lower := analysis.Confidence(strings.ToLower(string(c)))
	for _, known := range confidenceOrder {
		if lower == known {
			return known
		}
	}
	return analysis.ConfidenceLow
}

func severityClass(s rules.Severity) string {
	switch normalizeSeverity(s) {
	case rules.SeverityCritical:
		return "sev-critical"
	case rules.SeverityHigh:
		return "sev-high"
	case rules.SeverityMedium:
		return "sev-medium"
	case rules.SeverityLow:
		return "sev-low"
	default:
		return "sev-info"
	}
}

func confidenceClass(c analysis.Confidence) string {
	switch normalizeConfidence(c) {
	case analysis.ConfidenceHigh:
		return "conf-high"
	case analysis.ConfidenceMedium:
		return "conf-medium"
	default:
		return "conf-low"
	}
}

// codeSnippet holds a small window of source lines around a finding's sink,
// for best-effort inline display in the report.
type codeSnippet struct {
	Filename string
	Lines    []snippetLine
}

type snippetLine struct {
	Num       int32
	Text      string
	Highlight bool
}

// buildSnippet best-effort reads the source file named by pos and returns a
// window of ~snippetContext lines before/after the target line, with that
// line flagged for highlighting. It returns nil whenever the position is
// missing/invalid or the file cannot be read — code context is a nice-to-have,
// never a hard requirement.
func buildSnippet(pos *ir.Position) *codeSnippet {
	if pos == nil {
		return nil
	}
	filename := pos.GetFilename()
	target := pos.GetLine()
	if filename == "" || target <= 0 {
		return nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil
	}

	allLines := strings.Split(string(data), "\n")
	if int(target) > len(allLines) {
		return nil
	}

	startIdx := max(int(target)-1-snippetContext, 0)
	endIdx := min(int(target)-1+snippetContext, len(allLines)-1)

	lines := make([]snippetLine, 0, endIdx-startIdx+1)
	for i := startIdx; i <= endIdx; i++ {
		lineNum := int32(i + 1)
		lines = append(lines, snippetLine{
			Num:       lineNum,
			Text:      allLines[i],
			Highlight: lineNum == target,
		})
	}
	return &codeSnippet{Filename: filename, Lines: lines}
}

// reportTemplate is the full HTML document template. All dynamic values are
// inserted through html/template actions, which contextually auto-escape
// them, so untrusted content in findings cannot break out of its context.
var reportTemplate = template.Must(template.New("report").Parse(reportTemplateSrc))

const reportTemplateSrc = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
  :root {
    color-scheme: light dark;
    --sev-critical: #7f1d1d;
    --sev-high: #b91c1c;
    --sev-medium: #b45309;
    --sev-low: #1d4ed8;
    --sev-info: #4b5563;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 0 1.5rem 3rem;
    background: #0b0d10;
    color: #e5e7eb;
    line-height: 1.5;
  }
  header {
    padding: 2rem 0 1rem;
    border-bottom: 1px solid #2b2f36;
    margin-bottom: 1.5rem;
  }
  header h1 { margin: 0 0 0.25rem; font-size: 1.75rem; }
  header p { margin: 0; color: #9ca3af; font-size: 0.9rem; }
  h2 { font-size: 1.2rem; border-bottom: 1px solid #2b2f36; padding-bottom: 0.4rem; }
  section { margin-bottom: 2rem; }
  table { border-collapse: collapse; width: 100%; margin: 0.75rem 0 1.5rem; }
  table.summary-table { width: auto; min-width: 260px; margin-right: 2rem; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #1f2329; vertical-align: top; }
  th { color: #9ca3af; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em; }
  .summary-tables { display: flex; flex-wrap: wrap; gap: 1rem; }
  .badge {
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.02em;
    color: #fff;
  }
  .sev-critical { background: var(--sev-critical); }
  .sev-high { background: var(--sev-high); }
  .sev-medium { background: var(--sev-medium); }
  .sev-low { background: var(--sev-low); }
  .sev-info { background: var(--sev-info); }
  .conf-high { color: #22c55e; font-weight: 600; }
  .conf-medium { color: #eab308; font-weight: 600; }
  .conf-low { color: #9ca3af; font-weight: 600; }
  .loc { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem; color: #d1d5db; }
  .callee { color: #93c5fd; }
  pre.snippet {
    background: #14171c;
    border: 1px solid #2b2f36;
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
    margin-top: 0.5rem;
    overflow-x: auto;
    font-size: 0.8rem;
    line-height: 1.4;
  }
  pre.snippet .line { display: block; white-space: pre; }
  pre.snippet .line.hl { background: #402626; color: #fecaca; }
  tr.suppressed { opacity: 0.5; }
  .tag-suppressed { background: #4b5563; margin-left: 0.4rem; }
  .no-findings { color: #9ca3af; font-style: italic; }
  footer { color: #6b7280; font-size: 0.75rem; margin-top: 2rem; }
</style>
</head>
<body>
<header>
  <h1>Godzilla SAST Report</h1>
  <p>Generated {{.GeneratedAt}}</p>
</header>

<section class="summary">
  <h2>Summary</h2>
  <p>Total findings: <strong>{{.Total}}</strong></p>
  <div class="summary-tables">
    <table class="summary-table">
      <thead><tr><th>Severity</th><th>Count</th></tr></thead>
      <tbody>
      {{range .SeverityCounts}}
        <tr><td><span class="badge {{.Class}}">{{.Label}}</span></td><td>{{.Count}}</td></tr>
      {{end}}
      </tbody>
    </table>
    <table class="summary-table">
      <thead><tr><th>Confidence</th><th>Count</th></tr></thead>
      <tbody>
      {{range .ConfidenceCounts}}
        <tr><td>{{.Label}}</td><td>{{.Count}}</td></tr>
      {{end}}
      </tbody>
    </table>
  </div>
</section>

<section class="findings">
  <h2>Findings</h2>
  {{if not .Findings}}
    <p class="no-findings">No findings.</p>
  {{else}}
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Confidence</th>
        <th>Rule</th>
        <th>CWE</th>
        <th>Message</th>
        <th>Function</th>
        <th>Sink</th>
        <th>Source</th>
      </tr>
    </thead>
    <tbody>
    {{range .Findings}}
      <tr{{if .Suppressed}} class="suppressed"{{end}}>
        <td><span class="badge {{.SeverityClass}}">{{.SeverityLabel}}</span></td>
        <td><span class="{{.ConfidenceClass}}">{{.ConfidenceLabel}}</span></td>
        <td>{{.RuleID}}{{if .Suppressed}}<span class="badge tag-suppressed" title="{{.SuppressionReason}}">SUPPRESSED</span>{{end}}</td>
        <td>{{.CWE}}</td>
        <td>{{.Message}}</td>
        <td>{{.Function}}</td>
        <td>
          <div class="loc">{{.SinkLocation}} -&gt; <span class="callee">{{.SinkCallee}}</span></div>
          {{if .Snippet}}
          <pre class="snippet">{{range .Snippet.Lines}}<span class="line{{if .Highlight}} hl{{end}}">{{printf "%4d" .Num}}: {{.Text}}</span>
{{end}}</pre>
          {{end}}
        </td>
        <td class="loc">{{.SourceLocation}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}
</section>

<footer>Generated by Godzilla SAST.</footer>
</body>
</html>
`
