// Package report renders a slice of analysis.Finding values into a
// self-contained, standalone HTML document. The report has no external
// assets (CSS and JS are inlined) and uses html/template so that untrusted
// content coming from analyzed source code (messages, callee names, code
// snippets, etc.) can never make the report itself vulnerable to XSS.
//
// The document's markup, styling, and filter script live in separate source
// files under templates/ and are compiled into the binary with go:embed; the
// CSS/JS are static (they carry no finding data) and are injected into the
// single template as template.CSS/template.JS typed values, so they emit
// verbatim while every finding-derived value stays contextually auto-escaped.
package report

import (
	_ "embed"
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

//go:embed templates/report.html.tmpl
var reportTemplateSrc string

//go:embed templates/report.css
var reportCSS string

//go:embed templates/report.js
var reportJS string

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

	// A per-call cache so a source file shared by many findings/steps is read
	// off disk once. Kept call-scoped (not package-global) so a later scan or
	// test never observes stale file contents.
	cache := snippetCache{}

	data := reportData{
		Title:          "Godzilla SAST Report",
		GeneratedAt:    time.Now().Format(time.RFC1123),
		Total:          len(sorted),
		Tiles:          summaryTiles(sorted),
		ByRule:         ruleRows(sorted),
		SeverityFilter: severityFilters(),
		CSS:            template.CSS(reportCSS),
		JS:             template.JS(reportJS),
	}
	for _, f := range sorted {
		data.Findings = append(data.Findings, newFindingView(cache, f))
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
	Title          string
	GeneratedAt    string
	Total          int
	Tiles          []tile
	ByRule         []ruleRow
	SeverityFilter []severityFilter
	Findings       []findingView
	CSS            template.CSS
	JS             template.JS
}

// tile is one summary stat card.
type tile struct {
	Label string
	Count int
	Class string // optional severity class for coloring the number
	Lead  bool   // the headline tile (accent-colored)
}

// summaryTiles derives the headline stat cards from the findings.
func summaryTiles(findings []analysis.Finding) []tile {
	bySev := map[rules.Severity]int{}
	files := map[string]struct{}{}
	for _, f := range findings {
		bySev[normalizeSeverity(f.Severity)]++
		if f.SinkPos != nil && f.SinkPos.GetFilename() != "" {
			files[f.SinkPos.GetFilename()] = struct{}{}
		}
	}
	return []tile{
		{Label: "Total findings", Count: len(findings), Lead: true},
		{Label: "Critical", Count: bySev[rules.SeverityCritical], Class: "sev-critical"},
		{Label: "High", Count: bySev[rules.SeverityHigh], Class: "sev-high"},
		{Label: "Medium", Count: bySev[rules.SeverityMedium], Class: "sev-medium"},
		{Label: "Low / Info", Count: bySev[rules.SeverityLow] + bySev[rules.SeverityInfo], Class: "sev-low"},
		{Label: "Files affected", Count: len(files)},
	}
}

// severityFilter is one toggle in the filter bar.
type severityFilter struct {
	Key   string // data-sev value (lower-case severity)
	Label string
	Class string
}

func severityFilters() []severityFilter {
	out := make([]severityFilter, 0, len(severityOrder))
	for _, s := range severityOrder {
		out = append(out, severityFilter{
			Key:   string(s),
			Label: strings.ToUpper(string(s)),
			Class: severityClass(s),
		})
	}
	return out
}

// ruleRow is one row of the "findings by rule" summary table.
type ruleRow struct {
	RuleID   string
	CWE      string
	Count    int
	SevClass string // chip/text class of this rule's worst observed severity
}

// ruleRows tallies findings per rule, ordered by count desc, then worst
// severity first, then rule id — a deterministic order that also keeps the
// rule ids appearing in severity order for the severity-ordering test.
func ruleRows(findings []analysis.Finding) []ruleRow {
	type agg struct {
		cwe     string
		count   int
		bestSev int
	}
	byRule := map[string]*agg{}
	for _, f := range findings {
		a := byRule[f.RuleID]
		if a == nil {
			a = &agg{cwe: f.CWE}
			byRule[f.RuleID] = a
		}
		a.count++
		if r := normalizeSeverity(f.Severity).Rank(); r > a.bestSev {
			a.bestSev = r
		}
		if a.cwe == "" {
			a.cwe = f.CWE
		}
	}
	rows := make([]ruleRow, 0, len(byRule))
	for id, a := range byRule {
		rows = append(rows, ruleRow{
			RuleID:   id,
			CWE:      a.cwe,
			Count:    a.count,
			SevClass: severityClass(rules.Severity(rankSeverity(a.bestSev))),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		// Tie-break by worst severity (so rule ids also appear in severity
		// order), then rule id for determinism.
		si, sj := sevRankOfClass(rows[i].SevClass), sevRankOfClass(rows[j].SevClass)
		if si != sj {
			return si > sj
		}
		return rows[i].RuleID < rows[j].RuleID
	})
	return rows
}

// rankSeverity maps a 1..5 rank back to its severity string.
func rankSeverity(rank int) string {
	switch rank {
	case 5:
		return string(rules.SeverityCritical)
	case 4:
		return string(rules.SeverityHigh)
	case 3:
		return string(rules.SeverityMedium)
	case 2:
		return string(rules.SeverityLow)
	default:
		return string(rules.SeverityInfo)
	}
}

// sevRankOfClass returns the severity rank encoded by a "sev-*" css class.
func sevRankOfClass(class string) int {
	switch class {
	case "sev-critical":
		return 5
	case "sev-high":
		return 4
	case "sev-medium":
		return 3
	case "sev-low":
		return 2
	default:
		return 1
	}
}

// findingView is the per-finding data made available to the template; it
// pre-formats everything so the template stays logic-free.
type findingView struct {
	SeverityLabel     string
	SeverityClass     string
	SevKey            string
	ConfidenceLabel   string
	ConfidenceClass   string
	ConfKey           string
	RuleID            string
	CWE               string
	Message           string
	Language          string
	Function          string
	SinkCallee        string
	SinkLocation      string
	SourceLocation    string
	SourceSnippet     *codeSnippet
	SinkSnippet       *codeSnippet
	Flow              []flowStep
	HasFlow           bool
	FlowEndpointsOnly bool
	AnchorID          string
	Suppressed        bool
	SuppressionReason string
	ReviewConfirmed   bool
	ReviewNote        string
}

// flowStep is one position along the taint spread flow. The snippet is
// best-effort and rendered inside a nested, collapsed <details>.
type flowStep struct {
	Index    int
	Kind     string // "source", "sink", or "" for intermediate steps
	Location string
	Snippet  *codeSnippet
}

func newFindingView(cache snippetCache, f analysis.Finding) findingView {
	flow, endpointsOnly := buildFlow(cache, f)
	return findingView{
		SeverityLabel:     strings.ToUpper(string(f.Severity)),
		SeverityClass:     severityClass(f.Severity),
		SevKey:            string(normalizeSeverity(f.Severity)),
		ConfidenceLabel:   strings.ToUpper(string(f.Confidence)),
		ConfidenceClass:   confidenceClass(f.Confidence),
		ConfKey:           string(normalizeConfidence(f.Confidence)),
		RuleID:            f.RuleID,
		CWE:               f.CWE,
		Message:           f.Message,
		Language:          f.Language,
		Function:          f.Function,
		SinkCallee:        f.SinkCallee,
		SinkLocation:      analysis.PosString(f.SinkPos),
		SourceLocation:    analysis.PosString(f.SourcePos),
		SourceSnippet:     buildSnippet(cache, f.SourcePos),
		SinkSnippet:       buildSnippet(cache, f.SinkPos),
		Flow:              flow,
		HasFlow:           len(flow) > 0,
		FlowEndpointsOnly: endpointsOnly,
		AnchorID:          "f-" + analysis.Fingerprint(f),
		Suppressed:        f.Suppressed,
		SuppressionReason: f.SuppressionReason,
		ReviewConfirmed:   f.ReviewConfirmed,
		ReviewNote:        f.ReviewNote,
	}
}

// buildFlow builds the taint spread flow. When the engine reconstructed an
// intra-procedural path (Finding.Steps), each step is a position along it;
// otherwise it falls back to the source and sink endpoints and flags the flow
// as endpoints-only.
func buildFlow(cache snippetCache, f analysis.Finding) (steps []flowStep, endpointsOnly bool) {
	positions := f.Steps
	if len(positions) == 0 {
		endpointsOnly = true
		if f.SourcePos != nil {
			positions = append(positions, f.SourcePos)
		}
		if f.SinkPos != nil {
			positions = append(positions, f.SinkPos)
		}
	}
	steps = make([]flowStep, 0, len(positions))
	for i, p := range positions {
		kind := ""
		if i == 0 {
			kind = "source"
		}
		if i == len(positions)-1 && len(positions) > 1 {
			kind = "sink"
		}
		steps = append(steps, flowStep{
			Index:    i + 1,
			Kind:     kind,
			Location: analysis.PosString(p),
			Snippet:  buildSnippet(cache, p),
		})
	}
	return steps, endpointsOnly
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

// snippetCache memoizes source-file line reads across the many snippets a
// single report renders. A nil entry records an unreadable file so we don't
// retry it.
type snippetCache map[string][]string

func (c snippetCache) lines(filename string) ([]string, bool) {
	if v, ok := c[filename]; ok {
		return v, v != nil
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		c[filename] = nil
		return nil, false
	}
	lines := strings.Split(string(data), "\n")
	c[filename] = lines
	return lines, true
}

// codeSnippet holds a small window of source lines around a finding position,
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
func buildSnippet(cache snippetCache, pos *ir.Position) *codeSnippet {
	if pos == nil {
		return nil
	}
	filename := pos.GetFilename()
	target := pos.GetLine()
	if filename == "" || target <= 0 {
		return nil
	}

	allLines, ok := cache.lines(filename)
	if !ok {
		return nil
	}
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

// reportTemplate is the full HTML document template, parsed from the embedded
// template file. All dynamic values are inserted through html/template
// actions, which contextually auto-escape them, so untrusted content in
// findings cannot break out of its context.
var reportTemplate = template.Must(template.New("report").Parse(reportTemplateSrc))
