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
	"path"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	"godzilla/internal/srclines"
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
	cache := srclines.Cache{}

	// Positions are rendered relative to the common project root so the report
	// shows "models/group.go:322" rather than an absolute scan path.
	root := commonRoot(sorted)

	data := reportData{
		Title:          "Godzilla SAST Report",
		GeneratedAt:    time.Now().Format(time.RFC1123),
		Total:          len(sorted),
		Root:           root,
		Tiles:          summaryTiles(sorted),
		ByRule:         ruleRows(sorted),
		SeverityFilter: severityFilters(),
		CSS:            template.CSS(reportCSS),
		JS:             template.JS(reportJS),
	}
	for _, f := range sorted {
		data.Findings = append(data.Findings, newFindingView(cache, root, f))
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
	Root           string // common path prefix stripped from displayed locations
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

	// sevRank is that same worst severity's rank, kept for the sort below.
	// Unexported: html/template never reads unexported fields, so it stays out
	// of the rendered output while sparing the comparator a class-string ->
	// rank decode of a value we already had.
	sevRank int
}

// ruleRows tallies findings per rule, ordered by count desc, then worst
// severity first, then rule id — a deterministic order that also keeps the
// rule ids appearing in severity order for the severity-ordering test.
func ruleRows(findings []analysis.Finding) []ruleRow {
	type agg struct {
		cwe     string
		count   int
		bestSev rules.Severity
	}
	byRule := map[string]*agg{}
	for _, f := range findings {
		a := byRule[f.RuleID]
		if a == nil {
			a = &agg{cwe: f.CWE}
			byRule[f.RuleID] = a
		}
		a.count++
		if s := normalizeSeverity(f.Severity); s.Rank() > a.bestSev.Rank() {
			a.bestSev = s
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
			SevClass: severityClass(a.bestSev),
			sevRank:  a.bestSev.Rank(),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		// Tie-break by worst severity (so rule ids also appear in severity
		// order), then rule id for determinism.
		if rows[i].sevRank != rows[j].sevRank {
			return rows[i].sevRank > rows[j].sevRank
		}
		return rows[i].RuleID < rows[j].RuleID
	})
	return rows
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
	ConfidenceNote    string // plain-language explanation of the confidence level
	RuleID            string
	CWE               string
	Message           string
	Language          string
	Function          string
	SinkCallee        string
	SinkLocation      string
	Flow              []flowStep
	HasFlow           bool
	FlowEndpointsOnly bool
	AnchorID          string
	Suppressed        bool
	SuppressionReason string
	ReviewConfirmed   bool
	ReviewNote        string
}

// flowStep is one position along the taint spread flow, rendered inside a
// nested <details>. The endpoints (source and sink) are expanded by default
// (Open); intermediate steps stay collapsed. The snippet is best-effort.
type flowStep struct {
	Index    int
	Kind     string // "source", "sink", or "" for intermediate steps
	Open     bool   // expand this step's snippet by default (source/sink)
	Location string
	Snippet  *codeSnippet
}

func newFindingView(cache srclines.Cache, root string, f analysis.Finding) findingView {
	flow, endpointsOnly := buildFlow(cache, root, f)
	return findingView{
		SeverityLabel:     strings.ToUpper(string(f.Severity)),
		SeverityClass:     severityClass(f.Severity),
		SevKey:            string(normalizeSeverity(f.Severity)),
		ConfidenceLabel:   strings.ToUpper(string(f.Confidence)),
		ConfidenceClass:   confidenceClass(f.Confidence),
		ConfKey:           string(normalizeConfidence(f.Confidence)),
		ConfidenceNote:    confidenceNote(f.Confidence),
		RuleID:            f.RuleID,
		CWE:               f.CWE,
		Message:           f.Message,
		Language:          f.Language,
		Function:          f.Function,
		SinkCallee:        f.SinkCallee,
		SinkLocation:      displayPos(root, f.SinkPos),
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
func buildFlow(cache srclines.Cache, root string, f analysis.Finding) (steps []flowStep, endpointsOnly bool) {
	// kinds[i] labels position i as source/sink/intermediate. The endpoints are
	// expanded (Open) by default; intermediate steps stay collapsed.
	var positions []*ir.Position
	var kinds []string
	if len(f.Steps) > 0 {
		positions = f.Steps
		kinds = make([]string, len(positions))
		kinds[0] = "source"
		if len(positions) > 1 {
			kinds[len(positions)-1] = "sink"
		}
	} else {
		endpointsOnly = true
		// Label by role, not index, so a finding with only a sink (e.g. a
		// dangerous-call finding with no source) is never mislabeled "source".
		if f.SourcePos != nil {
			positions = append(positions, f.SourcePos)
			kinds = append(kinds, "source")
		}
		if f.SinkPos != nil {
			positions = append(positions, f.SinkPos)
			kinds = append(kinds, "sink")
		}
	}
	steps = make([]flowStep, 0, len(positions))
	for i, p := range positions {
		steps = append(steps, flowStep{
			Index:    i + 1,
			Kind:     kinds[i],
			Open:     kinds[i] != "", // expand the source and sink endpoints
			Location: displayPos(root, p),
			Snippet:  buildSnippet(cache, p),
		})
	}
	return steps, endpointsOnly
}

// confidenceNote returns a short plain-language explanation of a confidence
// level, so the report never shows a bare "MEDIUM" the reader must decode.
func confidenceNote(c analysis.Confidence) string {
	switch normalizeConfidence(c) {
	case analysis.ConfidenceHigh:
		return "intra-procedural source → sink flow"
	case analysis.ConfidenceMedium:
		return "flow crosses a function boundary (interprocedural)"
	default:
		return ""
	}
}

// commonRoot returns the longest common directory prefix shared by the
// findings' source/sink/step file paths, so the report can render locations
// relative to the scanned project instead of as long absolute paths. Go module
// cache paths (third-party dependency sources) are excluded from the
// computation and shortened separately by displayPath.
func commonRoot(findings []analysis.Finding) string {
	var common []string
	have := false
	consider := func(p *ir.Position) {
		if p == nil {
			return
		}
		fn := p.GetFilename()
		if fn == "" || strings.Contains(fn, "/pkg/mod/") {
			return
		}
		segs := strings.Split(fn, "/")
		segs = segs[:len(segs)-1] // directory segments only (drop basename)
		if !have {
			common = segs
			have = true
			return
		}
		n := 0
		for n < len(common) && n < len(segs) && common[n] == segs[n] {
			n++
		}
		common = common[:n]
	}
	for _, f := range findings {
		consider(f.SourcePos)
		consider(f.SinkPos)
		for _, s := range f.Steps {
			consider(s)
		}
	}
	if !have || len(common) == 0 {
		return ""
	}
	return strings.Join(common, "/")
}

// displayPath renders filename relative to root; a Go module-cache path becomes
// a short "dep: <module@version>/..." form; anything outside root is returned
// unchanged.
func displayPath(root, filename string) string {
	if filename == "" {
		return ""
	}
	if i := strings.LastIndex(filename, "/pkg/mod/"); i >= 0 {
		return "dep: " + filename[i+len("/pkg/mod/"):]
	}
	if root != "" {
		if filename == root {
			return path.Base(filename)
		}
		if strings.HasPrefix(filename, root+"/") {
			return filename[len(root)+1:]
		}
	}
	return filename
}

// displayPos formats a position as "path:line:col" with path shortened via
// displayPath, or "<unknown>" when pos is nil.
func displayPos(root string, pos *ir.Position) string {
	if pos == nil {
		return "<unknown>"
	}
	return fmt.Sprintf("%s:%d:%d", displayPath(root, pos.GetFilename()), pos.GetLine(), pos.GetColumn())
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

// codeSnippet holds a small window of source lines around a finding position,
// for best-effort inline display in the report.
type codeSnippet struct {
	Lines []snippetLine
}

type snippetLine struct {
	Num       int32
	Text      string
	Highlight bool
	Caret     string // for the highlighted line: whitespace prefix + "^" pointing at the column
}

// caretFor builds a compiler-style pointer line for a 1-based byte column: a
// whitespace prefix (tabs preserved so it aligns under a tab-indented line)
// followed by "^". Returns "" when col is unknown. One prefix char per source
// rune keeps the caret aligned in the monospace <pre>.
func caretFor(line string, col int32) string {
	if col <= 0 {
		return ""
	}
	n := int(col) - 1
	if n > len(line) {
		n = len(line)
	}
	var b strings.Builder
	consumed := 0
	for _, r := range line {
		if consumed >= n {
			break
		}
		if r == '\t' {
			b.WriteByte('\t')
		} else {
			b.WriteByte(' ')
		}
		consumed += utf8.RuneLen(r)
	}
	b.WriteByte('^')
	return b.String()
}

// buildSnippet best-effort reads the source file named by pos and returns a
// window of ~snippetContext lines before/after the target line, with that
// line flagged for highlighting. It returns nil whenever the position is
// missing/invalid or the file cannot be read — code context is a nice-to-have,
// never a hard requirement.
func buildSnippet(cache srclines.Cache, pos *ir.Position) *codeSnippet {
	if pos == nil {
		return nil
	}
	filename := pos.GetFilename()
	target := pos.GetLine()
	if filename == "" || target <= 0 {
		return nil
	}

	allLines, ok := cache.Lines(filename)
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
		line := snippetLine{
			Num:       lineNum,
			Text:      allLines[i],
			Highlight: lineNum == target,
		}
		if line.Highlight {
			line.Caret = caretFor(allLines[i], pos.GetColumn())
		}
		lines = append(lines, line)
	}
	return &codeSnippet{Lines: lines}
}

// reportTemplate is the full HTML document template, parsed from the embedded
// template file. All dynamic values are inserted through html/template
// actions, which contextually auto-escape them, so untrusted content in
// findings cannot break out of its context.
var reportTemplate = template.Must(template.New("report").Parse(reportTemplateSrc))
