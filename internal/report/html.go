// Package report renders a slice of analysis.Finding values into a single
// HTML document whose only external reference is the Google Fonts stylesheet;
// it degrades to the system stack offline. Everything finding-derived comes from
// analyzed source code, so it is rendered through html/template's contextual
// auto-escaping — a report must never itself be XSS.
//
// The markup, styling and script are one embedded template file. The stylesheet
// and script are written out literally in it rather than injected, and neither
// carries finding data: the script reads only data-* attributes and textContent
// html/template already escaped. A strict per-render nonce CSP pins both inline
// tags, which is why nothing may be interpolated into either.
package report

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/scaninfo"
	"github.com/bytevet/godzilla/internal/srclines"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"

	"html/template"
)

//go:embed templates/report.html.tmpl
var reportTemplateSrc string

// The severity filter chips and the summary strip iterate rules.Severities
// rather than a local restatement, so a new severity cannot silently vanish from
// them. Confidence has no such treatment: its three levels are spelled out in
// the template's threshold picker and in the script, so a new one needs both
// edited by hand.

// snippetContext is how many lines of source to show before/after the
// highlighted line when rendering best-effort code context.
const snippetContext = 3

// HTMLOption configures a WriteHTML render.
type HTMLOption func(*htmlConfig)

type htmlConfig struct {
	info scaninfo.Info
}

// WithScanInfo supplies the pipeline telemetry behind the report's scan
// diagnostics section. Without it the section is omitted rather than rendered
// with zeros.
func WithScanInfo(info scaninfo.Info) HTMLOption {
	return func(c *htmlConfig) { c.info = info }
}

// WriteHTML renders findings as a complete standalone HTML document to w,
// sorted worst-severity-first then by sink location.
func WriteHTML(w io.Writer, findings []analysis.Finding, opts ...HTMLOption) error {
	var cfg htmlConfig
	for _, o := range opts {
		o(&cfg)
	}

	// The diagnostics panel reports how long the report itself took, which it
	// cannot do for a phase it is inside of. Time the half that actually costs
	// something — building the view model reads every finding's source file —
	// and report it as "report build"; template execution is the cheap half.
	start := time.Now()

	sorted := sortedFindings(findings)

	// Call-scoped, not package-global, so a later scan or test never observes
	// stale file contents.
	cache := srclines.Cache{}

	// Positions are rendered relative to the common project root so the report
	// shows "models/group.go:322" rather than an absolute scan path.
	root := commonRoot(sorted)

	total := len(sorted)
	counts, files := summarize(sorted)
	data := reportData{
		Generated:      time.Now().Format(time.RFC1123),
		Target:         displayTarget(cfg.info.Target, root),
		Nonce:          newNonce(),
		Root:           relativeRoot(root),
		Total:          total,
		SeverityCells:  severityCells(counts, total),
		Critical:       counts[string(rules.SeverityCritical)],
		High:           counts[string(rules.SeverityHigh)],
		FilesAffected:  files,
		SeverityFilter: severityFilters(),
		Rules:          ruleRows(sorted, total),
	}
	data.Findings = make([]findingView, 0, len(sorted))
	for _, f := range sorted {
		data.Findings = append(data.Findings, newFindingView(cache, root, f))
	}
	data.Diag = newDiagView(cfg.info, time.Since(start))

	return reportTemplate.Execute(w, data)
}

// newNonce returns a fresh 128-bit CSP nonce. The document's inline <style> and
// <script> are allowed by nonce alone, so it must be unpredictable and must
// never be reused across renders.
func newNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand cannot fail on any supported platform; if it somehow did,
		// a fixed nonce would silently weaken the CSP, so fail loudly instead.
		panic("report: crypto/rand: " + err.Error())
	}
	return base64.RawStdEncoding.EncodeToString(b[:])
}

// sortedFindings returns a copy of findings in the pipeline-wide display order
// (analysis.CompareFindings: worst severity first, then sink location, unknown
// locations last). All three report writers (HTML, JSON, SARIF) and the CLI's
// console listing share this ordering, so their output is deterministic and
// mutually consistent.
func sortedFindings(findings []analysis.Finding) []analysis.Finding {
	sorted := slices.Clone(findings)
	slices.SortStableFunc(sorted, analysis.CompareFindings)
	return sorted
}

// reportData is the top-level structure fed to the HTML template. Every value
// is pre-formatted here so the template stays logic-free — the package
// deliberately parses without a FuncMap.
type reportData struct {
	Generated string
	Target    string
	Nonce     string
	Root      string // the anchor locations are relative to, itself shown relative to cwd

	Total          int
	Critical, High int // the masthead verdict
	FilesAffected  int

	SeverityCells  []sevCell // the severity strip's cells, worst first
	SeverityFilter []severityFilter
	Rules          []ruleRow
	Findings       []findingView
	Diag           *diagView // nil when no scan telemetry was supplied
}

// sevCell is one cell of the summary strip: a severity, its count, and that
// count as a percent of the total for the cell's bar.
type sevCell struct {
	Key   string
	Count int
	Pct   int
}

// displayTarget names the scanned project in the masthead: the scan root when
// the caller knows it, else the findings' common directory, else the working
// directory. The fallback goes through relativeRoot for the same reason the
// footer does — it reaches the title, the heading and the masthead, so a caller
// that supplies no target would otherwise print the scanning machine's paths
// three more times.
func displayTarget(target, root string) string {
	if target != "" {
		// An absolute target is the caller's own argument, but `scan
		// "$GITHUB_WORKSPACE"` is an ordinary CI invocation, so echoing it puts the
		// runner's filesystem in the title. Relative-to-cwd where that says
		// something, else the directory's own name — which is what the reader
		// recognises anyway.
		if strings.HasPrefix(target, "/") {
			if rel := relativeRoot(target); rel != "" && rel != "." {
				return rel
			}
			return path.Base(target)
		}
		return target
	}
	if rel := relativeRoot(root); rel != "" {
		return rel
	}
	return "."
}

// pctOf is a count as a whole percent of total, for a summary bar's width. Zero
// total yields zero rather than dividing.
func pctOf(n, total int) int {
	if total <= 0 || n <= 0 {
		return 0
	}
	return n * 100 / total
}

// summarize walks the findings once for both headline figures: the per-severity
// tally (every known level present) and how many distinct files hold a sink.
func summarize(findings []analysis.Finding) (counts map[string]int, files int) {
	counts = make(map[string]int, len(rules.Severities))
	for _, s := range rules.Severities {
		counts[string(s)] = 0
	}
	seen := map[string]struct{}{}
	for _, f := range findings {
		counts[string(normalizeSeverity(f.Severity))]++
		if f.SinkPos != nil && f.SinkPos.GetFilename() != "" {
			seen[f.SinkPos.GetFilename()] = struct{}{}
		}
	}
	return counts, len(seen)
}

// severityCells lists the severities that get their own cell in the summary
// strip. Info is folded out: the strip is six cells wide and its wrap points
// are factors of six (6 -> 3+3 -> 2+2+2), so a seventh cell would leave a
// half-empty trailing row. Info findings are still counted, filterable and
// listed.
func severityCells(counts map[string]int, total int) []sevCell {
	out := make([]sevCell, 0, len(rules.Severities))
	for _, s := range rules.Severities {
		if s == rules.SeverityInfo {
			continue
		}
		n := counts[string(s)]
		out = append(out, sevCell{Key: string(s), Count: n, Pct: pctOf(n, total)})
	}
	return out
}

// severityFilter is one toggle in the filter bar.
type severityFilter struct {
	Key   string // data-sev value (lower-case severity)
	Label string
}

// sevAbbrev shortens the two labels that would not fit the filter chips.
var sevAbbrev = map[rules.Severity]string{
	rules.SeverityCritical: "CRIT",
	rules.SeverityMedium:   "MED",
}

func severityFilters() []severityFilter {
	out := make([]severityFilter, 0, len(rules.Severities))
	for _, s := range rules.Severities {
		label, ok := sevAbbrev[s]
		if !ok {
			label = strings.ToUpper(string(s))
		}
		out = append(out, severityFilter{Key: string(s), Label: label})
	}
	return out
}

// ruleRow is one row of the "findings by rule" summary table.
type ruleRow struct {
	Name        string
	CWE         string
	Count       int
	Pct         int    // Count as a percent of all findings, for the row's bar
	TopSeverity string // this rule's worst observed severity, colouring the row

	// sevRank is that same worst severity's rank, kept for the sort below.
	// Unexported, so html/template leaves it out of the rendered output.
	sevRank int
}

// ruleRows tallies findings per rule, worst severity first, then count desc,
// then rule id. Severity leads so the table reads in the same order as the
// findings list below it.
func ruleRows(findings []analysis.Finding, total int) []ruleRow {
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
			Name:        id,
			CWE:         a.cwe,
			Count:       a.count,
			Pct:         pctOf(a.count, total),
			TopSeverity: string(normalizeSeverity(a.bestSev)),
			sevRank:     a.bestSev.Rank(),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].sevRank != rows[j].sevRank {
			return rows[i].sevRank > rows[j].sevRank
		}
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}

// findingView is the per-finding data made available to the template; it
// pre-formats everything so the template stays logic-free.
type findingView struct {
	ID             string // element id, minus the "f-" prefix the template adds
	Severity       string // lower-case, the data-severity the script filters on
	SeverityLabel  string
	Confidence     string // lower-case, drives both data-conf and the 3-tick meter
	ConfidenceNote string // plain-language explanation of the confidence level
	Rule           string
	CWE            string
	Message        string
	Short          string // first sentence of Message, shown in the collapsed row
	SinkLoc        string
	SortKey        string // data-loc: zero-padded so line 9 sorts before line 10
	Function       string
	Callee         string
	Lex            string // data-lex, picks the highlighter's lexical family

	Flow              []flowStep
	FlowEndpointsOnly bool

	Suppressed        bool
	SuppressedBy      string
	SuppressionReason string
	ReviewConfirmed   bool
	ReviewNote        string
}

// flowStep is one position along the taint flow, rendered inside a nested
// <details>. Kind is always one of source/step/sink — the template expands
// everything that is not a "step". The snippet is best-effort.
type flowStep struct {
	Index   int
	Kind    string
	Loc     string
	Snippet *codeSnippet
}

func newFindingView(cache srclines.Cache, root string, f analysis.Finding) findingView {
	flow, endpointsOnly := buildFlow(cache, root, f)
	return findingView{
		ID:             analysis.Fingerprint(f),
		Severity:       string(normalizeSeverity(f.Severity)),
		SeverityLabel:  strings.ToUpper(string(normalizeSeverity(f.Severity))),
		Confidence:     string(normalizeConfidence(f.Confidence)),
		ConfidenceNote: confidenceNote(f.Confidence),
		Rule:           f.RuleID,
		CWE:            f.CWE,
		Message:        f.Message,
		Short:          firstSentence(f.Message),
		SinkLoc:        displayPos(root, f.SinkPos),
		SortKey:        sortKey(root, f.SinkPos),
		Function:       f.Function,
		Callee:         f.SinkCallee,
		Lex:            lexFamily(f.Language),

		Flow:              flow,
		FlowEndpointsOnly: endpointsOnly,

		Suppressed:        f.Suppressed,
		SuppressedBy:      f.SuppressedBy,
		SuppressionReason: f.SuppressionReason,
		ReviewConfirmed:   f.ReviewConfirmed,
		ReviewNote:        f.ReviewNote,
	}
}

// lexFamily maps a finding's language onto the lexical family the report's
// highlighter tokenizes with. Deciding it here rather than in the script is what
// keeps the script from guessing: the frontend names are known on this side, so
// the browser never needs a table of aliases and languages no frontend emits.
// An unlisted language falls back to the C-style lexer, which degrades to plain
// text at worst.
func lexFamily(language string) string {
	switch language {
	case "python", "ruby":
		return "hash" // # line comments, no block form
	default:
		return "c" // go, java, javascript, rust, c, cpp
	}
}

// firstSentence is the collapsed row's one-line summary. Rule messages lead
// with what happened and follow with the remediation, so the first sentence is
// the part worth showing before the reader opens the finding.
//
// A period ending a single-letter word is skipped: rule messages say "e.g." and
// "i.e.", and cutting there would leave a row reading "Use a placeholder (e.g.".
func firstSentence(msg string) string {
	for i := 0; i+1 < len(msg); i++ {
		if msg[i] != '.' || msg[i+1] != ' ' {
			continue
		}
		if i >= 2 && msg[i-2] == '.' {
			continue // ...g. of "e.g."
		}
		return msg[:i+1]
	}
	return msg
}

// sortKey is the data-loc the script sorts "by file" on. It compares as text
// (localeCompare), so the line and column are zero-padded — otherwise line 10
// would sort before line 9. An unknown position sorts last.
func sortKey(root string, pos *ir.Position) string {
	if pos == nil {
		return "~"
	}
	return fmt.Sprintf("%s:%06d:%06d", displayPath(root, pos.GetFilename()), pos.GetLine(), pos.GetColumn())
}

// buildFlow builds the taint flow. When the engine reconstructed an
// intra-procedural path (Finding.Steps), each step is a position along it;
// otherwise it falls back to the source and sink endpoints and flags the flow
// as endpoints-only.
func buildFlow(cache srclines.Cache, root string, f analysis.Finding) (steps []flowStep, endpointsOnly bool) {
	// kinds[i] labels position i as source/step/sink.
	var positions []*ir.Position
	var kinds []string
	if len(f.Steps) > 0 {
		positions = f.Steps
		kinds = make([]string, len(positions))
		for i := range kinds {
			kinds[i] = "step"
		}
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
			Index:   i + 1,
			Kind:    kinds[i],
			Loc:     displayPos(root, p),
			Snippet: buildSnippet(cache, p),
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

// relativeRoot renders the anchor the locations hang off, without naming the
// machine the scan ran on. commonRoot is absolute because the frontends emit
// absolute positions, and a report is routinely uploaded as a CI artifact or
// attached to a ticket — "/home/runner/work/repo/repo" tells that reader nothing
// and is the only part of the document that does not survive leaving the host.
//
// Anchoring is unaffected: displayPath still resolves against the real root, and
// this only changes how that directory is named. Falls back to the base name for
// a root outside the working directory, where a "../../.." chain would be worse
// than useless.
func relativeRoot(root string) string {
	if root == "" {
		return ""
	}
	wd, err := os.Getwd()
	if err != nil {
		return path.Base(root)
	}
	switch {
	case root == wd:
		return "."
	case strings.HasPrefix(root, wd+"/"):
		return root[len(wd)+1:]
	default:
		return path.Base(root)
	}
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
	for _, known := range rules.Severities {
		if lower == known {
			return known
		}
	}
	return rules.SeverityInfo
}

func normalizeConfidence(c analysis.Confidence) analysis.Confidence {
	lower := analysis.Confidence(strings.ToLower(string(c)))
	for _, known := range analysis.Confidences {
		if lower == known {
			return known
		}
	}
	return analysis.ConfidenceLow
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
// template file.
var reportTemplate = template.Must(template.New("report").Parse(reportTemplateSrc))
