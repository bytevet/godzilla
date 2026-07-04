package report

import (
	"encoding/json"
	"io"

	"godzilla/internal/analysis"
	ir "godzilla/pkg/ir/v1"
)

// Version is the tool version stamped into machine-readable reports (SARIF and
// JSON). The CLI sets it at startup (from -ldflags at build time); it defaults
// to "dev" so tests and un-stamped builds still produce valid output (CI-8).
var Version = "dev"

// jsonDocument is the top-level shape written by WriteJSON.
type jsonDocument struct {
	Tool string `json:"tool"`
	// ToolVersion and SchemaVersion let scripted consumers detect which binary
	// produced a report and pin against the JSON format's evolution.
	ToolVersion   string        `json:"toolVersion"`
	SchemaVersion string        `json:"schemaVersion"`
	Findings      []jsonFinding `json:"findings"`
}

// jsonFinding is the per-finding shape written by WriteJSON.
type jsonFinding struct {
	RuleID      string        `json:"ruleId"`
	Fingerprint string        `json:"fingerprint"`
	Severity    string        `json:"severity"`
	Confidence  string        `json:"confidence"`
	CWE         string        `json:"cwe"`
	Message     string        `json:"message"`
	Language    string        `json:"language"`
	Function    string        `json:"function"`
	SinkCallee  string        `json:"sinkCallee"`
	Source      *jsonLocation `json:"source"`
	Sink        *jsonLocation `json:"sink"`
	// Path is the ordered source->sink taint flow (when reconstructable).
	Path []*jsonLocation `json:"path,omitempty"`
	// Suppressed findings (judged false positives by the LLM reviewer) are
	// retained in the output, flagged, with the reviewer's reason — never
	// silently dropped.
	Suppressed        bool   `json:"suppressed,omitempty"`
	SuppressedBy      string `json:"suppressedBy,omitempty"`
	SuppressionReason string `json:"suppressionReason,omitempty"`
	// A finding the LLM reviewer KEPT is flagged confirmed with its reasoning,
	// so a developer sees the reviewer's exploitability note, not just drops.
	ReviewConfirmed bool   `json:"reviewConfirmed,omitempty"`
	ReviewNote      string `json:"reviewNote,omitempty"`
}

// jsonLocation mirrors an ir.Position for JSON output.
type jsonLocation struct {
	File   string `json:"file"`
	Line   int32  `json:"line"`
	Column int32  `json:"column"`
}

// WriteJSON renders findings as a single indented JSON document to w:
// {"tool":"godzilla","findings":[...]}. Findings are sorted worst-severity
// first, then by sink location, matching WriteHTML's ordering, so output is
// deterministic across runs.
func WriteJSON(w io.Writer, findings []analysis.Finding) error {
	sorted := sortedFindings(findings)

	doc := jsonDocument{
		Tool:          "godzilla",
		ToolVersion:   Version,
		SchemaVersion: "1",
		Findings:      make([]jsonFinding, 0, len(sorted)),
	}
	for _, f := range sorted {
		doc.Findings = append(doc.Findings, jsonFinding{
			RuleID:            f.RuleID,
			Fingerprint:       analysis.Fingerprint(f),
			Severity:          string(f.Severity),
			Confidence:        string(f.Confidence),
			CWE:               f.CWE,
			Message:           f.Message,
			Language:          f.Language,
			Function:          f.Function,
			SinkCallee:        f.SinkCallee,
			Source:            jsonLocationFor(f.SourcePos),
			Sink:              jsonLocationFor(f.SinkPos),
			Path:              jsonPathFor(f.Steps),
			Suppressed:        f.Suppressed,
			SuppressedBy:      f.SuppressedBy,
			SuppressionReason: f.SuppressionReason,
			ReviewConfirmed:   f.ReviewConfirmed,
			ReviewNote:        f.ReviewNote,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// jsonPathFor converts the taint-path positions to JSON locations, or nil when
// there is no multi-step path to report.
func jsonPathFor(steps []*ir.Position) []*jsonLocation {
	if len(steps) < 2 {
		return nil
	}
	out := make([]*jsonLocation, 0, len(steps))
	for _, p := range steps {
		out = append(out, jsonLocationFor(p))
	}
	return out
}

// jsonLocationFor converts an *ir.Position to a *jsonLocation, returning nil
// when pos is nil so the JSON field is explicitly null.
func jsonLocationFor(pos *ir.Position) *jsonLocation {
	if pos == nil {
		return nil
	}
	return &jsonLocation{
		File:   pos.GetFilename(),
		Line:   pos.GetLine(),
		Column: pos.GetColumn(),
	}
}
