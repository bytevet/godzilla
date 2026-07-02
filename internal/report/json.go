package report

import (
	"encoding/json"
	"io"
	"sort"

	"godzilla/internal/analysis"
	ir "godzilla/pkg/ir/v1"
)

// jsonDocument is the top-level shape written by WriteJSON.
type jsonDocument struct {
	Tool     string        `json:"tool"`
	Findings []jsonFinding `json:"findings"`
}

// jsonFinding is the per-finding shape written by WriteJSON.
type jsonFinding struct {
	RuleID     string        `json:"ruleId"`
	Severity   string        `json:"severity"`
	Confidence string        `json:"confidence"`
	CWE        string        `json:"cwe"`
	Message    string        `json:"message"`
	Language   string        `json:"language"`
	Function   string        `json:"function"`
	SinkCallee string        `json:"sinkCallee"`
	Source     *jsonLocation `json:"source"`
	Sink       *jsonLocation `json:"sink"`
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
	sorted := make([]analysis.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := sorted[i].Severity.Rank(), sorted[j].Severity.Rank()
		if ri != rj {
			return ri > rj // worst (highest rank) first
		}
		return sinkSortKey(sorted[i]) < sinkSortKey(sorted[j])
	})

	doc := jsonDocument{
		Tool:     "godzilla",
		Findings: make([]jsonFinding, 0, len(sorted)),
	}
	for _, f := range sorted {
		doc.Findings = append(doc.Findings, jsonFinding{
			RuleID:     f.RuleID,
			Severity:   string(f.Severity),
			Confidence: string(f.Confidence),
			CWE:        f.CWE,
			Message:    f.Message,
			Language:   f.Language,
			Function:   f.Function,
			SinkCallee: f.SinkCallee,
			Source:     jsonLocationFor(f.SourcePos),
			Sink:       jsonLocationFor(f.SinkPos),
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
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
