package report

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// SARIF 2.1.0 document structs. Only the fields Godzilla populates are
// modeled; everything else is omitted via omitempty so nil positions don't
// emit zero-value junk.

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Properties sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	CWE string `json:"cwe,omitempty"`
}

type sarifResult struct {
	RuleID              string                 `json:"ruleId"`
	RuleIndex           int                    `json:"ruleIndex"`
	Level               string                 `json:"level"`
	Message             sarifMessage           `json:"message"`
	Locations           []sarifLocation        `json:"locations,omitempty"`
	RelatedLocations    []sarifRelatedLocation `json:"relatedLocations,omitempty"`
	CodeFlows           []sarifCodeFlow        `json:"codeFlows,omitempty"`
	Suppressions        []sarifSuppression     `json:"suppressions,omitempty"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          sarifResultProperties  `json:"properties,omitempty"`
}

// sarifCodeFlow / threadFlow model the ordered source->sink taint path. GitHub
// code scanning renders a codeFlow as a navigable data-flow trace.
type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifLocation `json:"location"`
}

// sarifSuppression records that a result was suppressed downstream (here, by
// the LLM reviewer). SARIF consumers such as GitHub code scanning render a
// suppressed result as dismissed rather than an open alert, so the finding
// stays visible and auditable instead of vanishing.
type sarifSuppression struct {
	Kind          string `json:"kind"` // "external": suppressed outside the analysis tool proper
	Justification string `json:"justification,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifRelatedLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	Message          sarifMessage          `json:"message"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int32 `json:"startLine,omitempty"`
	StartColumn int32 `json:"startColumn,omitempty"`
}

type sarifResultProperties struct {
	Confidence string `json:"confidence,omitempty"`
	CWE        string `json:"cwe,omitempty"`
}

// WriteSARIF renders findings as a SARIF 2.1.0 document to w. Findings are
// sorted worst-severity-first, then by sink location, matching WriteHTML's
// ordering, so output is deterministic across runs.
func WriteSARIF(w io.Writer, findings []analysis.Finding) error {
	sorted := sortedFindings(findings)

	// Build the rules array: one entry per distinct rule ID, in order of
	// first appearance, and an index lookup for results.
	ruleIndex := make(map[string]int)
	sarifRules := make([]sarifRule, 0)
	for _, f := range sorted {
		if _, ok := ruleIndex[f.RuleID]; ok {
			continue
		}
		ruleIndex[f.RuleID] = len(sarifRules)
		sarifRules = append(sarifRules, sarifRule{
			ID:   f.RuleID,
			Name: f.RuleID,
			Properties: sarifRuleProperties{
				CWE: f.CWE,
			},
		})
	}

	results := make([]sarifResult, 0, len(sorted))
	for _, f := range sorted {
		result := sarifResult{
			RuleID:              f.RuleID,
			RuleIndex:           ruleIndex[f.RuleID],
			Level:               sarifLevel(f.Severity),
			Message:             sarifMessage{Text: f.Message},
			PartialFingerprints: map[string]string{"godzilla/v1": analysis.Fingerprint(f)},
			Properties: sarifResultProperties{
				Confidence: string(f.Confidence),
				CWE:        f.CWE,
			},
		}
		if loc, ok := sarifLocationFor(f.SinkPos); ok {
			result.Locations = []sarifLocation{loc}
		}
		if related, ok := sarifRelatedLocationFor(f.SourcePos); ok {
			result.RelatedLocations = []sarifRelatedLocation{related}
		}
		if cf, ok := sarifCodeFlowFor(f.Steps); ok {
			result.CodeFlows = []sarifCodeFlow{cf}
		}
		if f.Suppressed {
			result.Suppressions = []sarifSuppression{{Kind: "external", Justification: f.SuppressionReason}}
		}
		results = append(results, result)
	}

	doc := sarifDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Godzilla",
						InformationURI: "https://github.com/bytevet/godzilla",
						Rules:          sarifRules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// sarifLevel maps a rules.Severity to a SARIF result level: critical/high
// become "error", medium becomes "warning", low/info become "note", and
// anything unrecognized falls back to "none".
func sarifLevel(sev rules.Severity) string {
	switch rules.Severity(strings.ToLower(string(sev))) {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	case rules.SeverityLow, rules.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// sarifLocationFor builds a SARIF location from an *ir.Position, returning
// ok=false when pos is nil so callers can omit the location entirely.
func sarifLocationFor(pos *ir.Position) (sarifLocation, bool) {
	if pos == nil {
		return sarifLocation{}, false
	}
	return sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: sarifURI(pos.GetFilename())},
			Region: &sarifRegion{
				StartLine:   pos.GetLine(),
				StartColumn: pos.GetColumn(),
			},
		},
	}, true
}

// sarifURI normalizes a source filename into a SARIF artifactLocation URI.
// GitHub code scanning maps results to repository files by a path relative to
// the repo root, and silently drops results whose URI is an absolute local
// path (which the Go SSA frontend emits). Rewrite absolute paths to be
// relative to the working directory — the repo root in a CI checkout — and
// always use forward slashes, as the SARIF spec requires. Relative paths and
// paths that would escape the working directory (a "../" chain, which GitHub
// also rejects) are passed through unchanged.
func sarifURI(filename string) string {
	if filename == "" || !filepath.IsAbs(filename) {
		return filepath.ToSlash(filename)
	}
	if cwd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(cwd, filename); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(filename)
}

// sarifCodeFlowFor builds a SARIF codeFlow (one threadFlow) from the ordered
// taint-path positions. Returns ok=false when there are fewer than two mappable
// steps (nothing to render as a flow).
func sarifCodeFlowFor(steps []*ir.Position) (sarifCodeFlow, bool) {
	tfls := make([]sarifThreadFlowLocation, 0, len(steps))
	for _, p := range steps {
		if loc, ok := sarifLocationFor(p); ok {
			tfls = append(tfls, sarifThreadFlowLocation{Location: loc})
		}
	}
	if len(tfls) < 2 {
		return sarifCodeFlow{}, false
	}
	return sarifCodeFlow{ThreadFlows: []sarifThreadFlow{{Locations: tfls}}}, true
}

// sarifRelatedLocationFor builds a SARIF related location (used for the
// tainted source) from an *ir.Position, returning ok=false when pos is nil.
func sarifRelatedLocationFor(pos *ir.Position) (sarifRelatedLocation, bool) {
	loc, ok := sarifLocationFor(pos)
	if !ok {
		return sarifRelatedLocation{}, false
	}
	return sarifRelatedLocation{
		PhysicalLocation: loc.PhysicalLocation,
		Message:          sarifMessage{Text: "tainted source"},
	}, true
}
