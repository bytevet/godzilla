package analysis

import (
	"regexp"
	"strconv"

	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// secretCWE is CWE-798: Use of Hard-coded Credentials.
const secretCWE = "CWE-798"

// secretPattern is a high-signal detector for a hardcoded credential. Patterns
// are deliberately specific (fixed prefixes / structural markers) rather than
// entropy-based, to keep the signal/noise ratio high for a CI gate.
type secretPattern struct {
	id       string
	re       *regexp.Regexp
	severity rules.Severity
	message  string
}

var secretPatterns = []secretPattern{
	{"secret-private-key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), rules.SeverityCritical, "Hardcoded private key"},
	{"secret-aws-access-key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), rules.SeverityHigh, "Hardcoded AWS access key ID"},
	{"secret-gcp-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), rules.SeverityHigh, "Hardcoded Google API key"},
	{"secret-slack-token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,48}\b`), rules.SeverityHigh, "Hardcoded Slack token"},
	{"secret-github-token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36}\b`), rules.SeverityHigh, "Hardcoded GitHub token"},
	{"secret-jwt", regexp.MustCompile(`\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b`), rules.SeverityMedium, "Hardcoded JSON Web Token"},
}

// ScanSecrets walks a gIR program for hardcoded secrets embedded in string
// constants. This is a non-dataflow, pattern-based analysis (distinct from the
// taint engine) and complements it in the same Finding stream.
func ScanSecrets(prog *ir.Program) []Finding {
	var findings []Finding
	if prog == nil {
		return findings
	}

	seen := map[string]bool{} // dedupe by patternID@position
	for _, mod := range prog.Modules {
		if mod == nil {
			continue
		}
		lang := mod.GetLanguage()

		for _, g := range mod.Globals {
			if g == nil {
				continue
			}
			scanConstant(g.GetInitValue(), g.GetPos(), lang, "", seen, &findings)
		}

		for _, fn := range mod.Functions {
			if fn == nil {
				continue
			}
			for _, blk := range fn.Blocks {
				if blk == nil {
					continue
				}
				for _, inst := range blk.Instrs {
					if inst == nil {
						continue
					}
					for _, op := range inst.GetOperands() {
						scanConstant(op.GetConstant(), inst.GetPos(), lang, fn.GetCanonicalName(), seen, &findings)
					}
					if inst.Call != nil {
						for _, a := range inst.Call.GetArgs() {
							scanConstant(a.GetConstant(), inst.GetPos(), lang, fn.GetCanonicalName(), seen, &findings)
						}
					}
				}
			}
		}
	}
	return findings
}

func scanConstant(c *ir.Constant, pos *ir.Position, lang, fn string, seen map[string]bool, findings *[]Finding) {
	if c == nil {
		return
	}
	s := c.GetStringVal()
	if s == "" {
		return
	}
	for _, p := range secretPatterns {
		if !p.re.MatchString(s) {
			continue
		}
		key := p.id + "@" + posKey(pos)
		if seen[key] {
			continue
		}
		seen[key] = true
		*findings = append(*findings, Finding{
			RuleID:     p.id,
			Severity:   p.severity,
			Confidence: ConfidenceHigh,
			CWE:        secretCWE,
			Message:    p.message,
			Language:   lang,
			Function:   fn,
			SourcePos:  pos,
			SinkPos:    pos,
		})
	}
}

func posKey(p *ir.Position) string {
	if p == nil {
		return "?"
	}
	return p.GetFilename() + ":" + strconv.Itoa(int(p.GetLine())) + ":" + strconv.Itoa(int(p.GetColumn()))
}
