package analysis

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"godzilla/internal/rules"
	"godzilla/internal/walkignore"
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
	{"secret-slack-webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{20,}`), rules.SeverityHigh, "Hardcoded Slack webhook URL"},
	{"secret-github-token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36}\b`), rules.SeverityHigh, "Hardcoded GitHub token"},
	{"secret-gitlab-pat", regexp.MustCompile(`\bglpat-[0-9A-Za-z_-]{20}\b`), rules.SeverityHigh, "Hardcoded GitLab personal access token"},
	{"secret-jwt", regexp.MustCompile(`\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b`), rules.SeverityMedium, "Hardcoded JSON Web Token"},
	{"secret-stripe-key", regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b`), rules.SeverityHigh, "Hardcoded Stripe live secret key"},
	{"secret-openai-anthropic-key", regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b`), rules.SeverityHigh, "Hardcoded OpenAI/Anthropic-style API key"},
	{"secret-npm-token", regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}\b`), rules.SeverityHigh, "Hardcoded npm access token"},
	{"secret-sendgrid-key", regexp.MustCompile(`\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b`), rules.SeverityHigh, "Hardcoded SendGrid API key"},
	{"secret-square-token", regexp.MustCompile(`\bsq0(?:atp|csp)-[0-9A-Za-z_-]{22,43}\b`), rules.SeverityHigh, "Hardcoded Square access token"},
	{"secret-db-connection", regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:@/]+:[^\s:@/]{3,}@`), rules.SeverityHigh, "Hardcoded database credentials in connection URL"},
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
	scanText(c.GetStringVal(), pos, lang, fn, seen, findings)
}

// scanText runs every secret pattern over a single string (a gIR constant or a
// line of a config file) and appends a Finding for each match, deduped by
// pattern id and position.
func scanText(s string, pos *ir.Position, lang, fn string, seen map[string]bool, findings *[]Finding) {
	if s == "" {
		return
	}
	if secretPathExcluded(pos.GetFilename()) {
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

// secretFileMaxBytes caps how large a file the config scanner will read, so a
// huge data blob (a lockfile, a bundled asset) can't stall the scan.
const secretFileMaxBytes = 5 << 20 // 5 MiB

// ScanSecretsInFiles walks root for textual CONFIG files that the language
// frontends never parse — .env, docker-compose.yml, Dockerfile, CI YAML,
// .npmrc, .properties, Terraform, and the like — and applies the secret
// patterns line by line, reporting file:line positions. This closes the biggest
// secret-leak vector: a credential committed to a config file rather than
// source code, which the gIR-constant scanner (ScanSecrets) cannot see. Source
// files handled by a frontend are skipped here (their string literals are
// already covered by ScanSecrets) to avoid double-reporting. root may be a file
// or a directory; a non-existent path yields no findings.
func ScanSecretsInFiles(root string) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	scanFile := func(path string) {
		if secretPathExcluded(path) {
			return
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() > secretFileMaxBytes {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		for i, line := range strings.Split(string(data), "\n") {
			pos := &ir.Position{Filename: path, Line: int32(i + 1), Column: 1}
			scanText(line, pos, "", "", seen, &findings)
		}
	}

	info, err := os.Stat(root)
	if err != nil {
		return findings
	}
	if !info.IsDir() {
		if isScannableConfigFile(root) {
			scanFile(root)
		}
		return findings
	}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if walkignore.SkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if isScannableConfigFile(path) {
			scanFile(path)
		}
		return nil
	})
	return findings
}

// configFileExts and configFileNames enumerate the textual config/infra files
// worth scanning for hardcoded secrets. Kept deliberately narrow (not "every
// text file") to bound cost and noise.
var configFileExts = map[string]bool{
	".env": true, ".yaml": true, ".yml": true, ".json": true, ".toml": true,
	".ini": true, ".cfg": true, ".conf": true, ".properties": true,
	".tf": true, ".tfvars": true, ".sh": true, ".bash": true, ".zsh": true,
	".xml": true, ".txt": true, ".pem": true, ".key": true, ".npmrc": true, ".netrc": true,
}

// sourceFileExts are handled by a language frontend, whose string literals the
// gIR-constant scanner already covers; skip them here to avoid double-reporting.
var sourceFileExts = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".java": true,
	".rs": true, ".c": true, ".cc": true, ".cpp": true, ".cxx": true, ".h": true, ".hpp": true,
}

// isScannableConfigFile reports whether path is a textual config/infra file the
// secret scanner should read.
func isScannableConfigFile(path string) bool {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(base))
	if sourceFileExts[ext] {
		return false
	}
	if configFileExts[ext] {
		return true
	}
	// Extensionless / specially-named infra files.
	lower := strings.ToLower(base)
	switch {
	case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile."):
		return true
	case strings.HasPrefix(lower, "docker-compose"):
		return true
	case strings.HasPrefix(lower, ".env"): // .env, .env.local, .env.production
		return true
	case lower == ".npmrc" || lower == ".netrc" || lower == ".pypirc":
		return true
	}
	return false
}

// secretExtraExcludedSegments are path segments the shared walk-exclusion policy
// (internal/walkignore) does NOT prune but whose files are, by construction, full
// of example/placeholder credentials rather than real leaks. Two kinds:
//   - vendored dependency trees walkignore.SkipDir can't match on a single path
//     segment: the Go module cache (go/pkg/mod) and Ruby's bundler dir; and
//   - directories that DO hold first-party source (so the walk keeps them) yet
//     whose credential-shaped strings are fixture/example/translation data.
//
// The real-world CVE benchmark showed these were the dominant secret-scan false
// positives — example JWTs in an OpenAPI schema, connection-string-shaped values
// in translation JSON, an SSH cert inside a vendored crypto library. Scanning them
// costs precision at the CI gate for no real signal.
//
// The vendored/build/venv/cache directories walkignore already prunes are handled
// by reusing walkignore.SkipDir below (single source of truth) rather than being
// re-listed here.
var secretExtraExcludedSegments = []string{
	"/go/pkg/mod/", "/.bundle/",
	"/fixtures/", "/fixture/", "/__tests__/", "/__mocks__/", "/testdata/",
	"/translations/", "/locales/", "/locale/", "/lc_messages/",
}

// secretPathExcluded reports whether the secret scanner should skip a file by
// path (a vendored dependency, build output, test fixture, i18n bundle, or API
// schema).
func secretPathExcluded(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	// Single source of truth for vendored/build/venv/cache directories: any dir
	// the source walk prunes is likewise not first-party source worth
	// secret-scanning. Reusing walkignore.SkipDir means a new frontend that
	// teaches walkignore a skip-dir gets secret-exclusion for free — no parallel
	// list to maintain. (The file-tree walk never even descends into these, but
	// the gIR-constant scanner can see a lowered dependency's file path, so the
	// check still matters here.)
	for _, seg := range strings.Split(lower, "/") {
		if seg != "" && walkignore.SkipDir(seg) {
			return true
		}
	}
	for _, seg := range secretExtraExcludedSegments {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	base := filepath.Base(lower)
	switch {
	case strings.HasPrefix(base, "swagger.") || strings.HasPrefix(base, "openapi."):
		return true // OpenAPI schemas are full of example credentials
	case strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.HasSuffix(base, "_test.go"):
		return true // unit-test files carry fixture secrets, not leaks
	}
	return false
}

func posKey(p *ir.Position) string {
	if p == nil {
		return "?"
	}
	return p.GetFilename() + ":" + strconv.Itoa(int(p.GetLine())) + ":" + strconv.Itoa(int(p.GetColumn()))
}
