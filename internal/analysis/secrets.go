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

// secretDetector is one compiled `kind: secret` rule. Collected once per scan so
// the per-constant loop does not re-filter the whole rule set, and so a rule
// whose regexp failed to compile is dropped up front rather than silently
// matching nothing on every string.
type secretDetector struct {
	rule *rules.Rule
	re   *regexp.Regexp
}

// secretDetectorsOf returns the compiled secret rules in rs. Call rs.Compile
// first; a rule that declares `matches` it could not compile is skipped (the
// loader already reported it).
func secretDetectorsOf(rs *rules.RuleSet) []secretDetector {
	if rs == nil {
		return nil
	}
	var ds []secretDetector
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if !r.IsSecret() {
			continue
		}
		if re := r.MatchesRe(); re != nil {
			ds = append(ds, secretDetector{rule: r, re: re})
		}
	}
	return ds
}

// ScanSecrets walks a gIR program for hardcoded secrets embedded in string
// constants, using rs's `kind: secret` rules. This is a non-dataflow,
// pattern-based analysis (distinct from the taint engine) and complements it in
// the same Finding stream.
func ScanSecrets(prog *ir.Program, rs *rules.RuleSet) []Finding {
	var findings []Finding
	dets := secretDetectorsOf(rs)
	if prog == nil || len(dets) == 0 {
		return findings
	}

	seen := map[string]bool{} // dedupe by ruleID@position
	for _, mod := range prog.Modules {
		if mod == nil {
			continue
		}
		for _, g := range mod.Globals {
			if g == nil {
				continue
			}
			scanConstant(g.GetInitValue(), g.GetPos(), mod.GetLanguage(), "", dets, seen, &findings)
		}
	}
	for mod, fn := range funcs(prog) {
		lang, name := mod.GetLanguage(), fn.GetCanonicalName()
		for inst := range instrs(fn) {
			for _, op := range inst.GetOperands() {
				scanConstant(op.GetConstant(), inst.GetPos(), lang, name, dets, seen, &findings)
			}
			if inst.Call != nil {
				for _, a := range inst.Call.GetArgs() {
					scanConstant(a.GetConstant(), inst.GetPos(), lang, name, dets, seen, &findings)
				}
			}
		}
	}
	return findings
}

func scanConstant(c *ir.Constant, pos *ir.Position, lang, fn string, dets []secretDetector, seen map[string]bool, findings *[]Finding) {
	if c == nil {
		return
	}
	scanText(c.GetStringVal(), pos, lang, fn, dets, seen, findings)
}

// scanText runs every secret detector over a single string (a gIR constant or a
// line of a config file) and appends a Finding for each match, deduped by rule
// id and position. lang is "" for a config file, which has no language; a rule
// that declares `languages:` is then skipped, since it asked to be scoped to
// one.
func scanText(s string, pos *ir.Position, lang, fn string, dets []secretDetector, seen map[string]bool, findings *[]Finding) {
	if s == "" || secretPathExcluded(pos.GetFilename()) {
		return
	}
	for _, d := range dets {
		// Match BEFORE the language check: a miss is the overwhelmingly common case
		// and MatchString is cheaper than AppliesTo's slice scan, so testing the
		// regexp first keeps the rare-hit path from paying for the filter.
		if !d.re.MatchString(s) || !d.rule.AppliesTo(lang) {
			continue
		}
		key := d.rule.ID + "@" + posKey(pos)
		if seen[key] {
			continue
		}
		seen[key] = true
		*findings = append(*findings, Finding{
			RuleID:     d.rule.ID,
			Severity:   d.rule.Severity,
			Confidence: ParseConfidence(d.rule.Confidence, ConfidenceHigh),
			CWE:        d.rule.CWE,
			Message:    d.rule.Message,
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
func ScanSecretsInFiles(root string, rs *rules.RuleSet) []Finding {
	var findings []Finding
	dets := secretDetectorsOf(rs)
	if len(dets) == 0 {
		return findings
	}
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
			scanText(line, pos, "", "", dets, seen, &findings)
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

	_ = walkignore.Files(root, func(path string, d fs.DirEntry) error {
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
	case lower == ".pypirc": // .npmrc/.netrc are matched earlier via configFileExts
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
