package analysis

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/bytevet/godzilla/internal/irwalk"
	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/walkignore"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
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

// secretScan is one run of the secret scanner: the compiled detectors, the
// ruleID@position dedup set, the path-exclusion memo, and the findings so far.
type secretScan struct {
	dets []secretDetector
	// pre is every detector's pattern ORed into one alternation regexp, used as a
	// single-pass prefilter in text so the common no-match string pays one scan
	// instead of one per detector. Purely an optimization — a string that passes
	// still runs each detector's own regexp, which alone decides the match and
	// attributes it to its rule. nil (no detectors, or the union failed to
	// compile) means no prefilter, and the per-detector loop stands alone.
	pre      *regexp.Regexp
	seen     map[string]bool // ruleID@position, for dedup
	excluded map[string]bool // filename -> excluded, see pathExcluded
	findings []Finding
}

func newSecretScan(rs *rules.RuleSet) *secretScan {
	dets := secretDetectorsOf(rs)
	return &secretScan{
		dets:     dets,
		pre:      combinedDetectorRe(dets),
		seen:     map[string]bool{},
		excluded: map[string]bool{},
	}
}

// combinedDetectorRe ORs the detectors' patterns into one prefilter regexp.
// Each pattern is wrapped in a non-capturing group so inline flags like (?i)
// stay scoped to their own pattern. Returns nil when there is nothing to
// combine or the union does not compile (callers then skip the prefilter).
func combinedDetectorRe(dets []secretDetector) *regexp.Regexp {
	if len(dets) == 0 {
		return nil
	}
	parts := make([]string, len(dets))
	for i, d := range dets {
		parts[i] = "(?:" + d.re.String() + ")"
	}
	re, err := regexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		return nil
	}
	return re
}

// pathExcluded is secretPathExcluded memoized per filename: exclusion is a
// property of the FILE, but is asked once per string constant in the whole
// lowered dependency closure.
func (s *secretScan) pathExcluded(filename string) bool {
	if v, ok := s.excluded[filename]; ok {
		return v
	}
	v := secretPathExcluded(filename)
	s.excluded[filename] = v
	return v
}

// text runs every detector over a single string (a gIR constant or a line of a
// config file) and appends a Finding for each match, deduped by rule id and
// position. lang is "" for a config file, which has no language; a rule that
// declares `languages:` is then skipped, since it asked to be scoped to one.
func (s *secretScan) text(str string, pos *ir.Position, lang, fn string) {
	if str == "" || s.pathExcluded(pos.GetFilename()) {
		return
	}
	if s.pre != nil && !s.pre.MatchString(str) {
		return
	}
	for _, d := range s.dets {
		// Match BEFORE the language check: a miss is the common case and MatchString
		// is cheaper than AppliesTo's slice scan.
		if !d.re.MatchString(str) || !d.rule.AppliesTo(lang) {
			continue
		}
		key := d.rule.ID + "@" + posKey(pos)
		if s.seen[key] {
			continue
		}
		s.seen[key] = true
		s.findings = append(s.findings, Finding{
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

// ScanSecrets walks a gIR program for hardcoded secrets embedded in string
// constants, using rs's `kind: secret` rules. This is a non-dataflow,
// pattern-based analysis (distinct from the taint engine) and complements it in
// the same Finding stream.
func ScanSecrets(prog *ir.Program, rs *rules.RuleSet) []Finding {
	s := newSecretScan(rs)
	if prog == nil || len(s.dets) == 0 {
		return nil
	}
	for _, mod := range prog.Modules {
		if mod == nil {
			continue
		}
		for _, g := range mod.Globals {
			if g != nil {
				s.text(g.GetInitValue().GetStringVal(), g.GetPos(), mod.GetLanguage(), "")
			}
		}
	}
	for mod, fn := range irwalk.Funcs(prog) {
		// Exclusion is a property of the file, so testing it here skips an excluded
		// dependency's whole body. A function with no Pos falls through to the
		// per-string check in text.
		if s.pathExcluded(fn.GetPos().GetFilename()) {
			continue
		}
		lang, name := mod.GetLanguage(), fn.GetCanonicalName()
		for inst := range irwalk.Instrs(fn) {
			for _, op := range inst.GetOperands() {
				s.text(op.GetConstant().GetStringVal(), inst.GetPos(), lang, name)
			}
			if inst.Call != nil {
				for _, a := range inst.Call.GetArgs() {
					s.text(a.GetConstant().GetStringVal(), inst.GetPos(), lang, name)
				}
			}
		}
	}
	return s.findings
}

// secretFileMaxBytes caps how large a file the config scanner will read, so a
// huge data blob (a lockfile, a bundled asset) can't stall the scan.
const secretFileMaxBytes = 5 << 20 // 5 MiB

// ScanSecretsInFiles walks root for textual CONFIG files that the language
// frontends never parse — .env, docker-compose.yml, Dockerfile, CI YAML, .npmrc,
// .properties, Terraform, and the like — and applies the secret patterns line by
// line, reporting file:line positions. This covers a credential committed to a
// config file rather than source code, which the gIR-constant scanner
// (ScanSecrets) cannot see. Source files handled by a frontend are skipped to
// avoid double-reporting: isSource is the caller's REQUIRED "a language frontend
// handles this path" predicate (internal/scan derives it from its frontend table,
// the single source of truth for supported extensions). root may be a file or a
// directory; a non-existent path yields no findings.
func ScanSecretsInFiles(root string, rs *rules.RuleSet, isSource func(path string) bool) []Finding {
	info, err := os.Stat(root)
	if err != nil {
		return nil
	}
	paths := []string{root}
	if info.IsDir() {
		paths = paths[:0]
		_ = walkignore.Files(root, func(path string, d fs.DirEntry) error {
			paths = append(paths, path)
			return nil
		})
	}
	return ScanSecretsInPaths(paths, rs, isSource)
}

// ScanSecretsInPaths is ScanSecretsInFiles over an explicit, pre-walked file
// list — the scan pipeline's cached directory inventory (walkignore.Inventory)
// — so the config-file secrets pass adds no directory walk of its own. File
// selection is identical: same scannable-config predicate, same (required)
// isSource skip, same excluded-path and size policies, applied per file by
// scanConfigPath.
func ScanSecretsInPaths(paths []string, rs *rules.RuleSet, isSource func(path string) bool) []Finding {
	s := newSecretScan(rs)
	if len(s.dets) == 0 {
		return nil
	}
	for _, p := range paths {
		s.scanConfigPath(p, isSource)
	}
	return s.findings
}

// scanConfigPath applies the secret patterns line by line to one path, if it is
// a scannable config file: not handled by a language frontend (the caller's
// isSource predicate), not in an excluded tree, and under the size cap.
func (s *secretScan) scanConfigPath(path string, isSource func(path string) bool) {
	if isSource(path) {
		return
	}
	if !isScannableConfigFile(path) || s.pathExcluded(path) {
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
	lineNo := 0
	for line := range strings.SplitSeq(string(data), "\n") {
		lineNo++
		s.text(line, &ir.Position{Filename: path, Line: int32(lineNo), Column: 1}, "", "")
	}
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

// isScannableConfigFile reports whether path is a textual config/infra file the
// secret scanner should read. Source files a frontend handles are already
// filtered out by the caller's isSource predicate (scanConfigPath).
func isScannableConfigFile(path string) bool {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(base))
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
// These were the dominant secret-scan false positives on the real-world CVE
// benchmark: scanning them costs precision at the CI gate for no real signal.
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
