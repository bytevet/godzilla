// Package scan is the importable scan pipeline shared by the CLI and the test
// corpus. It lowers source at a path to gIR (dispatching to the right language
// frontend, or all present frontends for a directory) and runs the taint engine
// plus the hardcoded-secrets scanner over the result. Keeping this out of
// package main lets tests exercise exactly the same code path the CLI runs.
package scan

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	cpp_converter "github.com/bytevet/godzilla/converters/cpp"
	go_converter "github.com/bytevet/godzilla/converters/go"
	java_converter "github.com/bytevet/godzilla/converters/java"
	js_converter "github.com/bytevet/godzilla/converters/javascript"
	py_converter "github.com/bytevet/godzilla/converters/python"
	ruby_converter "github.com/bytevet/godzilla/converters/ruby"
	rust_converter "github.com/bytevet/godzilla/converters/rust"
	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/memlimit"
	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/scaninfo"
	"github.com/bytevet/godzilla/internal/walkignore"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// LangCoverage records what happened to one language frontend during a scan:
// whether its source was Detected in the target, whether the frontend
// successfully Converted it, and the error if it did not. It exists so a caller
// (the CI gate) can tell "analyzed and clean" apart from "never analyzed" — a
// frontend/build/type-check failure must not masquerade as a clean result.
type LangCoverage struct {
	Language  string
	Detected  bool
	Converted bool
	Err       string
	// Files is how many source files of this language the walk found, and Skipped
	// how many of them the frontend could not lower. Converted is all-or-nothing
	// and so hides a PARTIAL failure: a frontend that lowers three files out of two
	// hundred still reports ok. Skipped is 0 for a frontend whose unit of work is
	// not a file (Go lowers packages), so 0 means "nothing known to be dropped",
	// not a guarantee.
	Files   int
	Skipped int
	// Degraded marks a frontend that ran to completion but at reduced depth: a Go
	// dependency closure trimmed to fit the source-byte budget, whose excluded
	// packages get bodyless SSA instead of lowered bodies. DegradedNote names the
	// counts.
	//
	// Deliberately NOT Converted=false. Converted=false means "never analyzed",
	// which puts the entry in Failed() and fails -strict; a degraded scan RAN and
	// produced findings, so it stays Converted=true and the gate passes. Reporting
	// it as a failure would fail every scan the budget rescued from being
	// OOM-killed — the opposite of what the budget is for.
	Degraded     bool
	DegradedNote string
}

// LanguageOf reports which frontend claims path, off the same languageFrontends
// table the scan dispatches on. ok is false when no frontend handles it — which
// is the difference between a file that was skipped and one that is not code.
func LanguageOf(path string) (lang string, ok bool) {
	name, conv := fileFrontend(path)
	return name, conv != nil
}

// CoverageSummary renders a one-line per-language coverage summary, so a
// degraded scan — a frontend that failed on detected source, or one that
// silently dropped part of it — is visible even when the run is not strict.
// Empty when no language was detected. It lives here rather than in a command
// because both binaries print it and the wording is the thing that must agree.
func CoverageSummary(coverage []LangCoverage) string {
	if len(coverage) == 0 {
		return ""
	}
	parts := make([]string, 0, len(coverage))
	for _, c := range coverage {
		status := "ok"
		switch {
		case !c.Converted:
			status = "FAILED"
		case c.Degraded:
			// The frontend ran and its findings hold; the dependency closure behind
			// them was trimmed to fit the memory budget. Distinct from FAILED, which
			// alone fails -strict.
			status = "DEGRADED"
		case c.Skipped > 0:
			// The frontend ran, so the language is not "failed", yet some of its
			// source never reached the engine. The ratio is what distinguishes a
			// scan that dropped most of a project from a genuinely clean one.
			status = fmt.Sprintf("PARTIAL(%d/%d files)", c.Files-c.Skipped, c.Files)
		}
		parts = append(parts, fmt.Sprintf("%s=%s", c.Language, status))
	}
	return "coverage: " + strings.Join(parts, ", ")
}

// Result is the outcome of scanning a path.
type Result struct {
	Findings []analysis.Finding
	Program  *ir.Program
	// Coverage reports, per language present in the target, whether that
	// frontend actually converted its source. A Detected-but-not-Converted entry
	// means findings for that language are missing because analysis failed, not
	// because the code is clean.
	Coverage []LangCoverage
	// Diag is scan telemetry for the HTML report's diagnostics section. It is
	// observational only: nothing in the pipeline reads it back.
	Diag scaninfo.Info
	// Sources lists the files the walk handed the frontends, under the same
	// selection policy they lower. Populated only under WithSources.
	Sources []string
}

// sourcesOf returns the walked source list only when it was asked for:
// WithDiagnostics computes the same slice for its line count, and handing that
// back too would make Sources present-or-absent depend on an unrelated option.
func sourcesOf(cfg config, srcFiles []string) []string {
	if !cfg.sources {
		return nil
	}
	return srcFiles
}

// Option configures a scan.
type Option func(*config)

type config struct {
	diagnostics, sources bool
	// depBudget caps the total source bytes of third-party dependency packages a
	// dep-lowering frontend may load as syntax roots; negative is unlimited.
	depBudget int64
}

// WithDiagnostics collects the telemetry behind the HTML report's scan
// diagnostics panel. Off by default: it is a second read pass over the source
// for the line count, plus a glob of every distinct callee against every rule,
// and nothing but that panel reads it — a gate run, `rules test` over every
// sample, and the corpus loop would all pay for a number they discard.
func WithDiagnostics() Option {
	return func(c *config) { c.diagnostics = true }
}

// WithDepBudget caps the total source bytes of third-party dependency packages
// the Go frontend promotes to syntax roots; the remainder is loaded as export
// data (bodyless SSA), so taint stops at those signatures instead of flowing
// through them. sourceBytes < 0 is unlimited. See DefaultDepBudget for the
// memory-derived figure the CLI passes.
func WithDepBudget(sourceBytes int64) Option {
	return func(c *config) { c.depBudget = sourceBytes }
}

// WithSources retains the list of source files the walk handed the frontends,
// in Result.Sources. Off by default for the same reason as WithDiagnostics: it
// is a selection pass nothing on the gate path reads. A caller that wants to
// know which files produced no gIR needs it, and asking here is far cheaper
// than walking the tree a second time — on a large repo that second walk is
// seconds, and it stats every entry.
func WithSources() Option {
	return func(c *config) { c.sources = true }
}

func newConfig(opts []Option) config {
	c := config{depBudget: -1} // unlimited unless a caller sets one
	for _, o := range opts {
		o(&c)
	}
	return c
}

// rssPerSourceByte is how much peak resident memory one byte of third-party Go
// source costs once it is promoted to a syntax root and lowered to SSA.
//
// A CONSERVATIVE ENVELOPE, not a fit. Measured across eight whole-repo and
// subpackage scans, the cost is superlinear in promoted bytes (log-log slope
// ~1.5), and two closures of the same 30 MB differ 2.8x in peak — declaration
// density is the real driver and source bytes cannot see it. A least-squares
// slope would therefore under-predict exactly where the budget has to hold. 512
// is 1.33x the worst uncensored measurement (384, a gogs subpackage at 10.9 GiB);
// anything below 384 is known-optimistic for a dependency set of that shape.
//
// Re-measure with .claude/skills/cve-recall/scripts/measure_peak_rss.py, which
// sizes the closure exactly as the frontend does. Raising this number loosens
// the budget: it is the divisor.
const rssPerSourceByte = 512

// depClosureShare is the fraction of available memory the dependency closure may
// claim. The rest covers the user code's own SSA, the engine's taint state, and
// the runtime's non-heap overhead — none of which this budget bounds.
const depClosureShare = 0.5

// DefaultDepBudget returns the dependency source-byte budget that fits the
// memory this process may use, or -1 (unlimited) when available memory cannot
// be detected — a host memlimit cannot read keeps today's behaviour rather than
// inheriting a guess.
func DefaultDepBudget() int64 {
	avail := memlimit.Available()
	if avail <= 0 {
		return -1
	}
	return int64(float64(avail) * depClosureShare / rssPerSourceByte)
}

// Failed returns the languages that were detected but failed to convert (so
// their code went un-analyzed). A CI gate can use this to fail closed instead
// of reporting a false "clean".
func (r Result) Failed() []LangCoverage {
	var failed []LangCoverage
	for _, c := range r.Coverage {
		if c.Detected && !c.Converted {
			failed = append(failed, c)
		}
	}
	return failed
}

// Scan lowers the source at path to gIR and runs the taint engine (with rs)
// alongside the non-dataflow dangerous-call (weak-crypto / insecure-RNG) and
// hardcoded-secrets passes over it. path may be a single
// .go/.py/.js/.java/.rs/.rb/.c/.cpp file or a directory (every present language
// is converted and merged). The returned findings are pre-LLM-review; the CLI
// applies that optional stage. Result.Coverage records which frontends ran and
// which failed.
func Scan(path string, rs *rules.RuleSet, opts ...Option) (Result, error) {
	cfg := newConfig(opts)
	start := time.Now()
	prog, coverage, targetPkgs, inv, err := convert(path, cfg)
	convertDur := time.Since(start)
	if err != nil {
		return Result{}, err
	}
	var srcFiles []string
	if cfg.diagnostics || cfg.sources {
		srcFiles = sourceFiles(path, inv)
	}
	raw, diag := runAnalyses(prog, rs, srcFiles, path, inv, targetPkgs, cfg)
	findings := scopeFindings(raw, targetPkgs)
	if cfg.diagnostics {
		finishDiag(&diag, start, convertDur, prog, coverage)
	}
	return Result{Findings: findings, Program: prog, Coverage: coverage, Diag: diag,
		Sources: sourcesOf(cfg, srcFiles)}, nil
}

// depLoweringLangs names the frontends that lower dependency bodies, so their
// dependency modules must be analyzed demand-driven. Only these contribute a
// non-empty targetPkgs; a module of any other language is entirely user code.
// Derived from the frontend table's lowersDeps flags — the single source of
// truth — so it cannot drift from the table.
var depLoweringLangs = func() map[string]bool {
	m := map[string]bool{}
	for _, fe := range languageFrontends {
		if fe.lowersDeps {
			m[fe.name] = true
		}
	}
	return m
}()

// seedScope returns the set of module names the engine should seed eagerly (user
// code). With no dependency lowering (targetPkgs empty) it returns nil, so every
// function is seeded. Otherwise it is the dep-lowering frontends' user packages
// (targetPkgs) plus every module from a non-dep-lowering frontend — all user code
// — so only the lowered dependency modules are left out and reached demand-driven.
// This keeps the language distinction in the (language-aware) scan layer; the
// engine consumes a neutral module-name set.
func seedScope(prog *ir.Program, targetPkgs map[string]bool) map[string]bool {
	if len(targetPkgs) == 0 {
		return nil
	}
	scope := make(map[string]bool, len(targetPkgs)+len(prog.Modules))
	for k := range targetPkgs {
		scope[k] = true
	}
	for _, m := range prog.Modules {
		if m != nil && !depLoweringLangs[m.Language] {
			scope[m.Name] = true
		}
	}
	return scope
}

// runAnalyses runs the four independent analysis passes over an already-lowered
// program and returns their findings in a deterministic order. The passes read
// the program and the rule set but never mutate shared state, so they run
// concurrently; the rule set is precompiled up front so the engine and the
// dangerous-call pass don't race building per-rule matchers. An empty filePath
// skips the raw-file secrets scan (for callers that already did it); a non-nil
// inv (directory scans) feeds that scan from the cached walk instead of
// re-walking filePath.
func runAnalyses(prog *ir.Program, rs *rules.RuleSet, srcFiles []string, filePath string, inv *walkignore.Inventory, targetPkgs map[string]bool, cfg config) ([]analysis.Finding, scaninfo.Info) {
	_ = rs.Compile() // guard-compile errors are already reported by the loader at load
	start := time.Now()
	var (
		taint, danger, secrets, fileSecrets []analysis.Finding
		stats                               analysis.Stats
		lines                               int
		wg                                  sync.WaitGroup
	)
	wg.Add(4)
	// ScopeSeed makes dependency functions analyzed demand-driven (only when taint
	// reaches them) when deps were lowered; a nil/empty set seeds every function.
	go func() {
		defer wg.Done()
		e := analysis.NewEngine(rs).ScopeSeed(seedScope(prog, targetPkgs))
		if cfg.diagnostics {
			taint, stats = e.AnalyzeWithStats(prog)
		} else {
			taint = e.Analyze(prog)
		}
	}()
	go func() { defer wg.Done(); danger = analysis.ScanDangerousCalls(prog, rs) }()
	go func() { defer wg.Done(); secrets = analysis.ScanSecrets(prog, rs) }()
	// Line counting joins the same WaitGroup: re-reading the source the frontends
	// already read is far cheaper than the taint engine, so alongside it it costs
	// no measurable wall time. srcFiles is empty unless diagnostics were asked for.
	go func() { defer wg.Done(); lines = countLines(srcFiles) }()
	if filePath != "" {
		// Raw config files (.env, compose, Dockerfile, CI YAML, ...) that no
		// language frontend parses — the dominant hardcoded-secret vector.
		wg.Add(1)
		go func() {
			defer wg.Done()
			if inv != nil {
				fileSecrets = analysis.ScanSecretsInPaths(inv.Files(), rs, isSourcePath)
			} else {
				fileSecrets = analysis.ScanSecretsInFiles(filePath, rs, isSourcePath)
			}
		}()
	}
	wg.Wait()

	if !cfg.diagnostics {
		return slices.Concat(taint, dropCoLocatedDangerous(danger, taint), secrets, fileSecrets), scaninfo.Info{}
	}
	diag := scaninfo.Info{
		Files:       len(srcFiles),
		Lines:       lines,
		Functions:   stats.Functions,
		Rules:       stats.Rules,
		RulesLive:   stats.RulesLive,
		SourceSites: stats.SourceSites,
		SinkSites:   stats.SinkSites,
		Analysis:    time.Since(start),
		Index:       stats.Index,
		RuleSel:     stats.RuleSelect,
		Taint:       stats.Taint,
	}
	if diag.Rules == 0 {
		// AnalyzeWithStats returns early on an empty program, so take the rule
		// count from the set itself rather than reporting none were evaluated.
		diag.Rules = len(rs.Rules)
	}
	return slices.Concat(taint, dropCoLocatedDangerous(danger, taint), secrets, fileSecrets), diag
}

// dropCoLocatedDangerous removes every dangerous-call finding that sits on a call
// the taint engine ALREADY reported — `eval(user_input)` is legitimately matched
// by both passes. The dataflow finding is strictly richer (it names the source
// and carries the Steps that drive SARIF codeFlows and LLM triage), so it is the
// one that survives. A dangerous-call finding with no dataflow twin is untouched.
//
// It is deliberately given only (danger, taint), never the secrets passes: a
// hardcoded-secret finding can legitimately sit on the same call as a taint
// finding (a literal credential passed to a flagged API) and must not vanish.
func dropCoLocatedDangerous(danger, taint []analysis.Finding) []analysis.Finding {
	if len(danger) == 0 || len(taint) == 0 {
		return danger
	}
	// Keyed on (sink position, sink callee), not position alone: nested calls can
	// share a line — `exec(compile(src, ...))` — and a position-only key would let
	// one call's dataflow finding mask a DIFFERENT call's call-site finding. A
	// finding with no position is never keyed on either side, so position-less
	// findings don't all collapse into one bucket.
	key := func(f analysis.Finding) string {
		return analysis.PosString(f.SinkPos) + "\x00" + f.SinkCallee
	}
	confirmed := make(map[string]bool, len(taint))
	for _, f := range taint {
		if f.SinkPos != nil {
			confirmed[key(f)] = true
		}
	}
	kept := danger[:0]
	for _, f := range danger {
		if f.SinkPos != nil && confirmed[key(f)] {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// ScanFiles analyzes an explicit list of paths (the changed-files / pre-commit
// entry point) in one process: every source path is lowered and merged into a
// single program so the engine runs once (cross-file taint among the changed
// files still connects), while every path — source or not — is also scanned for
// hardcoded secrets so a changed .env/compose/Dockerfile is covered. A path with
// an unsupported extension contributes only its secrets scan; a frontend failure
// is warned on stderr and skipped rather than aborting the batch, since
// pre-commit hands over mixed file types. A batch with no analyzable source
// returns cleanly rather than erroring, so a docs-only commit does not fail.
func ScanFiles(paths []string, rs *rules.RuleSet, opts ...Option) (Result, error) {
	cfg := newConfig(opts)
	start := time.Now()
	merged := &ir.Program{}
	var coverage []LangCoverage
	var findings []analysis.Finding
	var convertDur time.Duration
	var srcFiles []string
	targetPkgs := map[string]bool{}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", p, err)
			continue
		}
		if !info.IsDir() {
			findings = append(findings, analysis.ScanSecretsInFiles(p, rs, isSourcePath)...)
			if _, conv := fileFrontend(p); conv == nil {
				continue // non-source file: secrets already scanned, no dataflow
			}
		}
		convertStart := time.Now()
		prog, cov, tp, inv, err := convert(p, cfg)
		convertDur += time.Since(convertStart)
		if info.IsDir() {
			// Feed off convert's single pruned walk. When convert failed before
			// yielding an inventory (e.g. a directory with no analyzable source),
			// the config files it holds still get scanned.
			if inv != nil {
				findings = append(findings, analysis.ScanSecretsInPaths(inv.Files(), rs, isSourcePath)...)
			} else {
				findings = append(findings, analysis.ScanSecretsInFiles(p, rs, isSourcePath)...)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", p, err)
			continue
		}
		merged.Modules = append(merged.Modules, prog.Modules...)
		coverage = append(coverage, cov...)
		// Accumulated here, past the error check, because runAnalyses is handed no
		// root and no inventory on this path — and because a path whose conversion
		// failed was not analysed. A non-directory p passed the fileFrontend check
		// above, so it is already known to be source and needs no re-stat.
		if cfg.diagnostics {
			if info.IsDir() {
				srcFiles = append(srcFiles, sourceFiles(p, inv)...)
			} else {
				srcFiles = append(srcFiles, p)
			}
		}
		for pkg := range tp {
			targetPkgs[pkg] = true
		}
	}
	// The per-path raw-file secrets scan already ran in the loop above, so pass an
	// empty path to skip it here.
	raw, diag := runAnalyses(merged, rs, srcFiles, "", nil, targetPkgs, cfg)
	findings = append(findings, scopeFindings(raw, targetPkgs)...)
	if cfg.diagnostics {
		finishDiag(&diag, start, convertDur, merged, coverage)
	}
	return Result{Findings: findings, Program: merged, Coverage: coverage, Diag: diag,
		Sources: sourcesOf(cfg, srcFiles)}, nil
}

// convert lowers source at path into a single gIR program and reports per-
// language coverage. For a single file it runs the matching frontend; for a
// directory it walks the tree ONCE into a walkignore.Inventory (also returned,
// for the raw-file secrets pass) and runs every present-language frontend off
// that cached file list, merging their modules. A frontend that fails on present
// source is warned on stderr AND recorded as a failed-coverage entry, so the
// caller can fail the gate rather than report a false "clean".
func convert(path string, cfg config) (*ir.Program, []LangCoverage, map[string]bool, *walkignore.Inventory, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if !info.IsDir() {
		lang, conv := fileFrontend(path)
		if conv == nil {
			return nil, nil, nil, nil, fmt.Errorf("unsupported file type: %s (expected .go, .py, .js/.vue/.svelte, .java, C/C++, .rs, or .rb/.erb)", path)
		}
		r, err := conv(path, nil, cfg)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		cov := LangCoverage{
			Language: lang, Detected: true, Converted: true, Files: 1, Skipped: r.skipped,
			Degraded: r.degraded, DegradedNote: r.degradedNote,
		}
		warnDegraded(cov, path)
		return r.prog, []LangCoverage{cov}, r.targetPkgs, nil, nil
	}

	// ONE pruned walk: language detection, every present frontend and the
	// config-file secrets pass all consume this inventory.
	inv := walkignore.NewInventory(path)
	present := detectLanguages(inv)
	merged := &ir.Program{}
	var coverage []LangCoverage
	frontends := languageFrontends
	// Present frontends are independent, so run them concurrently. Results are
	// collected per frontend index and merged in frontend order, keeping module
	// order and coverage deterministic.
	type feResult struct {
		prog       *ir.Program
		cov        LangCoverage
		targetPkgs map[string]bool
	}
	results := make([]*feResult, len(frontends))
	var wg sync.WaitGroup
	for i, fe := range frontends {
		if present[fe.name] == 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			cov := LangCoverage{Language: fe.name, Detected: true, Files: present[fe.name]}
			r, err := fe.convert(path, inv, cfg)
			cov.Skipped = r.skipped
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: %s frontend failed under %s: %v\n", fe.name, path, err)
				cov.Err = err.Error()
				results[i] = &feResult{cov: cov}
				return
			}
			cov.Converted = true
			cov.Degraded, cov.DegradedNote = r.degraded, r.degradedNote
			results[i] = &feResult{prog: r.prog, cov: cov, targetPkgs: r.targetPkgs}
		}()
	}
	wg.Wait()
	targetPkgs := map[string]bool{}
	for _, r := range results {
		if r == nil {
			continue
		}
		coverage = append(coverage, r.cov)
		// Warned here, in the ordered merge rather than in the goroutine, so the
		// warnings appear in frontend order however the frontends interleave.
		warnDegraded(r.cov, path)
		if r.prog != nil {
			merged.Modules = append(merged.Modules, r.prog.Modules...)
		}
		for p := range r.targetPkgs {
			targetPkgs[p] = true
		}
	}
	// Every launched frontend goroutine records a result on both its success and
	// failure paths, so "no frontend ran" is exactly "coverage is empty".
	if len(coverage) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("no analyzable Go/Python/JavaScript/Vue/Svelte/Java/Rust/Ruby/C/C++ source found under %s", path)
	}
	return merged, coverage, targetPkgs, inv, nil
}

// convertResult is one frontend's output, as a struct rather than a return
// tuple: the values are heterogeneous and most are meaningful for only some
// frontends, so a positional list stops being readable.
type convertResult struct {
	prog *ir.Program
	// targetPkgs is the set of user-authored package paths, so findings inside
	// lowered dependencies can be scoped out. Only a dep-lowering frontend (Go)
	// fills it; nil otherwise.
	targetPkgs map[string]bool
	// skipped is how many files the frontend could not lower, 0 for a frontend
	// whose unit of work is not a file.
	skipped int
	// degraded and degradedNote report a frontend that ran at reduced depth; they
	// feed LangCoverage's fields of the same names.
	degraded     bool
	degradedNote string
}

// warnDegraded reports on stderr that a frontend ran at reduced depth. Stderr,
// never stdout: stdout carries the machine-readable output.
func warnDegraded(cov LangCoverage, path string) {
	if !cov.Degraded {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: %s frontend degraded under %s: %s\n", cov.Language, path, cov.DegradedNote)
}

// frontend pairs a language tag with the function that lowers a path to gIR and
// the predicate that recognizes that language's single-file extensions. convert
// takes the scan path, the shared file inventory for directory scans (nil for
// single files), and the scan's own options — of which only the dependency
// budget reaches a frontend.
type frontend struct {
	name    string
	convert func(string, *walkignore.Inventory, config) (convertResult, error)
	matches func(path string) bool
	// lowersDeps marks a frontend that lowers third-party dependency bodies: its
	// convert returns a non-nil targetPkgs set, its modules are seeded
	// demand-driven (seedScope), and its findings are scoped to user code
	// (scopeFindings). The single source of truth behind depLoweringLangs.
	lowersDeps bool
}

// languageFrontends is the single source of truth for the language→frontend
// mapping used by convert, fileFrontend (single-file dispatch) and
// detectLanguages. The order is significant: it fixes module and coverage
// ordering for directory scans, so keep it as-is.
var languageFrontends = []frontend{
	{name: "go", convert: goConvert, lowersDeps: true,
		matches: go_converter.IsGoFile},
	{name: "python", convert: noDepConvert(py_converter.NewConverter),
		matches: py_converter.IsPythonFile},
	{name: "javascript", convert: noDepConvert(js_converter.NewConverter),
		matches: js_converter.IsJSFamily},
	{name: "java", convert: noDepConvert(java_converter.NewConverter),
		matches: java_converter.IsJavaFile},
	{name: "cpp", convert: noDepConvert(cpp_converter.NewConverter),
		matches: cpp_converter.IsCppFile},
	{name: "rust", convert: noDepConvert(rust_converter.NewConverter),
		matches: rust_converter.IsRustFile},
	{name: "ruby", convert: noDepConvert(ruby_converter.NewConverter),
		matches: ruby_converter.IsRubyFile},
}

// goConvert lowers a Go path and returns its target (user-authored) package set,
// so scopeFindings can drop findings whose sink sits inside a lowered dependency.
// The inventory is unused: the Go frontend's unit of work is the package, and
// go/packages does its own module-aware source discovery.
func goConvert(p string, _ *walkignore.Inventory, cfg config) (convertResult, error) {
	c := go_converter.NewConverter().SetDepBudget(cfg.depBudget)
	prog, err := c.ConvertFile(p)
	degraded, note := c.Degraded()
	// skipped stays 0: the Go frontend lowers packages, not files, so it has no
	// per-file skip count to report (see LangCoverage.Skipped).
	return convertResult{
		prog: prog, targetPkgs: c.TargetPackages(),
		degraded: degraded, degradedNote: note,
	}, err
}

// fileConverter is the shape every non-dep-lowering frontend's converter shares:
// lower one path to a program. It exists so noDepConvert can be written once
// against all of them instead of per-frontend wrapper closures.
type fileConverter interface {
	ConvertFile(string) (*ir.Program, error)
}

// inventoryConverter marks a converter that can lower a directory from the scan
// pipeline's pre-walked file inventory instead of re-walking the tree itself.
// Every non-Go frontend implements it (the per-file frontends select their
// sources from it; Java derives its source index from it).
type inventoryConverter interface {
	ConvertInventory(*walkignore.Inventory) (*ir.Program, error)
}

// noDepConvert adapts a frontend that does not lower dependency bodies (every
// frontend except Go) to the frontend.convert signature; it has no dependency
// findings to scope, so it returns a nil target-package set. newC is called per
// conversion so each scan gets a fresh converter. Directory scans (inv non-nil)
// hand the converter the shared inventory; single-file scans use ConvertFile.
func noDepConvert[T fileConverter](newC func() T) func(string, *walkignore.Inventory, config) (convertResult, error) {
	return func(p string, inv *walkignore.Inventory, _ config) (convertResult, error) {
		c := newC()
		var prog *ir.Program
		var err error
		if ic, ok := any(c).(inventoryConverter); ok && inv != nil {
			prog, err = ic.ConvertInventory(inv)
		} else {
			prog, err = c.ConvertFile(p)
		}
		// A per-file frontend reports how many files it had to drop; one whose unit
		// of work is not a file simply does not implement this.
		skipped := 0
		if s, ok := any(c).(interface{ Skipped() int }); ok {
			skipped = s.Skipped()
		}
		return convertResult{prog: prog, skipped: skipped}, err
	}
}

// scopeFindings drops findings whose sink function lives in a lowered dependency
// package. Dependencies are lowered so taint flows THROUGH them, but a sink
// reached inside a library is noise, not an actionable finding. Only a
// dep-lowering frontend's language can produce one (depLoweringLangs), so
// findings from every other language, and those with no recorded package, are
// kept. Keys on Finding.Language rather than module membership because a Finding
// records its language and package but not its module, and targetPkgs is a set
// of PACKAGE paths. A no-op when targetPkgs is empty.
func scopeFindings(findings []analysis.Finding, targetPkgs map[string]bool) []analysis.Finding {
	if len(targetPkgs) == 0 {
		return findings
	}
	kept := findings[:0]
	for _, f := range findings {
		if depLoweringLangs[f.Language] && f.Package != "" && !targetPkgs[f.Package] {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// isSourcePath reports whether a language frontend handles path. Passed to
// analysis.ScanSecretsInFiles so the raw-file secrets pass skips exactly the
// files whose string literals the gIR-constant scanner already covers.
func isSourcePath(path string) bool {
	_, conv := fileFrontend(path)
	return conv != nil
}

// fileFrontend returns the language tag and conversion function for a single
// source file, or a nil function for an unsupported extension. It dispatches off
// the shared languageFrontends table (first match wins, in table order).
func fileFrontend(path string) (string, func(string, *walkignore.Inventory, config) (convertResult, error)) {
	for _, fe := range languageFrontends {
		if fe.matches(path) {
			return fe.name, fe.convert
		}
	}
	return "", nil
}

// detectLanguages reports which supported languages have source files present
// in the scan root's inventory (already pruned of vendor/node_modules/.git),
// so convert only runs the relevant frontends.
func detectLanguages(inv *walkignore.Inventory) map[string]int {
	present := map[string]int{}
	for _, p := range inv.Files() {
		for _, fe := range languageFrontends {
			if fe.matches(p) {
				present[fe.name]++
				break
			}
		}
	}
	return present
}
