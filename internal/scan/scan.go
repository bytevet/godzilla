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
	"sync"

	cpp_converter "github.com/bytevet/godzilla/converters/cpp"
	go_converter "github.com/bytevet/godzilla/converters/go"
	java_converter "github.com/bytevet/godzilla/converters/java"
	js_converter "github.com/bytevet/godzilla/converters/javascript"
	py_converter "github.com/bytevet/godzilla/converters/python"
	ruby_converter "github.com/bytevet/godzilla/converters/ruby"
	rust_converter "github.com/bytevet/godzilla/converters/rust"
	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/rules"
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
func Scan(path string, rs *rules.RuleSet) (Result, error) {
	prog, coverage, targetPkgs, inv, err := convert(path)
	if err != nil {
		return Result{}, err
	}
	findings := scopeFindings(runAnalyses(prog, rs, path, inv, targetPkgs), targetPkgs)
	return Result{Findings: findings, Program: prog, Coverage: coverage}, nil
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
func runAnalyses(prog *ir.Program, rs *rules.RuleSet, filePath string, inv *walkignore.Inventory, targetPkgs map[string]bool) []analysis.Finding {
	_ = rs.Compile() // guard-compile errors are already reported by the loader at load
	var (
		taint, danger, secrets, fileSecrets []analysis.Finding
		wg                                  sync.WaitGroup
	)
	wg.Add(3)
	// ScopeSeed makes dependency functions analyzed demand-driven (only when taint
	// reaches them) when deps were lowered; a nil/empty set seeds every function.
	go func() {
		defer wg.Done()
		taint = analysis.NewEngine(rs).ScopeSeed(seedScope(prog, targetPkgs)).Analyze(prog)
	}()
	go func() { defer wg.Done(); danger = analysis.ScanDangerousCalls(prog, rs) }()
	go func() { defer wg.Done(); secrets = analysis.ScanSecrets(prog, rs) }()
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

	return slices.Concat(taint, dropCoLocatedDangerous(danger, taint), secrets, fileSecrets)
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
func ScanFiles(paths []string, rs *rules.RuleSet) (Result, error) {
	merged := &ir.Program{}
	var coverage []LangCoverage
	var findings []analysis.Finding
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
		prog, cov, tp, inv, err := convert(p)
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
		for pkg := range tp {
			targetPkgs[pkg] = true
		}
	}
	// The per-path raw-file secrets scan already ran in the loop above, so pass an
	// empty path to skip it here.
	findings = append(findings, scopeFindings(runAnalyses(merged, rs, "", nil, targetPkgs), targetPkgs)...)
	return Result{Findings: findings, Program: merged, Coverage: coverage}, nil
}

// convert lowers source at path into a single gIR program and reports per-
// language coverage. For a single file it runs the matching frontend; for a
// directory it walks the tree ONCE into a walkignore.Inventory (also returned,
// for the raw-file secrets pass) and runs every present-language frontend off
// that cached file list, merging their modules. A frontend that fails on present
// source is warned on stderr AND recorded as a failed-coverage entry, so the
// caller can fail the gate rather than report a false "clean".
func convert(path string) (*ir.Program, []LangCoverage, map[string]bool, *walkignore.Inventory, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if !info.IsDir() {
		lang, conv := fileFrontend(path)
		if conv == nil {
			return nil, nil, nil, nil, fmt.Errorf("unsupported file type: %s (expected .go, .py, .js/.vue/.svelte, .java, C/C++, .rs, or .rb/.erb)", path)
		}
		prog, targetPkgs, skipped, err := conv(path, nil)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return prog, []LangCoverage{{
			Language: lang, Detected: true, Converted: true, Files: 1, Skipped: skipped,
		}}, targetPkgs, nil, nil
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
			prog, targetPkgs, skipped, err := fe.convert(path, inv)
			cov.Skipped = skipped
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: %s frontend failed under %s: %v\n", fe.name, path, err)
				cov.Err = err.Error()
				results[i] = &feResult{cov: cov}
				return
			}
			cov.Converted = true
			results[i] = &feResult{prog: prog, cov: cov, targetPkgs: targetPkgs}
		}()
	}
	wg.Wait()
	targetPkgs := map[string]bool{}
	for _, r := range results {
		if r == nil {
			continue
		}
		coverage = append(coverage, r.cov)
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

// frontend pairs a language tag with the function that lowers a path to gIR and
// the predicate that recognizes that language's single-file extensions. convert
// takes the scan path plus, for directory scans, the shared file inventory (nil
// for single files). It returns the lowered program and — only for frontends
// that lower dependency bodies (Go) — the set of user-authored package paths, so
// findings inside lowered dependencies can be scoped out; nil otherwise.
type frontend struct {
	name    string
	convert func(string, *walkignore.Inventory) (*ir.Program, map[string]bool, int, error)
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
func goConvert(p string, _ *walkignore.Inventory) (*ir.Program, map[string]bool, int, error) {
	c := go_converter.NewConverter()
	prog, err := c.ConvertFile(p)
	// 0 skipped: the Go frontend lowers packages, not files, so it has no
	// per-file skip count to report (see LangCoverage.Skipped).
	return prog, c.TargetPackages(), 0, err
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
func noDepConvert[T fileConverter](newC func() T) func(string, *walkignore.Inventory) (*ir.Program, map[string]bool, int, error) {
	return func(p string, inv *walkignore.Inventory) (*ir.Program, map[string]bool, int, error) {
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
		return prog, nil, skipped, err
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
func fileFrontend(path string) (string, func(string, *walkignore.Inventory) (*ir.Program, map[string]bool, int, error)) {
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
