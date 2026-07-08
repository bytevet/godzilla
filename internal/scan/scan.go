// Package scan is the importable scan pipeline shared by the CLI and the test
// corpus. It lowers source at a path to gIR (dispatching to the right language
// frontend, or all present frontends for a directory) and runs the taint engine
// plus the hardcoded-secrets scanner over the result. Keeping this out of
// package main lets tests exercise exactly the same code path the CLI runs.
package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	cpp_converter "godzilla/converters/cpp"
	go_converter "godzilla/converters/go"
	java_converter "godzilla/converters/java"
	js_converter "godzilla/converters/javascript"
	py_converter "godzilla/converters/python"
	ruby_converter "godzilla/converters/ruby"
	rust_converter "godzilla/converters/rust"
	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
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
	prog, coverage, targetPkgs, err := convert(path)
	if err != nil {
		return Result{}, err
	}
	findings := scopeFindings(runAnalyses(prog, rs, path, targetPkgs), targetPkgs)
	return Result{Findings: findings, Program: prog, Coverage: coverage}, nil
}

// runAnalyses runs the four independent analysis passes over an already-lowered
// program and returns their findings in a deterministic order. The passes read
// the program (and the rule set) but never mutate shared state, so they run
// concurrently: the taint engine already saturates cores on a many-rule scan,
// but on smaller inputs the spare cores run the dangerous-call and secrets scans
// in parallel instead of after it. The rule set is precompiled up front so the
// engine and the dangerous-call pass don't race building per-rule matchers.
// A nil filePath skips the raw-file secrets scan (callers that already did it).
func runAnalyses(prog *ir.Program, rs *rules.RuleSet, filePath string, targetPkgs map[string]bool) []analysis.Finding {
	rs.Compile()
	var (
		taint, danger, secrets, fileSecrets []analysis.Finding
		wg                                  sync.WaitGroup
	)
	wg.Add(3)
	// ScopeSeed makes dependency functions analyzed demand-driven (only when taint
	// reaches them) when deps were lowered; a nil/empty set seeds every function.
	go func() { defer wg.Done(); taint = analysis.NewEngine(rs).ScopeSeed(targetPkgs).Analyze(prog) }()
	// Non-dataflow, call-site-syntactic rules (weak crypto, insecure randomness,
	// etc.) evaluated alongside the taint engine (COV-4).
	go func() { defer wg.Done(); danger = analysis.ScanDangerousCalls(prog, rs) }()
	go func() { defer wg.Done(); secrets = analysis.ScanSecrets(prog) }()
	if filePath != "" {
		// Raw config files (.env, compose, Dockerfile, CI YAML, ...) that no
		// language frontend parses — the dominant hardcoded-secret vector.
		wg.Add(1)
		go func() { defer wg.Done(); fileSecrets = analysis.ScanSecretsInFiles(filePath) }()
	}
	wg.Wait()

	findings := taint
	findings = append(findings, danger...)
	findings = append(findings, secrets...)
	findings = append(findings, fileSecrets...)
	return findings
}

// ScanFiles analyzes an explicit list of paths (a changed-files / pre-commit
// entry point, CI-9) in a single process: each source path is lowered and its
// modules merged into one program so the engine runs once (cross-file taint
// among the changed files still connects, and there is one exit code / report),
// while every path — source or not — is also scanned for hardcoded secrets so a
// changed .env/compose/Dockerfile is covered. A path with an unsupported
// extension contributes only its secrets scan; a genuine frontend failure is
// warned about on stderr and skipped rather than aborting the batch (pre-commit
// hands over mixed file types). A batch with no analyzable source — e.g. a
// commit touching only docs — is not an error: it returns cleanly (with any
// secrets those files contained), so a pre-commit hook does not spuriously fail.
func ScanFiles(paths []string, rs *rules.RuleSet) (Result, error) {
	merged := &ir.Program{Mode: "ssa"}
	var coverage []LangCoverage
	var findings []analysis.Finding
	targetPkgs := map[string]bool{}
	for _, p := range paths {
		findings = append(findings, analysis.ScanSecretsInFiles(p)...)
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", p, err)
			continue
		}
		if !info.IsDir() {
			if _, conv := fileFrontend(p); conv == nil {
				continue // non-source file: secrets already scanned, no dataflow
			}
		}
		prog, cov, tp, err := convert(p)
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
	findings = append(findings, scopeFindings(runAnalyses(merged, rs, "", targetPkgs), targetPkgs)...)
	return Result{Findings: findings, Program: merged, Coverage: coverage}, nil
}

// convert lowers source at path into a single gIR program and reports per-
// language coverage. For a single source file it runs the matching frontend
// (dispatched via languageFrontends); for a directory it runs every frontend
// whose language is present and merges the modules they produce (a repo may
// mix languages), tolerating a frontend that
// finds nothing as long as at least one yields modules. A frontend that fails
// on present source is warned about on stderr AND recorded as a failed-coverage
// entry, so the caller can choose to fail the gate rather than report a false
// "clean".
func convert(path string) (*ir.Program, []LangCoverage, map[string]bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, nil, err
	}

	if !info.IsDir() {
		lang, conv := fileFrontend(path)
		if conv == nil {
			return nil, nil, nil, fmt.Errorf("unsupported file type: %s (expected .go, .py, .js, .java, C/C++, .rs, or .rb)", path)
		}
		prog, targetPkgs, err := conv(path)
		if err != nil {
			return nil, nil, nil, err
		}
		return prog, []LangCoverage{{Language: lang, Detected: true, Converted: true}}, targetPkgs, nil
	}

	present := detectLanguages(path)
	merged := &ir.Program{Mode: "ssa"}
	var coverage []LangCoverage
	frontends := languageFrontends
	// Present frontends are independent (separate converters, separate source
	// sets), so run them concurrently. Results are collected per frontend index
	// and merged in frontend order, keeping module order and coverage
	// deterministic.
	type feResult struct {
		prog       *ir.Program
		cov        LangCoverage
		targetPkgs map[string]bool
	}
	results := make([]*feResult, len(frontends))
	var wg sync.WaitGroup
	for i, fe := range frontends {
		if !present[fe.name] {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			cov := LangCoverage{Language: fe.name, Detected: true}
			prog, targetPkgs, err := fe.convert(path)
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
		return nil, nil, nil, fmt.Errorf("no analyzable Go/Python/JavaScript/Java/Rust/Ruby/C/C++ source found under %s", path)
	}
	return merged, coverage, targetPkgs, nil
}

// frontend pairs a language tag with the function that lowers a path to gIR and
// the predicate that recognizes that language's single-file extensions. convert
// returns the lowered program and, for frontends that lower dependency bodies
// (Go), the set of user-authored package paths so findings inside lowered
// dependencies can be scoped out; nil for frontends that don't lower deps.
type frontend struct {
	name    string
	convert func(string) (*ir.Program, map[string]bool, error)
	matches func(path string) bool
}

// languageFrontends is the single source of truth for the language→frontend
// mapping used by convert (directory scan, run in this order), fileFrontend
// (single-file dispatch), and detectLanguages (which languages are present).
// The order is significant: it fixes module and coverage ordering for directory
// scans, so keep go/python/javascript/java/cpp/rust/ruby as-is. The Go entry
// uses goConvert (the dep-lowering path); every other frontend uses noDepConvert.
var languageFrontends = []frontend{
	{"go", goConvert, func(p string) bool { return strings.HasSuffix(p, ".go") }},
	{"python", noDepConvert(func(p string) (*ir.Program, error) { return py_converter.NewConverter().ConvertFile(p) }),
		func(p string) bool { return strings.HasSuffix(p, ".py") }},
	{"javascript", noDepConvert(func(p string) (*ir.Program, error) { return js_converter.NewConverter().ConvertFile(p) }),
		isJSFamilyFile},
	{"java", noDepConvert(func(p string) (*ir.Program, error) { return java_converter.NewConverter().ConvertFile(p) }),
		func(p string) bool { return strings.HasSuffix(p, ".java") || strings.HasSuffix(p, ".class") }},
	{"cpp", noDepConvert(func(p string) (*ir.Program, error) { return cpp_converter.NewConverter().ConvertFile(p) }),
		isCppFile},
	{"rust", noDepConvert(func(p string) (*ir.Program, error) { return rust_converter.NewConverter().ConvertFile(p) }),
		func(p string) bool { return strings.HasSuffix(p, ".rs") }},
	{"ruby", noDepConvert(func(p string) (*ir.Program, error) { return ruby_converter.NewConverter().ConvertFile(p) }),
		func(p string) bool { return strings.HasSuffix(p, ".rb") }},
}

// goConvert lowers a Go path and returns its target (user-authored) package set,
// so scopeFindings can drop findings whose sink sits inside a lowered dependency.
func goConvert(p string) (*ir.Program, map[string]bool, error) {
	c := go_converter.NewConverter()
	prog, err := c.ConvertFile(p)
	return prog, c.TargetPackages(), err
}

// noDepConvert adapts a frontend that does not lower dependency bodies (every
// frontend except Go) to the frontend.convert signature — it has no dependency
// findings to scope, so it returns a nil target-package set.
func noDepConvert(conv func(string) (*ir.Program, error)) func(string) (*ir.Program, map[string]bool, error) {
	return func(p string) (*ir.Program, map[string]bool, error) {
		prog, err := conv(p)
		return prog, nil, err
	}
}

// scopeFindings drops Go findings whose sink function lives in a lowered
// dependency package (not user code). Dependencies are lowered so taint flows
// THROUGH them, but a sink reached inside a library is noise, not an actionable
// finding. Non-Go findings, and Go findings with no recorded package, are kept.
// A no-op when targetGoPkgs is empty (nothing was dep-lowered).
func scopeFindings(findings []analysis.Finding, targetGoPkgs map[string]bool) []analysis.Finding {
	if len(targetGoPkgs) == 0 {
		return findings
	}
	kept := findings[:0]
	for _, f := range findings {
		if f.Language == "go" && f.Package != "" && !targetGoPkgs[f.Package] {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// fileFrontend returns the language tag and conversion function for a single
// source file, or a nil function for an unsupported extension. It dispatches off
// the shared languageFrontends table (first match wins, in table order).
func fileFrontend(path string) (string, func(string) (*ir.Program, map[string]bool, error)) {
	for _, fe := range languageFrontends {
		if fe.matches(path) {
			return fe.name, fe.convert
		}
	}
	return "", nil
}

// isJSFamilyFile reports whether path is a JavaScript-family source file the JS
// frontend handles: plain JS, TypeScript, JSX/TSX, and ES-module/CommonJS
// variants (the .ts/.tsx/.jsx/.mjs/.cjs files are esbuild-transformed to JS in
// the frontend before parsing).
func isJSFamilyFile(path string) bool {
	switch {
	case strings.HasSuffix(path, ".js"),
		strings.HasSuffix(path, ".ts"),
		strings.HasSuffix(path, ".tsx"),
		strings.HasSuffix(path, ".jsx"),
		strings.HasSuffix(path, ".mjs"),
		strings.HasSuffix(path, ".cjs"):
		return true
	}
	return false
}

// isCppFile reports whether path is a C or C++ translation unit (not a header,
// which clang can't compile to a standalone module).
func isCppFile(path string) bool {
	switch {
	case strings.HasSuffix(path, ".c"),
		strings.HasSuffix(path, ".cc"),
		strings.HasSuffix(path, ".cpp"),
		strings.HasSuffix(path, ".cxx"),
		strings.HasSuffix(path, ".c++"):
		return true
	}
	return false
}

// detectLanguages walks dir and reports which supported languages have source
// files present (skipping vendor/node_modules/.git), so convert only runs the
// relevant frontends.
func detectLanguages(dir string) map[string]bool {
	present := map[string]bool{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if walkignore.SkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		for _, fe := range languageFrontends {
			if fe.matches(p) {
				present[fe.name] = true
				break
			}
		}
		return nil
	})
	return present
}
