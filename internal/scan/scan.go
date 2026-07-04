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

	cpp_converter "godzilla/converters/cpp"
	go_converter "godzilla/converters/go"
	java_converter "godzilla/converters/java"
	js_converter "godzilla/converters/javascript"
	py_converter "godzilla/converters/python"
	rust_converter "godzilla/converters/rust"
	"godzilla/internal/analysis"
	"godzilla/internal/rules"
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

// Scan lowers the source at path to gIR and runs the taint engine (with rs) plus
// the non-dataflow secrets scanner over it. path may be a single .go/.py/.js
// file or a directory (every present language is converted and merged). The
// returned findings are pre-LLM-review; the CLI applies that optional stage.
// Result.Coverage records which frontends ran and which failed.
func Scan(path string, rs *rules.RuleSet) (Result, error) {
	prog, coverage, err := convert(path)
	if err != nil {
		return Result{}, err
	}
	findings := analysis.NewEngine(rs).Analyze(prog)
	findings = append(findings, analysis.ScanSecrets(prog)...)
	// Also scan raw config files (.env, compose, Dockerfile, CI YAML, ...) that
	// no language frontend parses — the dominant hardcoded-secret vector.
	findings = append(findings, analysis.ScanSecretsInFiles(path)...)
	return Result{Findings: findings, Program: prog, Coverage: coverage}, nil
}

// Convert lowers source at path into a single gIR program. It is the
// coverage-free façade over convert, retained for callers that do not need the
// per-language conversion status.
func Convert(path string) (*ir.Program, error) {
	prog, _, err := convert(path)
	return prog, err
}

// convert lowers source at path into a single gIR program and reports per-
// language coverage. For a .go/.py/.js file it runs the matching frontend; for
// a directory it runs every frontend whose language is present and merges the
// modules they produce (a repo may mix languages), tolerating a frontend that
// finds nothing as long as at least one yields modules. A frontend that fails
// on present source is warned about on stderr AND recorded as a failed-coverage
// entry, so the caller can choose to fail the gate rather than report a false
// "clean".
func convert(path string) (*ir.Program, []LangCoverage, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}

	if !info.IsDir() {
		lang, conv := fileFrontend(path)
		if conv == nil {
			return nil, nil, fmt.Errorf("unsupported file type: %s (expected .go, .py, .js, .java, C/C++, or .rs)", path)
		}
		prog, err := conv(path)
		if err != nil {
			return nil, nil, err
		}
		return prog, []LangCoverage{{Language: lang, Detected: true, Converted: true}}, nil
	}

	present := detectLanguages(path)
	merged := &ir.Program{Mode: "ssa"}
	ranAny := false
	var coverage []LangCoverage
	frontends := []struct {
		name    string
		convert func(string) (*ir.Program, error)
	}{
		{"go", func(p string) (*ir.Program, error) { return go_converter.NewConverter().ConvertFile(p) }},
		{"python", func(p string) (*ir.Program, error) { return py_converter.NewConverter().ConvertFile(p) }},
		{"javascript", func(p string) (*ir.Program, error) { return js_converter.NewConverter().ConvertFile(p) }},
		{"java", func(p string) (*ir.Program, error) { return java_converter.NewConverter().ConvertFile(p) }},
		{"cpp", func(p string) (*ir.Program, error) { return cpp_converter.NewConverter().ConvertFile(p) }},
		{"rust", func(p string) (*ir.Program, error) { return rust_converter.NewConverter().ConvertFile(p) }},
	}
	for _, fe := range frontends {
		if !present[fe.name] {
			continue
		}
		ranAny = true
		cov := LangCoverage{Language: fe.name, Detected: true}
		prog, err := fe.convert(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s frontend failed under %s: %v\n", fe.name, path, err)
			cov.Err = err.Error()
			coverage = append(coverage, cov)
			continue
		}
		cov.Converted = true
		coverage = append(coverage, cov)
		if prog != nil {
			merged.Modules = append(merged.Modules, prog.Modules...)
		}
	}
	if !ranAny {
		return nil, nil, fmt.Errorf("no analyzable Go/Python/JavaScript source found under %s", path)
	}
	return merged, coverage, nil
}

// fileFrontend returns the language tag and conversion function for a single
// source file, or a nil function for an unsupported extension.
func fileFrontend(path string) (string, func(string) (*ir.Program, error)) {
	switch {
	case strings.HasSuffix(path, ".go"):
		return "go", func(p string) (*ir.Program, error) { return go_converter.NewConverter().ConvertFile(p) }
	case strings.HasSuffix(path, ".py"):
		return "python", func(p string) (*ir.Program, error) { return py_converter.NewConverter().ConvertFile(p) }
	case isJSFamilyFile(path):
		return "javascript", func(p string) (*ir.Program, error) { return js_converter.NewConverter().ConvertFile(p) }
	case strings.HasSuffix(path, ".java"), strings.HasSuffix(path, ".class"):
		return "java", func(p string) (*ir.Program, error) { return java_converter.NewConverter().ConvertFile(p) }
	case isCppFile(path):
		return "cpp", func(p string) (*ir.Program, error) { return cpp_converter.NewConverter().ConvertFile(p) }
	case strings.HasSuffix(path, ".rs"):
		return "rust", func(p string) (*ir.Program, error) { return rust_converter.NewConverter().ConvertFile(p) }
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
// files present (skipping vendor/node_modules/.git), so Convert only runs the
// relevant frontends.
func detectLanguages(dir string) map[string]bool {
	present := map[string]bool{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "vendor", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(p, ".go"):
			present["go"] = true
		case strings.HasSuffix(p, ".py"):
			present["python"] = true
		case isJSFamilyFile(p):
			present["javascript"] = true
		case strings.HasSuffix(p, ".java"), strings.HasSuffix(p, ".class"):
			present["java"] = true
		case isCppFile(p):
			present["cpp"] = true
		case strings.HasSuffix(p, ".rs"):
			present["rust"] = true
		}
		return nil
	})
	return present
}
