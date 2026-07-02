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

	go_converter "godzilla/converters/go"
	js_converter "godzilla/converters/javascript"
	py_converter "godzilla/converters/python"
	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// Result is the outcome of scanning a path.
type Result struct {
	Findings []analysis.Finding
	Program  *ir.Program
}

// Scan lowers the source at path to gIR and runs the taint engine (with rs) plus
// the non-dataflow secrets scanner over it. path may be a single .go/.py/.js
// file or a directory (every present language is converted and merged). The
// returned findings are pre-LLM-review; the CLI applies that optional stage.
func Scan(path string, rs *rules.RuleSet) (Result, error) {
	prog, err := Convert(path)
	if err != nil {
		return Result{}, err
	}
	findings := analysis.NewEngine(rs).Analyze(prog)
	findings = append(findings, analysis.ScanSecrets(prog)...)
	return Result{Findings: findings, Program: prog}, nil
}

// Convert lowers source at path into a single gIR program. For a .go/.py/.js
// file it runs the matching frontend; for a directory it runs every frontend
// whose language is present and merges the modules they produce (a repo may mix
// languages), tolerating a frontend that finds nothing as long as at least one
// yields modules. A frontend that fails on present source is warned about on
// stderr rather than silently dropped.
func Convert(path string) (*ir.Program, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		switch {
		case strings.HasSuffix(path, ".go"):
			return go_converter.NewConverter().ConvertFile(path)
		case strings.HasSuffix(path, ".py"):
			return py_converter.NewConverter().ConvertFile(path)
		case strings.HasSuffix(path, ".js"):
			return js_converter.NewConverter().ConvertFile(path)
		default:
			return nil, fmt.Errorf("unsupported file type: %s (expected .go, .py, or .js)", path)
		}
	}

	present := detectLanguages(path)
	merged := &ir.Program{Mode: "ssa"}
	ranAny := false
	frontends := []struct {
		name    string
		convert func(string) (*ir.Program, error)
	}{
		{"go", func(p string) (*ir.Program, error) { return go_converter.NewConverter().ConvertFile(p) }},
		{"python", func(p string) (*ir.Program, error) { return py_converter.NewConverter().ConvertFile(p) }},
		{"javascript", func(p string) (*ir.Program, error) { return js_converter.NewConverter().ConvertFile(p) }},
	}
	for _, fe := range frontends {
		if !present[fe.name] {
			continue
		}
		ranAny = true
		prog, err := fe.convert(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s frontend failed under %s: %v\n", fe.name, path, err)
			continue
		}
		if prog != nil {
			merged.Modules = append(merged.Modules, prog.Modules...)
		}
	}
	if !ranAny {
		return nil, fmt.Errorf("no analyzable Go/Python/JavaScript source found under %s", path)
	}
	return merged, nil
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
		case strings.HasSuffix(p, ".js"):
			present["javascript"] = true
		}
		return nil
	})
	return present
}
