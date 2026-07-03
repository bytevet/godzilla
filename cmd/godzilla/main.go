// Command godzilla is the CLI entry point for the Godzilla SAST tool.
//
// The "scan" command converts a source directory into gIR (Godzilla's
// language-agnostic intermediate representation), runs the taint analysis
// engine over it using the built-in rule set (plus any user rules), prints the
// findings, and sets an exit code suitable for a CI/CD quality gate.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"godzilla/internal/analysis"
	"godzilla/internal/llm"
	"godzilla/internal/report"
	"godzilla/internal/rules"
	"godzilla/internal/rules/loader"
	"godzilla/internal/scan"
	ir "godzilla/pkg/ir/v1"
)

// Exit codes.
const (
	exitClean    = 0 // no findings at/above the fail-on threshold
	exitError    = 1 // conversion / rule-loading error
	exitUsage    = 2 // bad invocation
	exitFindings = 3 // findings at/above the fail-on threshold (gate failed)
)

const usageText = `usage: godzilla scan [flags] <path>

Convert Go source at <path> to gIR, run taint analysis, and report findings.

flags:
  -rules <file>     additional YAML rule file to load alongside the built-in rules
  -fail-on <sev>    minimum severity that fails the gate: info|low|medium|high|critical (default medium)
  -summary          also print a gIR summary (opcode histogram, intrinsics)
  -html <file>      write an HTML report to <file>
  -json <file>      write a JSON report to <file>
  -sarif <file>     write a SARIF 2.1.0 report to <file>
  -llm-review       triage lower-confidence findings with an LLM (needs ANTHROPIC_API_KEY)

exit codes: 0 clean, 1 error, 2 usage, 3 findings at/above -fail-on
`

func usage() {
	fmt.Fprint(os.Stderr, usageText)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	default:
		usage()
		os.Exit(exitUsage)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	fs.Usage = usage
	rulesPath := fs.String("rules", "", "additional YAML rule file")
	failOn := fs.String("fail-on", "medium", "minimum severity that fails the gate")
	showSummary := fs.Bool("summary", false, "also print a gIR summary")
	htmlPath := fs.String("html", "", "write an HTML report to this file")
	jsonPath := fs.String("json", "", "write a JSON report to this file")
	sarifPath := fs.String("sarif", "", "write a SARIF 2.1.0 report to this file")
	llmReview := fs.Bool("llm-review", false, "review lower-confidence findings with an LLM and drop false positives")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		usage()
		os.Exit(exitUsage)
	}
	path := fs.Arg(0)

	threshold := rules.Severity(*failOn)
	if threshold.Rank() == 0 {
		fmt.Fprintf(os.Stderr, "error: invalid -fail-on severity %q\n", *failOn)
		os.Exit(exitUsage)
	}

	ruleSet, err := loader.LoadDefault(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading rules: %v\n", err)
		os.Exit(exitError)
	}

	res, err := scan.Scan(path, ruleSet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	if *showSummary {
		printSummary(os.Stdout, summarize(res.Program))
		fmt.Fprintln(os.Stdout)
	}

	findings := res.Findings

	if *llmReview {
		var dropped int
		findings, dropped = llm.Filter(context.Background(), llm.NewAnthropicReviewer(), findings, analysis.ConfidenceMedium)
		if dropped > 0 {
			fmt.Fprintf(os.Stdout, "LLM reviewer dropped %d likely false positive(s).\n\n", dropped)
		}
	}

	gated := printFindings(os.Stdout, findings, threshold)

	reports := []struct {
		path  string
		kind  string
		write func(io.Writer, []analysis.Finding) error
	}{
		{*htmlPath, "HTML", report.WriteHTML},
		{*jsonPath, "JSON", report.WriteJSON},
		{*sarifPath, "SARIF", report.WriteSARIF},
	}
	for _, r := range reports {
		if r.path == "" {
			continue
		}
		if err := writeReport(r.path, findings, r.write); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing %s report: %v\n", r.kind, err)
			os.Exit(exitError)
		}
		fmt.Fprintf(os.Stdout, "%s report written to %s\n", r.kind, r.path)
	}

	if gated > 0 {
		os.Exit(exitFindings)
	}
	os.Exit(exitClean)
}

// writeReport creates path, streams the report to it via write, and returns any
// error. The file's Close error is surfaced when write itself succeeded: a
// failed flush/close would otherwise silently truncate the report.
func writeReport(path string, findings []analysis.Finding, write func(io.Writer, []analysis.Finding) error) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	return write(f, findings)
}

// printFindings renders findings sorted by severity (worst first) then location,
// and returns how many meet or exceed the gate threshold.
func printFindings(w *os.File, findings []analysis.Finding, threshold rules.Severity) int {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := findings[i].Severity.Rank(), findings[j].Severity.Rank()
		if ri != rj {
			return ri > rj
		}
		return posString(findings[i].SinkPos) < posString(findings[j].SinkPos)
	})

	gated := 0
	for _, f := range findings {
		if f.Severity.Rank() >= threshold.Rank() {
			gated++
		}
	}

	if len(findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return 0
	}

	for _, f := range findings {
		fmt.Fprintf(w, "[%s] %s (%s, confidence: %s)\n", f.Severity, f.RuleID, f.CWE, f.Confidence)
		fmt.Fprintf(w, "  %s\n", f.Message)
		fmt.Fprintf(w, "  sink:   %s  ->  %s\n", posString(f.SinkPos), f.SinkCallee)
		fmt.Fprintf(w, "  source: %s\n", posString(f.SourcePos))
		fmt.Fprintf(w, "  in:     %s\n\n", f.Function)
	}

	fmt.Fprintf(w, "%d finding(s); %d at/above %q.\n", len(findings), gated, threshold)
	return gated
}

func posString(p *ir.Position) string {
	if p == nil {
		return "<unknown>"
	}
	return fmt.Sprintf("%s:%d:%d", p.Filename, p.Line, p.Column)
}

// summary holds the aggregate counts and histograms computed from a
// converted ir.Program, ready to be rendered by printSummary.
type summary struct {
	modules      int
	functions    int
	synthetic    int
	blocks       int
	instructions int

	langModules map[string]int
	opCounts    map[ir.OpCode]int
	intrinsics  map[string]int
}

// summarize walks a converted gIR program and tallies module, function,
// block, and instruction counts, along with per-language module counts,
// an opcode histogram, and distinct intrinsic names.
func summarize(prog *ir.Program) summary {
	s := summary{
		langModules: make(map[string]int),
		opCounts:    make(map[ir.OpCode]int),
		intrinsics:  make(map[string]int),
	}

	for _, mod := range prog.Modules {
		s.modules++
		s.langModules[mod.Language]++

		for _, fn := range mod.Functions {
			s.functions++
			if fn.Synthetic {
				s.synthetic++
			}

			for _, blk := range fn.Blocks {
				s.blocks++

				for _, instr := range blk.Instrs {
					s.instructions++
					s.opCounts[instr.Op]++

					if instr.Op == ir.OpCode_OP_CODE_INTRINSIC && instr.Intrinsic != "" {
						s.intrinsics[instr.Intrinsic]++
					}
				}
			}
		}
	}

	return s
}

// printSummary renders a human-readable report of s to w.
func printSummary(w *os.File, s summary) {
	fmt.Fprintf(w, "modules: %d\n", s.modules)
	fmt.Fprintf(w, "functions: %d (%d synthetic)\n", s.functions, s.synthetic)
	fmt.Fprintf(w, "basic blocks: %d\n", s.blocks)
	fmt.Fprintf(w, "instructions: %d\n", s.instructions)

	fmt.Fprintln(w, "\nmodules by language:")
	for _, lang := range sortedKeys(s.langModules) {
		fmt.Fprintf(w, "  %s: %d module(s)\n", lang, s.langModules[lang])
	}

	fmt.Fprintln(w, "\nopcode histogram:")
	for _, op := range sortedOpCodes(s.opCounts) {
		fmt.Fprintf(w, "  %-28s %d\n", op.String(), s.opCounts[op])
	}

	fmt.Fprintln(w, "\nintrinsics:")
	if len(s.intrinsics) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, name := range sortedKeys(s.intrinsics) {
		fmt.Fprintf(w, "  %s: %d\n", name, s.intrinsics[name])
	}
}

// sortedKeys returns the keys of m sorted alphabetically.
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedOpCodes returns the keys of m sorted by count descending, then by
// opcode name ascending to break ties deterministically.
func sortedOpCodes(m map[ir.OpCode]int) []ir.OpCode {
	ops := make([]ir.OpCode, 0, len(m))
	for op := range m {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool {
		if m[ops[i]] != m[ops[j]] {
			return m[ops[i]] > m[ops[j]]
		}
		return ops[i].String() < ops[j].String()
	})
	return ops
}
