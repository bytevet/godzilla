// Command godzilla is the CLI entry point for the Godzilla SAST tool.
//
// The "scan" command converts a source directory into gIR (Godzilla's
// language-agnostic intermediate representation), runs the taint analysis
// engine over it using the built-in rule set (plus any user rules), prints the
// findings, and sets an exit code suitable for a CI/CD quality gate.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/buildpolicy"
	"github.com/bytevet/godzilla/internal/config"
	"github.com/bytevet/godzilla/internal/llm"
	"github.com/bytevet/godzilla/internal/memlimit"
	"github.com/bytevet/godzilla/internal/proc"
	"github.com/bytevet/godzilla/internal/report"
	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/rules/loader"
	"github.com/bytevet/godzilla/internal/scan"
	"github.com/bytevet/godzilla/internal/triage"
)

// version is the tool version, overridable at build time via
//
//	go build -ldflags "-X main.version=v1.2.3"
//
// (wired in the Makefile). It is printed by `godzilla version` and stamped into
// SARIF and JSON reports for CI provenance (CI-8).
var version = "dev"

// Exit codes.
const (
	exitClean    = 0 // no findings at/above the fail-on threshold
	exitError    = 1 // conversion / rule-loading error
	exitUsage    = 2 // bad invocation
	exitFindings = 3 // findings at/above the fail-on threshold (gate failed)
)

const usageText = `usage: godzilla <scan|rules|version> ...

  scan [flags] <path...>  analyze source at the given path(s) and report findings (see below)
  rules <list|lint|test>  inspect, validate, or test rules (see: godzilla rules)
  version               print the tool version

Convert source at the given path(s) to gIR, run taint analysis, and report
findings. Multiple paths (or -files) are lowered and analyzed together in one
process with a single merged exit code and report — a changed-files entry point
for pre-commit hooks / CI diffs.

flags:
  -rules <path>     additional YAML rule file — or directory of rulepacks — to load alongside the built-in rules
  -fail-on <sev>    minimum severity that fails the gate: info|low|medium|high|critical (default medium)
  -html <file>      write an HTML report to <file>
  -json <file>      write a JSON report to <file>
  -sarif <file>     write a SARIF 2.1.0 report to <file>
  -llm-review       triage lower-confidence findings with an LLM (needs ANTHROPIC_API_KEY;
                    set GODZILLA_LLM_PROVIDER=openai + GODZILLA_LLM_BASE_URL for a local/
                    OpenAI-compatible server, e.g. Ollama/vLLM)
  -strict           fail (exit 1) if a detected language's frontend could not analyze its source
  -dep-budget <n>   cap on the third-party Go source promoted to full analysis: a byte count
                    (suffixes K/M/G), "off" for no cap, or "auto" (default) to size it from
                    available memory. Past the cap dependencies are analyzed as signatures
                    only, so a huge repo completes at reduced depth instead of being OOM-killed
  -baseline <file>  suppress findings whose fingerprint is in this baseline file (gate only NEW findings)
  -write-baseline <file>  write the current findings' fingerprints to <file> as a baseline and exit 0
  -allow-build      allow running the scanned project's build tool (Maven/Gradle/Cargo) — executes repo code; off by default
  -config <file>    path to a .godzilla.yaml (default: auto-loaded from the scan root)
  -quiet            suppress console output; the exit code and report files still reflect findings
  -files <file>     changed-files mode: read newline-separated paths from <file> ('-' for stdin),
                    e.g. a pre-commit hook: git diff --name-only --cached | godzilla scan -files -
  -parse-timeout <dur>  deadline per per-file parse/dump subprocess (default 2m0s)
  -build-timeout <dur>  deadline for a whole-project build under -allow-build (default 10m0s)

A .godzilla.yaml in the scan root can set fail-on, path include/exclude globs,
and per-rule disable / severity-overrides; CLI flags override its values.

Suppress a single finding at the source with a "godzilla:ignore" comment on the
sink line or the line above it (optionally "godzilla:ignore[rule-id]").

exit codes: 0 clean, 1 error, 2 usage, 3 findings at/above -fail-on
`

func usage() {
	fmt.Fprint(os.Stderr, usageText)
}

func main() {
	// Cap the heap relative to available RAM so a large whole-repo scan GCs
	// harder instead of being OOM-killed mid-analysis (the default GC target of
	// ~2x the live set can exceed host memory on a big dependency closure).
	memlimit.Configure()

	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "rules":
		runRules(os.Args[2:])
	case "version", "-version", "--version", "-v":
		fmt.Printf("godzilla %s\n", version)
	default:
		usage()
		os.Exit(exitUsage)
	}
}

// readFileList reads newline-separated paths from src (or stdin when src is
// "-"), skipping blank lines and surrounding whitespace. It backs the
// changed-files/pre-commit `-files` mode.
func readFileList(src string) ([]string, error) {
	var data []byte
	var err error
	if src == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(src)
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, line := range strings.Split(string(data), "\n") {
		if p := strings.TrimSpace(line); p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// parseDepBudget resolves -dep-budget to a source-byte cap for
// scan.WithDepBudget, where a negative value means unlimited: "auto" sizes it
// from available memory, "off" removes it, and anything else is a byte count
// with an optional K/M/G/T suffix (powers of 1024; a trailing "B" or "iB" is
// accepted and ignored).
func parseDepBudget(s string) (int64, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto", "":
		return scan.DefaultDepBudget(), nil
	case "off", "none", "unlimited":
		return -1, nil
	}
	// 512, 512M, 512MB and 512MiB all mean the same thing.
	num := strings.TrimSpace(s)
	num = strings.TrimSuffix(strings.TrimSuffix(num, "B"), "b")
	num = strings.TrimSuffix(strings.TrimSuffix(num, "I"), "i")
	mult := int64(1)
	if n := len(num); n > 0 {
		if i := strings.IndexRune("KMGT", unicode.ToUpper(rune(num[n-1]))); i >= 0 {
			mult = int64(1) << (10 * (i + 1))
			num = num[:n-1]
		}
	}
	v, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
	if err != nil {
		return 0, errors.New(`want a byte count (e.g. 512M), "off", or "auto"`)
	}
	if v < 0 {
		return 0, errors.New(`want a non-negative byte count; use "off" for no cap`)
	}
	return v * mult, nil
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	fs.Usage = usage
	rulesPath := fs.String("rules", "", "additional YAML rule file, or a directory of rulepacks")
	failOn := fs.String("fail-on", "medium", "minimum severity that fails the gate")
	htmlPath := fs.String("html", "", "write an HTML report to this file")
	jsonPath := fs.String("json", "", "write a JSON report to this file")
	sarifPath := fs.String("sarif", "", "write a SARIF 2.1.0 report to this file")
	llmReview := fs.Bool("llm-review", false, "review lower-confidence findings with an LLM and drop false positives")
	strict := fs.Bool("strict", false, "fail if a detected language could not be analyzed")
	depBudget := fs.String("dep-budget", "auto", `cap on third-party Go source promoted to full analysis: a byte count, "off", or "auto"`)
	baselinePath := fs.String("baseline", "", "suppress findings whose fingerprint is in this baseline file")
	writeBaseline := fs.String("write-baseline", "", "write current findings' fingerprints to this baseline file and exit")
	allowBuild := fs.Bool("allow-build", false, "allow executing the scanned project's build tool (Maven/Gradle/Cargo)")
	configPath := fs.String("config", "", "path to a .godzilla.yaml (default: auto-loaded from the scan root)")
	quiet := fs.Bool("quiet", false, "suppress coverage and per-finding console output; the exit code and any report files still reflect findings")
	filesList := fs.String("files", "", "changed-files mode: read newline-separated paths to scan from this file, or '-' for stdin (for pre-commit hooks / CI diffs)")
	parseTimeout := fs.Duration("parse-timeout", proc.ParseTimeout(), "deadline for each per-file parse/dump subprocess (python3, JavaDump, rustc, clang)")
	buildTimeout := fs.Duration("build-timeout", proc.BuildTimeout(), "deadline for a whole-project build subprocess (only runs with -allow-build)")
	_ = fs.Parse(args)

	// Only an EXPLICIT -allow-build decides the policy. Calling SetAllowed
	// unconditionally made the flag's false default UNSET GODZILLA_ALLOW_BUILD, so
	// the environment variable this flag's own help text offers as the alternative
	// could never take effect through the CLI.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "allow-build" {
			buildpolicy.SetAllowed(*allowBuild)
		}
	})
	proc.SetTimeouts(*parseTimeout, *buildTimeout)
	report.Version = version // stamp the tool version into SARIF/JSON reports

	// Collect scan targets: a `-files` list (stdin with '-'), one or more
	// positional paths, or the single positional path of the classic invocation.
	var paths []string
	if *filesList != "" {
		p, err := readFileList(*filesList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading -files %s: %v\n", *filesList, err)
			os.Exit(exitError)
		}
		paths = p
	}
	paths = append(paths, fs.Args()...)
	if len(paths) == 0 {
		usage()
		os.Exit(exitUsage)
	}
	filesMode := *filesList != "" || len(paths) > 1
	// The config root: the single target for a classic scan, else the working
	// directory (a changed-files run has no single root — pre-commit runs at the
	// repo root).
	path := paths[0]
	configRoot := path
	if filesMode {
		configRoot = "."
	}

	// Per-project config (.godzilla.yaml): gate threshold, path filters, and
	// per-rule disable/severity overrides. An explicit -config wins; otherwise it
	// auto-loads from the scan root. CLI flags override file values (CI-5).
	var cfg *config.Config
	if *configPath != "" {
		c, err := config.LoadFile(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading config %s: %v\n", *configPath, err)
			os.Exit(exitError)
		}
		cfg = c
	} else {
		c, p, err := config.Load(configRoot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading config %s: %v\n", p, err)
			os.Exit(exitError)
		}
		cfg = c
	}

	// The config's fail-on applies only when the CLI did not set -fail-on.
	failOnSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "fail-on" {
			failOnSet = true
		}
	})
	if cfg != nil && cfg.FailOn != "" && !failOnSet {
		*failOn = cfg.FailOn
	}

	threshold := rules.Severity(*failOn)
	if threshold.Rank() == 0 {
		fmt.Fprintf(os.Stderr, "error: invalid -fail-on severity %q\n", *failOn)
		os.Exit(exitUsage)
	}

	budget, err := parseDepBudget(*depBudget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid -dep-budget %q: %v\n", *depBudget, err)
		os.Exit(exitUsage)
	}

	ruleSet, err := loader.LoadDefault(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading rules: %v\n", err)
		os.Exit(exitError)
	}
	ruleSet = cfg.ApplyRules(ruleSet) // disable rules / apply severity overrides (no-op if cfg nil)

	// Only the HTML report renders scan diagnostics, so only it pays to collect them.
	scanOpts := []scan.Option{scan.WithDepBudget(budget)}
	if *htmlPath != "" {
		scanOpts = append(scanOpts, scan.WithDiagnostics())
	}
	var res scan.Result
	if filesMode {
		res, err = scan.ScanFiles(paths, ruleSet, scanOpts...)
	} else {
		res, err = scan.Scan(path, ruleSet, scanOpts...)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	// Sampled here rather than inside Scan: ReadMemStats stops the world, and a
	// library caller in a loop must not pay that per iteration. Sys only grows, so
	// reading it the moment the scan returns is the same high-water mark.
	if *htmlPath != "" {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		res.Diag.PeakBytes = ms.Sys
	}

	if !*quiet {
		printCoverage(os.Stdout, res.Coverage)
	}

	findings := res.Findings

	// Deterministic, user-directed suppression runs before the (nondeterministic)
	// LLM stage: inline `godzilla:ignore` source directives, then a fingerprint
	// baseline. Both flag findings as suppressed rather than deleting them.
	findings = triage.ApplyInlineIgnores(findings)
	if cfg != nil {
		var excluded int
		findings, excluded = cfg.FilterFindings(findings, path)
		if excluded > 0 {
			fmt.Fprintf(os.Stdout, "config: excluded %d finding(s) by path filter.\n", excluded)
		}
	}
	if *baselinePath != "" {
		baseFps, err := triage.LoadBaseline(*baselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading baseline: %v\n", err)
			os.Exit(exitError)
		}
		findings = triage.ApplyBaseline(findings, baseFps)
	}

	// -write-baseline captures the current (deterministically filtered) findings
	// as a baseline and exits cleanly — the adopt-on-legacy-code workflow.
	if *writeBaseline != "" {
		if err := writeReportRaw(*writeBaseline, func(w io.Writer) error {
			return triage.WriteBaseline(w, findings)
		}); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing baseline: %v\n", err)
			os.Exit(exitError)
		}
		active := 0
		for _, f := range findings {
			if !f.Suppressed {
				active++
			}
		}
		fmt.Fprintf(os.Stdout, "Baseline written to %s (%d fingerprint(s)).\n", *writeBaseline, active)
		os.Exit(exitClean)
	}

	if *llmReview {
		var stats llm.ReviewStats
		// Select the reviewer backend (LLM-9: GODZILLA_LLM_PROVIDER=openai uses an
		// OpenAI-compatible/local endpoint; default is Anthropic with read-only
		// agency over the scanned project — LLM-4).
		reviewer := llm.NewReviewer(llm.NewFileToolBox(res.Program, path))
		findings, stats = llm.Filter(context.Background(), reviewer, findings, analysis.ConfidenceMedium)
		fmt.Fprintf(os.Stdout, "LLM review: %d reviewed, %d suppressed, %d kept (no code context), %d error(s).\n",
			stats.Reviewed, stats.Suppressed, stats.LowContext, stats.Errors)
		if stats.Skipped > 0 {
			fmt.Fprintf(os.Stdout, "note: %d finding(s) past the review cap were kept unreviewed.\n", stats.Skipped)
		}
		if stats.Errors > 0 {
			fmt.Fprintf(os.Stdout, "warning: %d finding(s) could not be reviewed and were kept unreviewed: %v\n", stats.Errors, stats.FirstErr)
		}
		if stats.Reviewed > 0 && stats.Errors == stats.Reviewed {
			fmt.Fprintln(os.Stdout, "warning: --llm-review adjudicated 0 findings (the reviewer was a no-op; check ANTHROPIC_API_KEY).")
		}
		fmt.Fprintln(os.Stdout)
	}

	gated := printFindings(os.Stdout, findings, threshold, *quiet)

	// res.Diag is already the report's input type, so there is nothing to map.
	scanInfo := res.Diag
	scanInfo.Target = path
	if filesMode {
		scanInfo.Target = "changed files"
	}

	reports := []struct {
		path  string
		kind  string
		write func(io.Writer, []analysis.Finding) error
	}{
		{*htmlPath, "HTML", func(w io.Writer, f []analysis.Finding) error {
			return report.WriteHTML(w, f, report.WithScanInfo(scanInfo))
		}},
		{*jsonPath, "JSON", report.WriteJSON},
		{*sarifPath, "SARIF", report.WriteSARIF},
	}
	for _, r := range reports {
		if r.path == "" {
			continue
		}
		if err := writeReportRaw(r.path, func(w io.Writer) error { return r.write(w, findings) }); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing %s report: %v\n", r.kind, err)
			os.Exit(exitError)
		}
		fmt.Fprintf(os.Stdout, "%s report written to %s\n", r.kind, r.path)
	}

	// A strict gate fails closed: if any detected language could not be analyzed,
	// the scan is incomplete and a "clean" result cannot be trusted, so this
	// outranks the findings-based exit code.
	if *strict {
		if failed := res.Failed(); len(failed) > 0 {
			langs := make([]string, 0, len(failed))
			for _, c := range failed {
				langs = append(langs, c.Language)
			}
			fmt.Fprintf(os.Stderr, "error: -strict: %d language(s) failed to analyze: %s\n", len(failed), strings.Join(langs, ", "))
			os.Exit(exitError)
		}
	}

	if gated > 0 {
		os.Exit(exitFindings)
	}
	os.Exit(exitClean)
}

// printCoverage prints a one-line per-language coverage summary so an
// incomplete scan is visible even when the run is not strict. Nothing is
// printed when no languages were detected.
func printCoverage(w io.Writer, coverage []scan.LangCoverage) {
	if len(coverage) == 0 {
		return
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
	fmt.Fprintf(w, "coverage: %s\n\n", strings.Join(parts, ", "))
}

// writeReportRaw creates path, streams the report to it via write, and returns
// any error. The file's Close error is surfaced when write itself succeeded: a
// failed flush/close would otherwise silently truncate the report.
func writeReportRaw(path string, write func(io.Writer) error) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	return write(f)
}

// printFindings renders findings sorted by severity (worst first) then location,
// and returns how many meet or exceed the gate threshold. When quiet, it still
// computes the gate count but prints nothing — for CI that consumes a report
// file and only needs the exit code.
func printFindings(w io.Writer, findings []analysis.Finding, threshold rules.Severity, quiet bool) int {
	slices.SortStableFunc(findings, analysis.CompareFindings)

	// Suppressed findings (judged false positives by the LLM reviewer) are
	// retained for auditability but do not count toward the gate: partition them
	// out of the active set and list them separately with the reviewer's reason.
	active := make([]analysis.Finding, 0, len(findings))
	var suppressed []analysis.Finding
	for _, f := range findings {
		if f.Suppressed {
			suppressed = append(suppressed, f)
		} else {
			active = append(active, f)
		}
	}

	gated := 0
	for _, f := range active {
		if f.Severity.Rank() >= threshold.Rank() {
			gated++
		}
	}

	if quiet {
		return gated
	}

	if len(active) == 0 {
		fmt.Fprintln(w, "No findings.")
	}
	for _, f := range active {
		fmt.Fprintf(w, "[%s] %s (%s, confidence: %s)\n", f.Severity, f.RuleID, f.CWE, f.Confidence)
		fmt.Fprintf(w, "  %s\n", f.Message)
		fmt.Fprintf(w, "  sink:   %s  ->  %s\n", analysis.PosString(f.SinkPos), f.SinkCallee)
		fmt.Fprintf(w, "  source: %s\n", analysis.PosString(f.SourcePos))
		fmt.Fprintf(w, "  in:     %s\n\n", f.Function)
	}

	if len(suppressed) > 0 {
		fmt.Fprintf(w, "Suppressed (%d) — not gated:\n", len(suppressed))
		for _, f := range suppressed {
			by := f.SuppressedBy
			if by == "" {
				by = "suppressed"
			}
			fmt.Fprintf(w, "  [%s] %s  %s  ->  %s  (%s)\n", f.Severity, f.RuleID, analysis.PosString(f.SinkPos), f.SinkCallee, by)
			if f.SuppressionReason != "" {
				fmt.Fprintf(w, "    reason: %s\n", f.SuppressionReason)
			}
		}
		fmt.Fprintln(w)
	}

	if len(active) > 0 || len(suppressed) > 0 {
		fmt.Fprintf(w, "%d finding(s); %d at/above %q; %d suppressed.\n", len(active), gated, threshold, len(suppressed))
	}
	return gated
}
