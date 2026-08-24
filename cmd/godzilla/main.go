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
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/buildpolicy"
	"github.com/bytevet/godzilla/internal/config"
	"github.com/bytevet/godzilla/internal/llm"
	"github.com/bytevet/godzilla/internal/memlimit"
	"github.com/bytevet/godzilla/internal/proc"
	"github.com/bytevet/godzilla/internal/progress"
	"github.com/bytevet/godzilla/internal/report"
	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/rules/loader"
	"github.com/bytevet/godzilla/internal/scan"
	"github.com/bytevet/godzilla/internal/triage"
	"github.com/bytevet/godzilla/internal/tui"
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
  -baseline <file>  suppress findings whose fingerprint is in this baseline file (gate only NEW findings)
  -write-baseline <file>  write the current findings' fingerprints to <file> as a baseline and exit 0
  -allow-build      allow running the scanned project's build tool (Maven/Gradle/Cargo) — executes repo code; off by default
  -config <file>    path to a .godzilla.yaml (default: auto-loaded from the scan root)
  -quiet            suppress console output (and the progress display); the exit code and report files still reflect findings
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

// trapInterrupt tears the display down on Ctrl-C. A signal skips every defer, so
// without this the terminal keeps a half-drawn bar and — worse — loses the
// warnings the display is holding, which are only written out by Stop.
//
// The exit code is the shell's own convention for a signal death, 128+signo;
// re-raising with the default disposition would be the more faithful ending but
// costs a syscall.Kill this package does not otherwise need and Windows does not
// have. Nothing is trapped when the display is off, so a piped scan keeps the
// default behaviour exactly.
func trapInterrupt(ui *tui.UI) {
	if ui == nil {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-ch
		ui.Abort()
		ui.Stop()
		if sig == syscall.SIGTERM {
			os.Exit(143)
		}
		os.Exit(130)
	}()
}

// progressUI arms the stage ledger and starts a display over it, or returns nil
// when the display is off. The ledger's lifetime is the display's.
func progressUI(quiet bool, expect []string) *tui.UI {
	if !tui.Enabled(quiet) {
		return nil
	}
	disable := progress.Enable()
	ui := tui.Start(tui.Options{Capture: true, Expect: expect})
	ui.OnStop(disable)
	return ui
}

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

	ruleSet, err := loader.LoadDefault(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading rules: %v\n", err)
		os.Exit(exitError)
	}
	ruleSet = cfg.ApplyRules(ruleSet) // disable rules / apply severity overrides (no-op if cfg nil)

	// Only the HTML report renders scan diagnostics, so only it pays to collect them.
	var scanOpts []scan.Option
	if *htmlPath != "" {
		scanOpts = append(scanOpts, scan.WithDiagnostics())
	}
	// ONE display for everything that makes the user wait — the scan and the LLM
	// review, which is network-bound and the longest single wait in the run. It
	// owns stderr while it is up, and the few stdout writes that happen inside
	// the window go through ui.Stdout(), so both scroll above the bar instead of
	// tearing through it while each still lands on its own stream.
	//
	// os.Exit skips defers AND strands captured output in the pipe, so every exit
	// inside the window goes through exitWith. Past ui.Stop below, os.Exit is
	// fine again.
	var expect []string
	if *llmReview {
		// Reserved before it starts: a stage discovered only at the end would
		// leave the bar pinned near 100% for the longest wait in the run.
		expect = append(expect, "llm")
	}
	// Asked about stdout, not about the display: the two streams can be a
	// terminal and a file independently.
	st := styler{on: tui.Color(os.Stdout), rich: tui.Width(os.Stdout) > 0 && !*quiet,
		width: tui.Width(os.Stdout)}
	var ui *tui.UI
	if ui = progressUI(*quiet, expect); ui != nil {
		defer ui.Stop()
		trapInterrupt(ui)
		scanOpts = append(scanOpts, scan.WithProgress())
	}
	exitWith := func(code int) {
		if code != exitClean {
			ui.Abort()
		}
		ui.Stop()
		os.Exit(code)
	}
	var res scan.Result
	if filesMode {
		res, err = scan.ScanFiles(paths, ruleSet, scanOpts...)
	} else {
		res, err = scan.Scan(path, ruleSet, scanOpts...)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		exitWith(exitError)
	}
	// Sampled here rather than inside Scan: ReadMemStats stops the world, and a
	// library caller in a loop must not pay that per iteration. Sys only grows, so
	// reading it the moment the scan returns is the same high-water mark.
	if *htmlPath != "" {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		res.Diag.PeakBytes = ms.Sys
	}

	// Only when piped. On a terminal the completeness is on the phase rows and
	// again in the closing block, and this line — which ran off the right edge —
	// is what that replaced.
	if !*quiet && !st.rich {
		printCoverage(ui.Stdout(), res.Coverage, st)
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
			fmt.Fprintf(ui.Stdout(), "config: excluded %d finding(s) by path filter.\n", excluded)
		}
	}
	if *baselinePath != "" {
		baseFps, err := triage.LoadBaseline(*baselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading baseline: %v\n", err)
			exitWith(exitError)
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
			exitWith(exitError)
		}
		active := 0
		for _, f := range findings {
			if !f.Suppressed {
				active++
			}
		}
		fmt.Fprintf(ui.Stdout(), "Baseline written to %s (%d fingerprint(s)).\n", *writeBaseline, active)
		exitWith(exitClean)
	}

	if *llmReview {
		var stats llm.ReviewStats
		// Select the reviewer backend (LLM-9: GODZILLA_LLM_PROVIDER=openai uses an
		// OpenAI-compatible/local endpoint; default is Anthropic with read-only
		// agency over the scanned project — LLM-4).
		reviewer := llm.NewReviewer(llm.NewFileToolBox(res.Program, path))
		findings, stats = llm.Filter(context.Background(), reviewer, findings, analysis.ConfidenceMedium)
		ui.Stop()
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

	ui.Stop()
	gated, active := printFindings(os.Stdout, findings, threshold, *quiet, st)

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
	var written []string
	for _, r := range reports {
		if r.path == "" {
			continue
		}
		if err := writeReportRaw(r.path, func(w io.Writer) error { return r.write(w, findings) }); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing %s report: %v\n", r.kind, err)
			os.Exit(exitError)
		}
		written = append(written, r.path)
		if !st.rich {
			fmt.Fprintf(os.Stdout, "%s report written to %s\n", r.kind, r.path)
		}
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

	code, reason := exitClean, "no findings at or above -fail-on="+string(threshold)
	if gated > 0 {
		code, reason = exitFindings, "findings at or above -fail-on="+string(threshold)
	}
	if st.rich {
		counts := map[rules.Severity]int{}
		for _, f := range active {
			counts[f.Severity]++
		}
		fmt.Fprintln(os.Stdout)
		summary{
			st: st, counts: counts, total: len(active), reports: written,
			coverage: res.Coverage, failed: res.Failed(),
			rules: len(ruleSet.Rules), langs: len(res.Coverage),
			code: code, reason: reason,
		}.write(os.Stdout)
	}
	os.Exit(code)
}

// printFinding renders one finding. The two layouts are deliberate: piped
// output is what tooling and the CLI tests were written against and stays byte
// for byte what it has always been, while a terminal gets the message wrapped
// to the window with a hanging indent and the fields aligned into columns —
// which is the difference between skimming two hundred findings and not.
func printFinding(w io.Writer, n, of int, f analysis.Finding, st styler) {
	tag := "[" + string(f.Severity) + "]"
	if !st.rich {
		fmt.Fprintf(w, "%s %s (%s, confidence: %s)\n", tag, f.RuleID, f.CWE, f.Confidence)
		fmt.Fprintf(w, "  %s\n", f.Message)
		fmt.Fprintf(w, "  sink:   %s  ->  %s\n", analysis.PosString(f.SinkPos), f.SinkCallee)
		fmt.Fprintf(w, "  source: %s\n", analysis.PosString(f.SourcePos))
		fmt.Fprintf(w, "  in:     %s\n\n", f.Function)
		return
	}

	// The counter is left-padded to the width of the largest index so the tags
	// line up, but the BODY hangs at a fixed two columns rather than under the
	// counter: on a two-hundred-finding scan that indent would otherwise eat
	// eight columns of every wrapped line.
	idx := fmt.Sprintf("%*d/%d ", len(strconv.Itoa(of)), n, of)

	fmt.Fprintf(w, "%s%s %s  %s\n", st.dim(idx), st.severity(f.Severity, fmt.Sprintf("%-10s", tag)),
		st.bold(f.RuleID), st.dim(f.CWE+" · confidence "+string(f.Confidence)))
	for _, line := range st.wrap(f.Message, 2) {
		fmt.Fprintf(w, "  %s\n", line)
	}
	fmt.Fprintf(w, "  %s %s %s %s\n", st.dim("sink  "),
		st.loc(analysis.PosString(f.SinkPos)), st.dim("→"), st.callee(f.SinkCallee))
	fmt.Fprintf(w, "  %s %s\n", st.dim("source"), st.loc(analysis.PosString(f.SourcePos)))
	fmt.Fprintf(w, "  %s %s\n\n", st.dim("in    "), st.dim(f.Function))
}

// printCoverage prints the scan's per-language coverage summary. The trailing
// blank line separates it from the findings that follow.
func printCoverage(w io.Writer, coverage []scan.LangCoverage, st styler) {
	if line := scan.CoverageSummary(coverage); line != "" {
		fmt.Fprintf(w, "%s\n\n", st.coverage(line))
	}
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
func printFindings(w io.Writer, findings []analysis.Finding, threshold rules.Severity, quiet bool, st styler) (int, []analysis.Finding) {
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
		return gated, active
	}

	if len(active) == 0 {
		fmt.Fprintln(w, st.good("No findings."))
	}
	for i, f := range active {
		printFinding(w, i+1, len(active), f, st)
	}

	if len(suppressed) > 0 {
		fmt.Fprintf(w, "%s\n", st.dim(fmt.Sprintf("Suppressed (%d) — not gated:", len(suppressed))))
		for _, f := range suppressed {
			by := f.SuppressedBy
			if by == "" {
				by = "suppressed"
			}
			fmt.Fprintf(w, "  %s\n", st.dim(fmt.Sprintf("[%s] %s  %s  ->  %s  (%s)",
				f.Severity, f.RuleID, analysis.PosString(f.SinkPos), f.SinkCallee, by)))
			if f.SuppressionReason != "" {
				fmt.Fprintf(w, "    %s\n", st.dim("reason: "+f.SuppressionReason))
			}
		}
		fmt.Fprintln(w)
	}

	// On a terminal the closing block says all of this, with the exit code and
	// the coverage beside it; printing both would state the count twice.
	if !st.rich && (len(active) > 0 || len(suppressed) > 0) {
		fmt.Fprintf(w, "%d finding(s); %d at/above %q; %d suppressed.\n",
			len(active), gated, threshold, len(suppressed))
	}
	return gated, active
}
