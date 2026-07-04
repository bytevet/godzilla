package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"godzilla/internal/rules"
	"godzilla/internal/rules/loader"
	"godzilla/internal/ruletest"
)

const rulesUsageText = `usage: godzilla rules <list|lint|test> [args]

  rules list [-rules <file>]   list the loaded rules (built-in plus -rules)
  rules lint <file>...         validate rule YAML file(s) without scanning
  rules test <dir> [-rules f]  scan each sample dir (with expected.yaml) and
                               check it against the loaded rules
`

func rulesUsage() { fmt.Fprint(os.Stderr, rulesUsageText) }

func runRules(args []string) {
	if len(args) < 1 {
		rulesUsage()
		os.Exit(exitUsage)
	}
	switch args[0] {
	case "list":
		runRulesList(args[1:])
	case "lint":
		runRulesLint(args[1:])
	case "test":
		runRulesTest(args[1:])
	default:
		rulesUsage()
		os.Exit(exitUsage)
	}
}

// runRulesList prints every loaded rule (built-in plus an optional -rules file):
// id, severity, CWE, languages, and source/sink counts.
func runRulesList(args []string) {
	fs := flag.NewFlagSet("rules list", flag.ExitOnError)
	rulesPath := fs.String("rules", "", "additional YAML rule file to include")
	_ = fs.Parse(args)

	rs, err := loader.LoadDefault(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading rules: %v\n", err)
		os.Exit(exitError)
	}
	sorted := append([]rules.Rule(nil), rs.Rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, r := range sorted {
		langs := "all"
		if len(r.Languages) > 0 {
			langs = strings.Join(r.Languages, ",")
		}
		cwe := r.CWE
		if cwe == "" {
			cwe = "-"
		}
		fmt.Fprintf(os.Stdout, "%-32s %-8s %-8s [%s]  %d source(s), %d sink(s)\n",
			r.ID, r.Severity, cwe, langs, len(r.Sources), len(r.Sinks))
	}
	fmt.Fprintf(os.Stdout, "\n%d rule(s).\n", len(sorted))
}

// runRulesLint validates rule YAML files (same checks as the loader) without
// running a scan, exiting non-zero if any file is invalid.
func runRulesLint(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: godzilla rules lint <file>...")
		os.Exit(exitUsage)
	}
	failed := false
	for _, path := range args {
		rs, err := loader.LoadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stdout, "FAIL %s: %v\n", path, err)
			failed = true
			continue
		}
		fmt.Fprintf(os.Stdout, "ok   %s (%d rule(s))\n", path, len(rs.Rules))
	}
	if failed {
		os.Exit(exitError)
	}
}

// runRulesTest scans each sample subdirectory (one carrying an expected.yaml)
// under <dir> and checks it against the loaded rules, printing a PASS/FAIL line
// per sample and exiting non-zero on any failure — the rule-author analogue of
// the in-repo corpus test.
func runRulesTest(args []string) {
	fs := flag.NewFlagSet("rules test", flag.ExitOnError)
	rulesPath := fs.String("rules", "", "additional YAML rule file to include")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: godzilla rules test <dir> [-rules <file>]")
		os.Exit(exitUsage)
	}
	dir := fs.Arg(0)

	rs, err := loader.LoadDefault(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading rules: %v\n", err)
		os.Exit(exitError)
	}
	results, err := ruletest.RunDir(dir, rs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "no samples (subdirectories with expected.yaml) found under %s\n", dir)
		os.Exit(exitUsage)
	}

	passed, failed, skipped := 0, 0, 0
	for _, r := range results {
		switch {
		case r.Skipped != "":
			skipped++
			fmt.Fprintf(os.Stdout, "SKIP %s: %s\n", r.Sample, r.Skipped)
		case r.Pass:
			passed++
			fmt.Fprintf(os.Stdout, "PASS %s\n", r.Sample)
		default:
			failed++
			fmt.Fprintf(os.Stdout, "FAIL %s\n", r.Sample)
			for _, m := range r.Failures {
				fmt.Fprintf(os.Stdout, "       %s\n", m)
			}
		}
	}
	fmt.Fprintf(os.Stdout, "\n%d passed, %d failed, %d skipped.\n", passed, failed, skipped)
	if failed > 0 {
		os.Exit(exitFindings)
	}
}
