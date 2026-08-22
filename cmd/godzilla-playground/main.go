// Command godzilla-playground serves the gIR Playground: it lowers a target
// once with the same pipeline `godzilla scan` uses, then serves a local web UI
// over the result for reading the gIR and trying rule patterns against it.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bytevet/godzilla/internal/buildpolicy"
	"github.com/bytevet/godzilla/internal/memlimit"
	"github.com/bytevet/godzilla/internal/playground"
	"github.com/bytevet/godzilla/internal/proc"
	"github.com/bytevet/godzilla/internal/rules/loader"
	"github.com/bytevet/godzilla/internal/scan"
)

// version is the tool version, overridable at build time via
//
//	go build -ldflags "-X main.version=v1.2.3"
//
// (wired in the Makefile). The UI shows it, so a screenshot names the build it
// came from.
var version = "dev"

// Exit codes.
const (
	exitClean = 0 // the server ran and stopped cleanly
	exitError = 1 // conversion / rule-loading / listen error
	exitUsage = 2 // bad invocation
)

const usageText = `usage: godzilla-playground [flags] <path>

Lower the source at <path> to gIR once, then serve a local web UI over it: the
gIR of every file, the canonical name of every call, and each argument's LOGICAL
index — the number a rule pins with #<n>, which a method call's receiver shifts
by one. A pattern pad tests a canonical glob against the loaded module using the
real rule matcher, so what it reports is what the engine would match.

flags:
  -rules <path>     additional YAML rule file — or directory of rulepacks — to load alongside the built-in rules
  -addr <host:port> listen address (default 127.0.0.1:0 — loopback, ephemeral port)
  -open             open the URL in a browser (default true; -open=false suppresses)
  -allow-build      allow running the scanned project's build tool (Maven/Gradle/Cargo) — executes repo code; off by default
  -parse-timeout <dur>  deadline per per-file parse/dump subprocess (default 2m0s)
  -build-timeout <dur>  deadline for a whole-project build under -allow-build (default 10m0s)

exit codes: 0 clean, 1 error, 2 usage
`

func usage() {
	fmt.Fprint(os.Stderr, usageText)
}

func main() {
	// Cap the heap relative to available RAM so a large whole-repo scan GCs
	// harder instead of being OOM-killed mid-analysis.
	memlimit.Configure()

	fs := flag.NewFlagSet("godzilla-playground", flag.ExitOnError)
	fs.Usage = usage
	rulesPath := fs.String("rules", "", "additional YAML rule file, or a directory of rulepacks")
	addr := fs.String("addr", "127.0.0.1:0", "listen address (host:port); port 0 picks a free one")
	open := fs.Bool("open", true, "open the playground URL in a browser")
	allowBuild := fs.Bool("allow-build", false, "allow executing the scanned project's build tool (Maven/Gradle/Cargo)")
	parseTimeout := fs.Duration("parse-timeout", proc.ParseTimeout(), "deadline for each per-file parse/dump subprocess (python3, JavaDump, rustc, clang)")
	buildTimeout := fs.Duration("build-timeout", proc.BuildTimeout(), "deadline for a whole-project build subprocess (only runs with -allow-build)")
	_ = fs.Parse(os.Args[1:])

	if fs.NArg() != 1 {
		usage()
		os.Exit(exitUsage)
	}
	path := fs.Arg(0)

	proc.SetTimeouts(*parseTimeout, *buildTimeout)
	// Only an EXPLICIT -allow-build decides the policy; the flag's false default
	// would otherwise unset GODZILLA_ALLOW_BUILD.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "allow-build" {
			buildpolicy.SetAllowed(*allowBuild)
		}
	})

	ruleSet, err := loader.LoadDefault(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading rules: %v\n", err)
		os.Exit(exitError)
	}

	fmt.Fprintf(os.Stderr, "scanning %s …\n", path)
	res, err := scan.Scan(path, ruleSet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	fmt.Fprintf(os.Stderr, "lowered %d module(s); %d finding(s).\n", len(res.Program.GetModules()), len(res.Findings))
	if failed := res.Failed(); len(failed) > 0 {
		langs := make([]string, 0, len(failed))
		for _, c := range failed {
			langs = append(langs, c.Language)
		}
		fmt.Fprintf(os.Stderr, "warning: %d language(s) failed to analyze (%s): their gIR and findings are missing, not absent.\n",
			len(failed), strings.Join(langs, ", "))
	}

	idx := playground.NewIndex(res, path, version, ruleSet)
	if err := playground.Serve(idx, *addr, *open, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	os.Exit(exitClean)
}
