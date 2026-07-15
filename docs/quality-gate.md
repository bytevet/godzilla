# Per-PR quality gate

Every change to a SAST engine has to answer four questions before it merges:

1. **How much product code changed** (excluding tests)?
2. **Did precision or recall move** on the sample corpus (TP / FP / FN)?
3. **How much detection surface changed** (rules added / modified)?
4. **Did scans get slower** — the most important gate.

`scripts/pr-quality-gate.sh` answers all four by measuring **two git revisions
back-to-back on the same machine** and printing one report. The CI workflow
`.github/workflows/quality-gate.yml` runs it automatically on pull requests.

Nothing in the engine, gIR, rules, or tests is modified to support this — the
gate is built entirely from tooling that already exists (`git diff`, the corpus
scorer `TestCorpusSignalToNoise`, the rulepack YAML, and the Go benchmarks).

## Running it locally

```bash
# Compare your branch against main:
scripts/pr-quality-gate.sh origin/main

# Compare an explicit range:
scripts/pr-quality-gate.sh <base-ref> <head-ref>

# Fast smoke run (fewer perf samples), report only, no gating:
scripts/pr-quality-gate.sh origin/main --runs 5 --bench-count 4 --no-gate

# Just the cheap metrics (skip the heavy perf + corpus steps):
scripts/pr-quality-gate.sh origin/main --no-bench --no-wall --no-corpus
```

The gate compares **committed** revisions. To include working-tree changes,
commit them first (or commit to a scratch ref and pass it as `<head-ref>`).

Both revisions are materialized with `git worktree` and removed on exit; your
working tree is left untouched.

### Requirements

- `go` (always) and the per-language toolchains you want measured: `python3`,
  `java` (JDK 24+), `rustc`, `ruby`. A language whose toolchain is absent is
  **skipped with a note** rather than failing the run.
- `benchstat` for the Go microbenchmark comparison:
  `go install golang.org/x/perf/cmd/benchstat@latest`. If absent, that section
  is skipped.
- `hyperfine` (optional) for tighter wall-clock statistics. If absent, the
  script falls back to a builtin median timer.

## What each section means

| Section | Source | Blocking? |
|---|---|---|
| **1 · LOC changed** | `git diff --numstat` over `cmd/ converters/ internal/ pkg/ proto/ rulepacks/`, excluding `*_test.go`, `testdata/`, `test/`, generated `*.pb.go` | no |
| **2 · Corpus TP/FP/FN** | `TestCorpusSignalToNoise` log line, parsed on each revision | **yes** |
| **3 · Rule changes** | rule-ID set diff over `rulepacks/*.yaml` + a flag on `internal/rules/propagators.go` | no |
| **4 · Performance** | cross-language scan wall-clock + Go hot-path benchstat | **yes** |

Metric 4 measures perf at two altitudes because the corpus is multi-language:

- **Full-pipeline scan wall-clock** (primary): times `godzilla scan` on
  `test/<lang>/command_injection` for every available language, so a per-language
  frontend/lowering regression shows up. c/cpp are omitted — their LLVM frontend
  is the opt-in cgo build, not in the default binary.
- **Go hot-path microbenchmarks** (secondary, low-noise): the taint engine is
  language-neutral, so `BenchmarkEngine_RuleScaling`, `BenchmarkMatchGlob`, and
  `BenchmarkScan_GoWithDeps` are the cleanest early warning for a shared-engine
  regression that would hit every language. Gated via `benchstat`'s significance
  (a change reported as `~` is noise and never trips the gate).

## Hard gates (exit non-zero)

The script exits non-zero — and CI fails the check — when any of these trip:

- **FP increased** vs. base (precision regression), or **recall decreased**.
- Any language's scan **wall-clock regressed beyond `--wall-threshold`**
  (default **15%**).
- A key Go benchmark **regressed beyond `--perf-threshold`** (default **10%**)
  with benchstat significance.

LOC and rule churn are always **descriptive, never blocking**. Pass `--no-gate`
to report without failing. Thresholds are flags:
`--perf-threshold`, `--wall-threshold`, `--runs`, `--bench-count`.

## How CI wires it up

`quality-gate.yml` triggers on `workflow_run` **after the `CI` workflow
succeeds** — not on every push — because the gate builds and benchmarks both
revisions and is expensive. Running only on PRs that already build and pass
tests keeps the cost down, and the `workflow_run` context has a write token so
the report is posted as a single sticky PR comment (updated in place on each
run).
