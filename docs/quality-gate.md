# Per-PR quality gate

Every change to a SAST engine has to answer four questions before it merges:

1. **How much product code changed** (excluding tests)?
2. **Did precision or recall move** on the sample corpus (TP / FP / FN)?
3. **How much detection surface changed** (rules added / modified)?
4. **Did the engine get slower or more allocation-hungry** — gated on
   benchmark time and memory (scan wall-clock is reported for context only).

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
| **4 · Performance** | Go hot-path benchstat (time + memory) — gated; cross-language scan wall-clock — informational | **yes** (benchstat only) |

Metric 4 measures perf at two altitudes, but only one of them gates:

- **Go hot-path microbenchmarks — gated.** The taint engine is language-neutral,
  so `BenchmarkEngine_RuleScaling`, `BenchmarkMatchGlob`, and
  `BenchmarkScan_GoWithDeps` are the cleanest, lowest-noise signal for a
  shared-engine regression that would hit every language. `benchstat` compares
  `-count` samples and marks a change as `~` when it is not statistically
  significant, so noise never trips the gate. Both **time** (`sec/op`) and
  **memory** (`B/op`, `allocs/op`) are gated — memory counts are near-deterministic
  for these benchmarks, so an allocation regression is real signal.
- **Full-pipeline scan wall-clock — informational only.** Times `godzilla scan` on
  `test/<lang>/command_injection` for every available language (c/cpp omitted — their
  LLVM frontend is the opt-in cgo build). It is **not gated**: wall clock on a shared
  runner is too noisy (JVM/rustc startup jitter alone swings double digits). The
  report shows the per-revision medians for context; no delta is computed.

## Hard gates (exit non-zero)

The script exits non-zero — and CI fails the check — when any of these trip:

- **FP increased** vs. base (precision regression), or **recall decreased**.
- A key benchmark's **time regressed beyond `--perf-threshold`** (default **10%**)
  with benchstat significance.
- A key benchmark's **memory (`B/op` or `allocs/op`) regressed beyond
  `--mem-threshold`** (default **10%**) with benchstat significance.

LOC, rule churn, and **wall-clock** are always **descriptive, never blocking**.
Pass `--no-gate` to report without failing. Thresholds are flags:
`--perf-threshold`, `--mem-threshold`, `--runs`, `--bench-count`.

## How CI wires it up

`quality-gate.yml` triggers on `workflow_run` **after the `CI` workflow
succeeds** — not on every push — because the gate builds and benchmarks both
revisions and is expensive. Running only on PRs that already build and pass
tests keeps the cost down, and the `workflow_run` context has a write token so
the report is posted as a single sticky PR comment (updated in place on each
run).
