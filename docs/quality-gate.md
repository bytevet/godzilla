# Per-PR quality gate

Every change to a SAST engine has to answer four questions before it merges:

1. **How much product code changed** (excluding tests)?
2. **Did precision or recall move** on the sample corpus (TP / FP / FN)?
3. **How much detection surface changed** (rules added / modified)?
4. **Did anything get slower or more allocation-hungry** — gated on benchstat
   time and memory across the engine and every language's full-pipeline scan.

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
  `java` (JDK 24+), `rustc`, `ruby`. A language whose toolchain is absent has its
  scan benchmark **skipped** rather than failing the run.
- `benchstat` for the benchmark comparison:
  `go install golang.org/x/perf/cmd/benchstat@latest`. If absent, the performance
  section is skipped.

## What each section means

| Section | Source | Blocking? |
|---|---|---|
| **1 · LOC changed** | `git diff --numstat` over `cmd/ converters/ internal/ pkg/ proto/ rulepacks/`, excluding `*_test.go`, `testdata/`, `test/`, generated `*.pb.go` | no |
| **2 · Corpus TP/FP/FN** | `TestCorpusSignalToNoise` log line, parsed on each revision | **yes** |
| **3 · Rule changes** | rule-ID set diff over `rulepacks/*.yaml` + a flag on `internal/rules/propagators.go` | no |
| **4 · Performance** | benchstat over the engine + per-language scan benchmarks (time + memory) | **yes** |

Performance is measured entirely by **benchstat** — one statistically-rigorous
mechanism for both the engine and every language, so the base→head difference is
reliable rather than wall-clock noise. The benchmarks live in Go test files and
run on both revisions:

- **Engine hot paths** (language-neutral, lowest-noise): `BenchmarkEngine_RuleScaling`,
  `BenchmarkMatchGlob` — a shared-engine regression here would hit every language.
- **Per-language full-pipeline scans**: `BenchmarkScan_GoWithDeps`, `BenchmarkScan_GoSimple`,
  and `BenchmarkScan_{Python,JS,Rust,Java,Ruby}` (`internal/scan/bench_test.go`). Each
  scans that language's `command_injection` sample through the real frontend —
  **including the subprocess frontends** (python3/rustc/java/ruby) — so a per-language
  lowering/frontend regression shows up. c/cpp are omitted (opt-in LLVM cgo build).
  A benchmark whose toolchain is absent is skipped and simply doesn't gate.

`benchstat` compares `-count` samples and marks a change as `~` when it is not
statistically significant, so noise never trips the gate. Both **time** (`sec/op`)
and **memory** (`B/op`, `allocs/op`) are gated.

Subprocess-frontend scans (Java/Rust startup) and the GC-heavy Go dep scan are
inherently noisier than the pure-Go engine benchmarks — enough that at the usual
`alpha=0.05` a borderline noise result can read as significant. So the gate uses a
**strict `alpha=0.01`** (`--alpha`): only a regression the data strongly supports
trips it, which suppresses run-to-run subprocess/GC noise while still catching a
real slowdown on the stable benchmarks. `--bench-count` and the thresholds are
also tunable.

## Hard gates (exit non-zero)

The script exits non-zero — and CI fails the check — when any of these trip:

- **FP increased** vs. base (precision regression), or **recall decreased**.
- A key benchmark's **time regressed beyond `--perf-threshold`** (default **10%**)
  with benchstat significance.
- A key benchmark's **memory (`B/op` or `allocs/op`) regressed beyond
  `--mem-threshold`** (default **10%**) with benchstat significance.

LOC and rule churn are always **descriptive, never blocking**.
Pass `--no-gate` to report without failing. Thresholds are flags:
`--perf-threshold`, `--mem-threshold`, `--bench-count`.

## How CI wires it up

`quality-gate.yml` triggers on `workflow_run` **after the `CI` workflow
succeeds** — not on every push — because the gate builds and benchmarks both
revisions and is expensive. Running only on PRs that already build and pass
tests keeps the cost down, and the `workflow_run` context has a write token so
the report is posted as a single sticky PR comment (updated in place on each
run).
