# Per-PR quality gate

`scripts/pr-quality-gate.sh` measures two git revisions back-to-back on one
machine and reports four things; `.github/workflows/quality-gate.yml` runs it on
PRs. It changes nothing in the engine/rules/tests — it's built from `git diff`,
the corpus scorer, the rulepack YAML, and the Go benchmarks.

1. **LOC changed** (product code, excl. tests) — descriptive
2. **Corpus TP/FP/FN** (precision/recall) — **blocking**
3. **Rule changes** (rule-ID diff) — descriptive
4. **Performance** (benchstat time + memory) — **blocking**

## Running locally

```bash
scripts/pr-quality-gate.sh origin/main                        # branch vs main
scripts/pr-quality-gate.sh <base-ref> <head-ref>              # explicit range
scripts/pr-quality-gate.sh origin/main --no-bench --no-corpus # cheap metrics only
scripts/pr-quality-gate.sh origin/main --no-gate              # report, don't fail
```

Compares **committed** revisions (commit working-tree changes first). Both are
materialized with `git worktree` and removed on exit; your tree is untouched.

**Requires** `go`, plus the toolchains you want benchmarked (`python3`, `java`
JDK 24+, `rustc`, `ruby`) and `benchstat`. A missing toolchain or benchstat skips
that section rather than failing.

## What's measured

| Section | Source | Blocking |
|---|---|---|
| LOC | `git diff --numstat` over `cmd/ converters/ internal/ pkg/ proto/ rulepacks/`, excl. tests/generated | no |
| Corpus | `TestCorpusSignalToNoise` on each revision | **yes** |
| Rules | rule-ID diff over `rulepacks/*.yaml` | no |
| Performance | benchstat over the engine + per-language scan benchmarks | **yes** |

Performance uses **benchstat** for both time (`sec/op`) and memory (`B/op`,
`allocs/op`): engine hot paths (`BenchmarkEngine_RuleScaling`, `BenchmarkMatchGlob`)
and per-language full-pipeline scans (`BenchmarkScan_*`, including the subprocess
frontends). Those subprocess/GC benchmarks are noisy, so the gate uses a strict
**`alpha=0.01`** — only a strongly-supported regression trips it; a `~`
(not-significant) change never gates.

## Hard gates (exit non-zero)

- **FP increased** or **recall decreased** vs. base.
- A benchmark's **time** or **memory** regressed beyond threshold (default
  **10%**) with benchstat significance.

LOC and rule churn never block. `--no-gate` reports without failing;
`--perf-threshold`/`--mem-threshold`/`--bench-count` are tunable.

## CI

`quality-gate.yml` triggers on `workflow_run` after the `CI` workflow succeeds
(not every push — benchmarking both revisions is expensive) and posts one sticky
PR comment, updated in place each run.
