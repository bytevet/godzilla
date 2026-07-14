# Real-world CVE recall benchmark (TRUST-11)

Godzilla's hand-written corpus scores a perfect **F1 = 1.000** — but that corpus
uses the exact source→sink shapes the analyzer already models. This benchmark
measures recall on **real CVEs in famous projects**, which exercise modeling
*breadth* (per-framework request sources, framework-abstracted sinks, long call
chains) that a curated corpus cannot. The gap between the two numbers is the map
of what to model next; it is meant to be tracked over time, not to gate CI.

## Running

Opt-in — it clones external repositories over the network:

```
GODZILLA_CVE_BENCH=1 go test ./test/cvebench/ -v
```

Without the env var the test skips. A target that cannot be cloned or scanned in
the current environment is excluded from the ratio rather than counted as a
miss, mirroring the corpus scorer's eligibility handling.

## Ground truth

`manifest.yaml` — each entry is a real CVE pinned to its **vulnerable** commit,
with the sink file verified against the fix diff. A finding whose sink lands in
that file, matching the expected rule, counts as a true positive. Entries are
parse-only frontends (Python/JS/Ruby) that scan without a build; Go/Java CVEs
need a toolchain build and are covered in the one-off benchmark report, not here.

## Interpreting the gap

A miss here is almost always a **modeling-breadth** gap, not an engine defect —
the taint engine finds the flow when a modeled source reaches a modeled sink.
The recorded misses map to tracked BACKLOG items:

- **COV-11** — framework handler-parameter sources, and the residuals behind
  them (method-propagator chaining; per-CVE transforms).
- **COV-13** — framework-abstracted sinks (`express.static`, ORM raw builders)
  and treating a scanned library's own public-API parameters as untrusted.

This suite is the regression guard for those: as each gap closes, an entry here
flips from MISS to HIT, and the recall number rises toward the corpus's 1.000.
