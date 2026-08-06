# Recall-moving track — source/sink modeling breadth

## Goal

Move real-world CVE recall by closing **modeling-breadth** gaps: per-framework
request **sources**, framework-abstracted **sinks**, and the propagators and
sanitizers that connect them. For the current number, run the campaign
(`.claude/skills/cve-recall`) — it re-fetches its CVE list live, so any figure
written here would be stale by the next run.

The SSA/CFG foundation (loop-carried taint, flow-sensitive guard precision) is
what makes broadening these rules **safe**: dominator-guard suppression controls
the false-positive blast radius an over-broad rule would otherwise create.

## Status — the rules-first lever is largely exhausted

The premise this plan opened with, that the residual misses were YAML edits away,
no longer holds. The SSRF client sinks it called the biggest cluster are modeled
(`requests`, `httpx`, `urlopen`, `pycurl`; `axios`, `http(s).request`), and the
misses that remain need **frontend or engine capability**, not rule breadth.
Read the backlog below as "what a capability would unlock", not as ready work.

The capability blockers, each established by measurement rather than inspection:

- **Untyped dispatch stops at an ambiguous method name.** For Python/Ruby/JS the
  engine crosses a method call only when the method name is unique program-wide,
  because fanning out on a name like `execute` would seed taint into every
  same-named method across unrelated classes. Receiver-class narrowing recovers
  the case where the receiver's construction is visible; an opaque receiver with
  a common name still stops. This is the single most common wall in real code.
- **Framework-abstracted rendering** — a value reaching HTML through a view
  component (Rails cells, template helpers) rather than a response write. The
  template is now parsed for ERB, but the chain through the component is not
  followed.
- **Second-order flows** — source and sink in different requests, joined by a
  store. No intra-process edge exists, so no dataflow engine reaches them.
- **Non-HTTP untrusted input** — a model config or loaded artifact rather than a
  request string, so there is no seeded source at all.

## The hard constraint — false positives

Broadening sources/sinks trades recall for FP risk. Every change is gated on:

1. **Corpus `go test ./test/corpus/` FP=0 AND FN=0** (the precision floor).
2. **Real-project FP smoke** — rescan a large real app in the same language and
   confirm the finding count doesn't explode. Model **narrowly and precisely**
   (exact framework API globs, receiver-pinned sink args `#idx`,
   `builtin.format`/`identity` SSRF host-fix suppression, dominator-guard
   sanitizers) — never wildcard sinks.
3. Verify the **specific CVE flips** miss→hit on the campaign (evidence, not hope).
4. `build`/`gofmt`/`vet` clean; quality-gate perf within budget.

## Methodology (per item — iterative, measured)

1. From the campaign, pick a miss **cluster** by class × frequency × tractability.
2. Read the **actual CVE fix commit** (the campaign records each miss's fix-changed
   files) to see the exact source→sink shape — model *that*, not a guess.
3. Model it: a YAML rule edit first; a frontend synthetic source/sink for a
   construct that is not a call in the source language; the engine only as a last
   resort (see the escape-hatch ordering in `CLAUDE.md`).
4. Gate (the four checks above).
5. Commit; re-run the campaign; record the recall delta.

## Backlog

Each item is one gated increment; re-measure recall after each.

- [ ] **Per-framework request-source breadth** — FastAPI/Starlette `Request`,
      Django `request`, Express/Koa `ctx.request`, so flows originate for more
      apps. Still genuine rule work.
- [ ] **Remaining SSRF clients** — `aiohttp`, `urllib3`; `got`, `node-fetch`.
      Rule work, but the cluster it was meant to unlock is now capability-bound.
- [ ] **Framework-rendered XSS / open-redirect helpers** — template renderers,
      `redirect()`/`sendRedirect` wrappers. Needs the rendering capability above
      to pay off on component-based frameworks.
- [ ] **Code-injection residuals** — `eval`/`exec`/template-eval reached through
      a framework layer.
