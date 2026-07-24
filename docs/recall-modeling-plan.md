# Recall-moving track — source/sink modeling breadth

## Goal

Move real-world CVE recall past the SSA-era plateau (~18.5%, 5/27 on the live
web-app campaign) by closing the **modeling-breadth** gaps the SSA work does not
touch: per-framework request **sources**, framework-abstracted **sinks**, and the
propagators/sanitizers that connect them. The SSA/CFG foundation (loop-carried
taint, flow-sensitive guard precision) is the prerequisite that makes broadening
these rules **safe** — dominator-guard suppression now controls the false-positive
blast radius that over-broad rules would otherwise create.

## Why recall stayed flat through the SSA work

The live misses are not intra-function control-flow problems. They cluster on
classes whose exploit reaches the sink through a **framework/library API the
rulepacks don't model**:

- **SSRF** (largest cluster) — the tainted URL reaches an HTTP client through a
  framework/library wrapper (`requests`/`httpx`/`aiohttp`/`urllib`; `axios`/`got`/
  `node-fetch`) that isn't a modeled sink, or the request source the flow starts
  from isn't modeled for that framework.
- **Insecure deserialization** — the untrusted data is a loaded artifact
  (pickle/YAML/model file), not an HTTP string, so there is no modeled **source**
  to seed; and/or the deserializer sink isn't modeled.
- **Framework-rendered XSS / open redirect** — the sink is a template render or a
  framework redirect helper, not a raw response write.

The hits, by contrast, are all direct request→file/query shapes godzilla already
models. Closing the gaps above is a **rules-first** effort (the repo's design:
"adding a sink/source is usually a YAML edit, not code").

## The hard constraint — false positives

Broadening sources/sinks trades recall for FP risk. Every change is gated on:

1. **Corpus `go test ./test/corpus/` FP=0 AND FN=0** (the precision floor).
2. **Real-project FP smoke** — rescan a large real app in the same language and
   confirm the finding count doesn't explode (the lesson from the gitea
   421→2356 summary blow-up). Model **narrowly and precisely** (exact framework
   API globs, receiver-pinned sink args `#idx`, `builtin.format`/`identity`
   SSRF host-fix suppression, dominator-guard sanitizers) — never wildcard sinks.
3. Verify the **specific CVE flips** miss→hit on the campaign (evidence, not hope).
4. `build`/`gofmt`/`vet` clean; quality-gate perf within budget.

## Methodology (per item — iterative, measured)

1. From the campaign, pick a miss **cluster** by class × frequency × tractability.
2. Read the **actual CVE fix commit** (the campaign records each miss's fix-changed
   files) to see the exact source→sink shape — model *that*, not a guess.
3. Model it: a YAML rule edit (source/sink/propagator/sanitizer glob) first; a
   frontend opaque-base source **synthesis** if the source is a member-read off an
   opaque base; engine only as a last resort.
4. Gate (the four checks above).
5. Commit; re-run the campaign; record the recall delta.

## Prioritized backlog (evidence-based; refined from the fresh baseline)

- [ ] **R1 — SSRF framework HTTP-client sinks** (biggest cluster: langflow,
      superset, strapi, parse-server). Model Python `requests`/`httpx`/`aiohttp`/
      `urllib.request`/`urllib3` and JS `axios`/`got`/`node-fetch`/`http(s).request`
      as CWE-918 sinks; ensure the request source reaches them. `urlHostControllable`
      already suppresses fixed-host FPs.
- [ ] **R2 — Insecure-deserialization sources** (superset): model the non-HTTP
      untrusted-artifact source (uploaded file / model registry) so a modeled
      deserializer sink (`pickle.loads`/`yaml.load`/…) has taint to fire on.
- [ ] **R3 — Per-framework request-source breadth**: FastAPI/Starlette `Request`,
      Django `request`, Express/Koa `ctx.request`, so flows originate for more apps.
- [ ] **R4 — Framework-rendered XSS / open-redirect helpers**: template renderers,
      `redirect()`/`sendRedirect` framework wrappers.
- [ ] **R5 — Code-injection residuals**: `eval`/`exec`/template-eval reached through
      a framework layer.

Each Rn is one gated increment; re-measure recall after each. Order may shift once
the fresh baseline's per-miss fix files are analysed.

## Branch / sequencing note

This track stacks onto `claude/project-overview-wblehh` (PR #25), which is currently
**merge-ready and green**. Cleanest is to **merge PR #25 first**, then run this track
as a fresh follow-up PR from `main`. Absent that, it stacks on #25 per the
designated-branch policy — which grows an already-large PR. Flag for the human.

## Progress log

(updated as items land — newest first)

- _pending_ — baseline re-measured; backlog to be refined from per-miss fix files.
