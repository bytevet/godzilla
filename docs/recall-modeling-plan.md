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

- **`json.dumps` XSS propagator — LANDED (breadth, not a campaign flip).** Investigated the
  next four "source-works, class-doesn't-reach-fix-line" Python misses (llama-index SQLi &
  code-injection, langflow code-injection, label-studio XSS) by reading each fix commit. None
  is an R3-style rule-fixable flip: llama-index SQLi/code-injection are **source** gaps (LLM
  query param; outbound HTTP-response/SSE body) whose only rule-level fixes are high-FP and
  still wouldn't fire; langflow needs an **arg-value predicate** (`allow_dangerous_code=True`)
  the rule model can't express; label-studio XSS dies **upstream** in lxml/dict taint the
  straight-line frontend drops. The one clean, FP-safe gap found: `json.dumps`/`json.dump` was
  not a py-xss propagator, so `HttpResponse(json.dumps(user))` (reflected-JSON XSS) lost taint.
  Added them to `py-xss.yaml` + a `test/python/xss_json` corpus sample (fires only with the
  propagator). FP-safe confirmed: campaign findings_total **flat 118→118**, recall unchanged at
  6/27, corpus FP=0/FN=0. Landed on correctness merit; documented as breadth, not a metric flip.
  **Conclusion: the rules-first recall lever is now exhausted for this campaign's residual
  misses** — further gains need frontend/engine capabilities (dict/XML taint-through,
  untrusted-artifact & response-body sources, arg-value predicates), each a larger change with
  real FP surface, tracked under R1/R2 (#87/#88) rather than autonomous rule edits.
- **R3 (path-traversal propagators) — LANDED.** Recall **5/27 → 6/27 (22.2%)** on the
  py/js/ruby campaign. Root cause of the gradio misses was a **propagator gap**, not a
  source/sink gap: the FastAPI path param source *is* seeded and the `open`/`FileResponse`
  sink *is* modeled, but taint died at the ubiquitous `pathlib.Path(x)` / `os.path.normpath(x)`
  normalization hop because Python — unlike Java (`Paths.get`/`Path.of`/`Path.resolve`) — had no
  path-normalization propagators. Added them to `py-path-traversal.yaml` and `py-zip-slip.yaml`
  (both share `_py-fs-sinks.yaml`): `pathlib.Path`, `.resolve`/`.absolute`/`.joinpath`/
  `.expanduser`, `os.path.normpath`/`.abspath`/`.realpath`. Propagators forward existing taint
  and create no findings on their own, so the FP blast radius is structurally zero — confirmed:
  **CVE-2024-4941 gradio flips MISS→HIT** (`py-path-traversal` → `open` in `processing_utils.py`,
  a fix-changed file, cross-function), **CVE-2026-28414 gradio MISS→CLASS-ONLY**, and **all 26
  other targets are byte-identical** (findings_total 102→118, the +16 entirely inside gradio's
  two vulnerable file-serving flows). Corpus FP=0/FN=0.
- _pending_ — baseline re-measured; backlog to be refined from per-miss fix files.
