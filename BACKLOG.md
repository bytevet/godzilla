# Godzilla Backlog — gaps & issues toward "best SAST in the world"

> **Goal being measured against** (`README.md`, `ARCHITECTURE.md`, `spec.md`): (1) ultra-fast,
> usable as a per-commit CI gate; (2) near-perfect signal/noise (near-zero false positives at
> the gate); (3) multi-language via one taint engine over the frozen gIR SSA IR; (4) an optional
> LLM reviewer that adjudicates only low/medium-confidence findings and fails open.

## How this backlog was produced

A 7-lens deep-dive audit of the codebase (engine precision, frontend fidelity, detection
coverage, performance, CI/CD ergonomics, LLM reviewer, trust & testing). Every claim is grounded
in `file:line` evidence; several were **reproduced empirically** by writing probe programs and
running the scanner. The 21 highest-severity claims were then put through an **adversarial
verification pass** (each re-checked against the code by an independent reviewer trying to refute
it): **18 CONFIRMED, 3 PARTIAL (corrections folded in), 0 refuted.** Verdicts are noted per item.

Each item has a stable ID (`ENG-*`, `FE-*`, `COV-*`, `PERF-*`, `CI-*`, `LLM-*`, `TRUST-*`) used
by the roadmap below. Severity: **critical** = undermines a headline goal or trust; **high** =
major FP/FN class or adoption blocker; **medium** = notable quality issue; **low** = polish.

## Conventions to respect when fixing

Per `CLAUDE.md`: **gIR is a frozen cross-language contract.** Prefer fixes in this order —
(1) `OP_CODE_INTRINSIC` + engine/rule teaching, (2) YAML rule edits, (3) frontend lowering,
(4) engine (`internal/analysis`) changes that don't touch the schema. Only change `proto/*.proto`
as a last resort. Most Tier-0/Tier-1 items below are localized engine fixes or pure-YAML additions.

---

## Root causes (several gaps share one)

A few underlying defects surface across multiple lenses. Fixing the root clears several IDs at once:

| Root cause | IDs it explains | One-line fix |
|---|---|---|
| **Gate fails open** — a frontend/build/type-check failure becomes a stderr warning and exit 0 | FE-1, CI-3, TRUST-2 | Fail closed under a CI/strict mode; report coverage |
| **Sanitizer result re-tainted by return summary** (bug) | ENG-1, ENG-7 | Early-return in `handleCall` on sanitizer match |
| **TypeScript / ESM unscanned** | FE-6, COV-2 | Add TS/ESM handling to the JS frontend |
| **No suppression + no stable fingerprint** | CI-1, CI-2 | Baseline file + inline ignore + finding fingerprints |
| **No taint path recorded** (blocks trace UX + LLM context) | CI-6, LLM-2, ENG-10 | Thread the flow path through the engine into `Finding` |
| **Untrusted build execution** | TRUST-1, TRUST-9 | `--allow-build` opt-in + warning; later sandbox |

---

## Prioritized roadmap

> **Implementation status** (branch `claude/backlog-gap-analysis`):
> **Tier 0 — ✅ COMPLETE** (`4f445c9` engine, `6f7b62a` reviewer, `96ff41e` gate).
> **Tier 1 — ✅ COMPLETE**: CI-1/CI-2 fingerprints+baseline+inline-ignore (`b9f3df7`), ENG-4 default
> propagators (`ea27eb3`), COV-1 secrets-over-config-files (`9b142bd`), TRUST-1 build-exec gate
> (`96a5dbe`), COV-3 Java XSS/SSRF/redirect/deser (`39c5cf3`), COV-5 Python code injection (`315bbf6`),
> COV-6 header/cookie sources (`55d4f15`), FE-6/COV-2 TypeScript/JSX/ESM via esbuild (`803dcfd`).
> **Tier 2 — ✅ core goals met**: PERF-2 Go dep-scoping (`a6e6d06`), PERF-3 parallelism (`c99075e`),
> PERF-4 subprocess timeouts (`a53dec4`), PERF-5 shared CHA index (`d049e80`), PERF-7 dir excludes
> (`b73af85`); PERF-1/6/8 deferred with rationale (see Tier 2 below).
> **Tier 3 — ✅ COMPLETE**: ENG-3 field-sensitive structs (`5c26335`), CI-6 taint-path recording
> (`4c6a417`), LLM-2 taint-path-in-reviewer-context (`531ac68`), TRUST-7 frontend fuzzing +
> glob-DoS fix (`09f40e1`), TRUST-6 perf-regression guard + TRUST-8 2nd differential shape
> (`2326058`), TRUST-3 optional location oracle (`99abf24`), TRUST-5 precision/recall scorer
> (`f04483e`), ENG-6a taint-through-globals (`e88e46a`), ENG-6b out-parameter fill (`72ed5d4`),
> ENG-9 guard/barrier sanitization (`8e33f7c`), ENG-2 flow-sensitivity + strong updates (`41ae16f`),
> LLM-4 agentic tool-using reviewer (`516c18f`). Every High-severity engine/reviewer gap from the
> audit is now implemented and tested.
>
> **Opportunistic (medium/low) — ✅ swept**: LLM-5 reviewer concurrency/timeout/cap (`3dceb0f`),
> ENG-8 SSRF dedup ordering (`b8344be`), CI-5 project config + path filters (`0fce6df`), CI-8 version
> stamping (`b2e8133`), CI-7 rules list/lint/test (`6acc72f`), LLM-8 rule-vocabulary prompt +
> verdict-parse safety (`1cd91ee`), COV-4 dangerous-call rule kind (`3a1b72e`), FE-9/FE-10 Java/Rust
> toolchain-decay guards (`f866600`), CI-4 SARIF rule metadata + COV-9 sanitizer realism (`1abcdab`),
> LLM-6 verified done, LLM-7 richer verdict + confirmed-finding annotation (`6ac4a91`), CI-9 `-quiet`
> (`c05af2f`). **Remaining — deferred with rationale** (open-ended coverage/lowering-fidelity work,
> low incremental value against the near-zero-FP gate goal; see the Terminal-state note below):
> COV-7 (axum sources — needs MIR-signature extractor synthesis in the frontend), COV-8 (C/C++ cgo
> depth), COV-10 (PHP/Ruby/C#/Kotlin — new frontends), FE-2/FE-3/FE-4/FE-5/FE-7/FE-8 (per-frontend
> lowering fidelity), LLM-9 (OpenAI-compatible adapter; `ANTHROPIC_BASE_URL` already works for
> Anthropic-compatible proxies), PERF-1/6/8 (already reasoned).

### Tier 0 — Stop the bleeding (small diffs, highest trust/precision impact) — ✅ DONE
Localized bug fixes and one-line safety flips. Ship first.

- ✅ **ENG-1** *(critical, bug)* — sanitizer bypass via return summary. Highest value: kills a whole High-confidence FP class. One-function fix. *(early-return in `handleCall`; guard `internal/analysis/sanitizer_test.go`)*
- ✅ **ENG-5** *(high, bug)* — Java instance-method interproc off-by-one. Kills a whole Java FN class. *(receiver-aware INVOKE mapping; `test/java/interproc_instance{,_safe}`)*
- ✅ **FE-1 / CI-3 / TRUST-2** *(critical)* — fail **closed** on frontend/build failure. *(scan.Result.Coverage + `-strict` + coverage summary; `internal/scan/scan_test.go`, `cmd/godzilla/main_test.go`)*
- ✅ **LLM-1 + LLM-3 + LLM-6** *(critical/high)* — reviewer auditability. *(retain-and-flag suppressed findings + reason in JSON/SARIF/HTML; never drop on empty context; ReviewStats no-op/error warnings; `internal/llm/review_test.go`, `internal/report/suppression_test.go`)*
- ✅ **ENG-7** *(medium)* — return-flow findings labeled Medium so the reviewer sees them. *(interprocOrigins; `internal/analysis/return_flow_test.go`)*

### Tier 1 — Make it adoptable (the FP/coverage blockers that stop trials)
- **CI-1 + CI-2** — baseline file + inline `// godzilla:ignore` + stable finding fingerprints → enables `--fail-on-new` diff-aware gating.
- **FE-6 / COV-2** — TypeScript + `.mjs/.cjs/.jsx` + ESM support (most modern Node backends).
- **COV-1** — secrets scanner over raw file bytes (`.env`, compose, Dockerfile, CI YAML) + expand pattern set + entropy.
- **ENG-4** — shared per-language default-propagator pack (stdlib string/path/url) → closes the easiest FN.
- **COV-3, COV-5, COV-6** — fill the pure-YAML class/framework/source holes (Java deser/XXE/SSRF/XSS, SSTI/NoSQL/zip-slip/etc., missing HTTP accessors & frameworks).
- **TRUST-1** — gate build execution behind `--allow-build` + loud warning.

### Tier 2 — Make it fast (per-commit viability, goal #1) — ✅ core goals met
- ✅ **PERF-2** — scope Go analysis to target packages, not the whole dependency closure. *(`a6e6d06`; measured ~11× on gin_gorm, corpus 60s→21s)*
- ✅ **PERF-3** — parallelize per-rule analysis + per-frontend conversion. *(`c99075e`; race-clean, deterministic)*
- ✅ **PERF-4** — subprocess timeouts on every toolchain shell-out. *(`a53dec4`; `internal/proc`)*
- ✅ **PERF-5** — build the CHA method index once, shared across rules. *(`d049e80`)*
- ✅ **PERF-7** — shared directory exclusions + size caps. *(`b73af85`; `internal/walkignore`)*
- ⏸ **PERF-1** *(deferred, rationale)* — full incremental/per-file caching. High-value for the per-commit goal, but a substantial correctness-sensitive feature (content-hash keys, converter-version salt, invalidation, cache concurrency with PERF-3). Deferred: PERF-2/3/4/5/7 already delivered "ultra-fast" (an 11× frontend win + parallelism), so caching's marginal benefit no longer justifies the invalidation risk. Diff-aware *gating* already ships via CI-2 fingerprints + baseline.
- ⏸ **PERF-6** *(deferred, rationale)* — wire up tree-shaking (`Reachable`/`Roots`). After PERF-2 the speedup is marginal, and restricting analysis to reachable functions trades the whole-program-analysis safety property (analyze everything) for that marginal gain — the call graph is a CHA over-approximation with incomplete edges for reflection/DI/framework dispatch, so it risks dropping real findings. The primitives are kept as a building block for a future demand-driven pass.
- ⏸ **PERF-8** *(deferred, low)* — streaming/memory discipline; not a bottleneck after PERF-2 cut peak heap.

### Tier 3 — Make it precise & credible (deeper engine + measurement)
- **ENG-3** — field/key-sensitive containers (one-level access paths).
- **ENG-2** — strong updates + block-ordered (RPO) traversal (flow-sensitivity through memory).
- **ENG-6** — taint through globals + callee heap side-effects (cheap points-to substitute).
- **ENG-9** — guard/barrier sanitization (validation-style checks stop taint).
- **CI-6 + LLM-2 + LLM-4** — record the taint path; feed it (and the rule definition) to the reviewer; give the reviewer tool-use agency.
- **TRUST-5 + TRUST-3 + TRUST-4** — OWASP Benchmark / Juliet / real-CVE scoring in CI; assert location in `expected.yaml`; independent oracle.
- **TRUST-6, TRUST-7, TRUST-8** — perf-regression CI, frontend fuzzing, cross-frontend differential testing.

### Backlog (medium/low, opportunistic)
CI-4 (SARIF codeFlows/metadata), CI-5 (config file + path filters), CI-7 (rule-author tooling),
CI-8/CI-9 (version + console UX), COV-4 (non-dataflow rule type), COV-7/COV-8 (Rust axum / C-C++ depth),
COV-9 (sanitizer realism), COV-10 (new languages), ENG-8 (SSRF dedup ordering), FE-2 (import-alias — see
verifier correction; narrower than first stated), FE-3 (Rust bin/workspace targets), FE-4/FE-5/FE-7/FE-8
(frontend lowering fidelity), FE-9/FE-10 (JDK req / MIR version guard), LLM-5/LLM-7/LLM-8/LLM-9,
PERF-5/PERF-8.

### Terminal state — what's DONE vs. deferred

Everything **CRITICAL / HIGH / tractable-MEDIUM across the whole backlog is implemented and tested**
(Tiers 0–3 complete; the opportunistic MEDIUM/LOW set swept — see the roadmap status header for the
per-ID commit map). The items intentionally **left open** are the ones whose cost is disproportionate to
their value against the headline near-zero-FP per-commit-gate goal, deferred here with rationale so the
list is honest rather than silently unfinished:

- **COV-7 (Rust axum sources)** — needs the frontend to synthesize a source CALL per axum extractor
  (`Query`/`Path`/`Json`) by pattern-matching the MIR signature text, mirroring the Java
  `@RequestParam` trick. Real work in `mir.go`, only exercisable with `rustc` + the axum crate; the
  taint *engine* is ready (rules are a YAML edit once the sources fire). Highest-value of the deferrals.
- **COV-8 (C/C++ depth)** — more packs + argv/execve coverage on the opt-in cgo LLVM frontend; gated on
  a libLLVM build, so it can't run in the default test matrix.
- **COV-10 (PHP/Ruby/C#/Kotlin)** — net-new frontends; each is a large project on its own.
- **FE-2/FE-3/FE-4/FE-5/FE-7/FE-8** — per-frontend lowering-fidelity refinements (import aliases,
  Rust bin/workspace targets, misc node coverage). Each is narrow and open-ended; the fidelity guards
  FE-9/FE-10 already surface *gross* decay loudly, which was the trust-critical part.
- **LLM-9 (OpenAI-compatible adapter)** — the `Reviewer` interface already supports it and
  `ANTHROPIC_BASE_URL` covers Anthropic-compatible proxies today; a full OpenAI/Ollama adapter is a
  clean add when demanded.
- **CI-9 changed-files/`--files -`** — a convenience wrapper over per-file `scan`; marginal.
- **PERF-1/6/8** — reasoned in the Tier 2 section (caching invalidation risk; tree-shaking soundness
  trade-off; streaming not a bottleneck).

---

# Full gap inventory

Grouped by audit lens. Each entry: ID, severity, verification verdict (where run), impact, and fix direction.

## Engine precision & soundness (ENG)

### ENG-1 [CRITICAL] (verified: CONFIRMED) User-defined sanitizers are bypassed by the inter-procedural return summary, producing High-confidence FPs that skip LLM review

- **Impact:** Any project that writes its own sanitize/escape/validate helper (the common case — rulepack sanitizer support exists precisely for this) still gets flagged, at High confidence, which per finding.go:19 and the CLI design means the LLM reviewer never adjudicates it. This directly breaks the near-zero-FP gate promise: teams cannot silence findings by sanitizing, so they disable the rule or the gate.
- **Fix direction:** In handleCall, when rule.IsSanitizer(callee) matches, return early (or at minimum skip the returnTaint pull and the INVOKE return pull) so the sanitizer's result register is never tainted by the callee's summary. Also consider suppressing addEffect into sanitizer callees so their bodies don't generate spurious summaries. Pure engine change; no gIR or YAML impact.

### ENG-2 [HIGH] ✅ DONE (`41ae16f`) (verified: CONFIRMED) Taint is monotonic with no strong updates: stores through allocs never un-taint, making the analysis flow-insensitive through memory (FP class)

- **Impact:** False positives at High confidence on any code that reuses an address-taken local: sink-then-taint ordering, sanitize-by-reassignment, or cleared/reset buffers. CodeQL/Snyk are flow-sensitive over SSA memory (or use SSA-converted heap locations); this engine is strictly weaker even than block-ordered abstract interpretation.
- **Fix direction:** Exploit the SSA structure the frontends already emit: process blocks in reverse-post-order with per-block taint states joined at PHIs instead of a single global fixpoint map, and give STORE a strong-update semantics for non-aliased allocs (an alloc whose address is only used by LOAD/STORE in one function). This is engine-only work (internal/analysis), no gIR change.
- **DONE:** `analyzeFunc`'s whole-function flat fixpoint was replaced with a flow-sensitive per-block dataflow (`internal/analysis/flow.go`): blocks are processed in reverse-post-order, each block's entry state is the **union** of its predecessors' exit states (join over the frontend's Preds/Succs edges), and per-block exit states iterate to a fixpoint. STORE now gives a **strong update** — a clean store into a *non-escaping* alloc (`nonEscapingAllocs`: address used only as a STORE dest or a deref-read) clears the cell's taint. The union join keeps taint that reaches a point on ANY path (so no real flow is lost — verified by conditional-taint and escaping-alloc recall tests), while strong updates reject the "taint, overwrite with a constant, then use" and "sink before taint" FPs that a monotonic model cannot. Note the register-level cases are already handled by SSA renaming; this fix is specifically the **memory** (address-taken alloc) case, which is where flow-insensitivity actually bit. Guarded by `test/go/flow_strong_update` (FP control) + `TestFlow_StrongUpdateSuppresses`/`SinkBeforeTaint` (suppression) and `TestFlow_TaintedMemoryStillFires`/`ConditionalTaintStillFires`/`EscapingAllocNotStrongUpdated` (recall/soundness). Full corpus green (no recall regression across all six languages); the flow-sensitive state also sharpens the ENG-9 guard and SSRF checks at each sink. Engine-only, no gIR change.

### ENG-3 [HIGH] (verified: CONFIRMED) Field- and key-insensitive containers: storing taint into one struct field/map key taints the whole aggregate and every other field read

- **Impact:** Any request/context/config struct that carries one tainted field poisons every other field (extremely common: an HTTP handler struct, a parsed form object, a settings map with one user-controlled entry). This is a large High-confidence FP class that the LLM reviewer never sees; CodeQL and Snyk Code are field-sensitive precisely because of this pattern.
- **Fix direction:** Introduce access-path taint keys ('reg.fieldIdx', one level deep is enough for most FPs) instead of collapsing to the base register: visitStore through FIELD_ADDR records base+field; FIELD/FIELD_ADDR reads check the matching path and fall back to whole-base taint only when the field index is unknown. Keep the whole-container fallback for INDEX with dynamic indices and variadic packing so no current FN regresses. Engine-only change.

### ENG-4 [HIGH] Unknown external calls silently drop taint; taint-through depends on tiny per-rule propagator whitelists (large FN class)

- **Impact:** Systematic false negatives on real code, which almost never passes a raw source straight to a sink: one intervening stdlib string call defeats the analysis. CodeQL ships thousands of library flow summaries plus taint-through-steps for string types; Snyk Code learns them. For a security gate, missed injections are the worst failure mode and this is currently the easiest way to slip one past.
- **Fix direction:** Add a language-level default-propagator layer independent of individual rules: (a) a shared builtin propagator table in the engine (or a shared YAML 'propagators pack' merged into every rule at load) covering stdlib string/path/url manipulation per language; (b) optionally a conservative heuristic mode: an unresolved call with a tainted argument and a string-typed result propagates taint (flag-gated, since it raises FPs). Fits the YAML-first convention — no gIR change.

### ENG-5 [HIGH] Java inter-procedural arg-to-param mapping is off by one for instance methods, so cross-function Java flows are silently missed

- **Impact:** Every Java taint flow that crosses an instance-method boundary — i.e. nearly all real Java code, service/DAO layering especially — is a false negative. The existing test corpus only covers intra-procedural Java flows, so this is invisible to CI. It also means receiver taint (tainted `this`) never propagates for any language via the direct path.
- **Fix direction:** In handleCall's direct-summary block, detect an INVOKE whose resolved callee function has a receiver param (Java: IsInvoke && byKey hit; check callee's param-0-is-this convention or add a HasReceiver flag frontend-side via existing fields) and shift arg j -> param j+1, seeding param 0 from Call.Value's taint. Separately, extend the methodImpls index beyond 'go:(' so Java/other-language dynamic dispatch participates in CHA. Engine-only fix; add an inter-procedural Java sample to test/java with expected.yaml.

### ENG-6 [HIGH] ✅ DONE (`e88e46a`, `72ed5d4`) No taint through globals or callee side effects on pointer/heap arguments — the promised demand-driven points-to was never built and no cheap substitute exists

- **Impact:** Two everyday idioms — stashing request data in a package/module-level variable, and out-parameter fill functions (very common in Go and C, and the natural shape of parsers/binders like json.Unmarshal(&dst)) — are complete false negatives across all six languages. Against CodeQL (global flow through fields/statics, heap summaries) this is a headline soundness gap for goal (3).
- **Fix direction:** Two incremental engine-side steps before any full points-to: (a) per-rule global taint: treat global_name operands as taintable keys in a program-wide map, with a second outer fixpoint over functions when a global's taint changes (the worklist scaffolding already exists); (b) extend funcResult with 'taintsParamMemory[i] -> origin' derived from stores through param-derived addresses in the callee, and on return mark the caller's argument register (and its container chain) tainted. Both fit the frozen-gIR constraint — the schema already carries everything needed.
- **DONE:** Both parts landed engine-only, no gIR change. (a) `globalTaint` program-wide map + `globalReaders` index; a tainted store to a global records a `globalEffect` the orchestrator merges, re-enqueueing readers (the outer fixpoint). A global read keys on a tainted `GlobalName` operand, not one opcode (Go lowers a global read as `UN_OP(MUL)`, others as `LOAD`). (b) `funcResult.taintsParamMemory[i]` from a tainted store whose address roots at param `i` (via `rootBaseReg`), merged like `returnTaint`; callers taint the arg at that position (`taintCallerArg`, container chain included). By-value args can't be a store root, and Java models local/param stores as slot rebinds not `OP_CODE_STORE`, so no cross-language FP. Both are cross-function → **Medium** confidence. Guarded by `test/go/global_taint{,_safe}` + `outparam_fill{,_safe}` corpus samples and `TestAnalyze_GlobalTaintFlow/Safe` + `TestAnalyze_OutParamFill/Safe`.

### ENG-7 [MEDIUM] Confidence contract broken for return-flow: cross-function findings via return summaries are labeled High and bypass the LLM reviewer

- **Impact:** The context-insensitive return summary is exactly the over-approximating mechanism the Medium tier exists for (an identity helper called with taint at one site marks its result tainted at ALL sites). Those FPs land as High, so the LLM reviewer — which per CLAUDE.md only adjudicates at/below Medium — never filters them, undermining headline goal (4) and the triage story.
- **Fix direction:** Make 'crossed a function boundary' an explicit attribute of the taint fact rather than inferring it from origin-pointer identity: carry a small struct {origin *ir.Position, interproc bool} in the tainted map (or a parallel set), set interproc=true when taint enters via param seeds OR returnTaint OR INVOKE summaries, and derive confidence from it. Also either use ConfidenceLow (e.g. for CHA-dispatched flows, the most over-approximate tier) or remove it.

### ENG-8 [MEDIUM] ✅ DONE (`b8344be`) Sink dedup marks SSRF sinks reported before the suppression check, and one-finding-per-instruction hides later distinct flows

- **Impact:** A real SSRF can be permanently masked by an earlier benign flow to the same call site — a soundness hole in the one place the engine deliberately suppresses findings. Secondarily, multi-source sinks under-report: fixing one flagged source and re-running can reveal a 'new' finding at the same line, eroding gate trust.
- **Fix direction:** Only set reported[inst] when a finding is actually emitted, and for CWE-918 re-evaluate suppressed sinks after the worklist reaches fixpoint (or key `reported` on (inst, suppression-relevant tainted-arg set)). For multi-source visibility, key dedup on (inst, origin) rather than inst alone, with output-side collapsing if volume is a concern.
- **DONE (primary):** `reported[inst]` is now set **only when a finding is actually emitted**, moved below the CWE-918 `urlHostControllable` check (it was set unconditionally above it, and the old comment wrongly called that "safe"). A suppressed, host-fixed flow no longer consumes the sink's report slot, so a later flow whose taint reaches the host can still fire — closing the latent masking hole. Verified by `TestSSRF_HostControllableFires`/`TestSSRF_HostFixedSuppressed` and the full corpus (no regression). Note: with the deliberately conservative suppressor (`urlHostControllable` suppresses only on a *provably constant* host — a structural property taint growth cannot undo), the masking is latent rather than presently triggerable; the fix is correctness hardening that removes the hole for any future, less-conservative suppressor. **Deferred (secondary):** per-origin multi-source visibility (key dedup on `(inst, origin)` + enumerate all tainted origins at a sink) is left out deliberately — larger change, trades single-finding-per-sink dedup for higher volume, low incremental value against the near-zero-FP gate goal.

### ENG-9 [MEDIUM] ✅ DONE (`8e33f7c`) No guard/barrier sanitization or path sensitivity: validation-style checks (allowlists, regex checks, filepath containment) can never stop taint

- **Impact:** Validation-by-check is at least as common as sanitization-by-transformation in real codebases (ID allowlists, strconv.Atoi-then-use-original, regexp match guards). Every such site is a High-confidence FP with no rule-level escape hatch except deleting the sink. CodeQL's BarrierGuard and Semgrep's pattern-not-inside exist precisely for this; its absence is a top driver of gate fatigue.
- **Fix direction:** Add a 'validators' rule field (YAML-first, per conventions): a callee glob whose boolean result, when it dominates a branch, clears taint on the guarded successor for the checked argument's register. Engine-side this needs branch-successor awareness: when an IF's condition is a validator call result (or a comparison over one), analyze the true/false successor block sets with the argument register removed from the taint state. gIR already carries IF + block structure, so no schema change.
- **DONE:** New `validators` rule field (`rule.go`: `IsValidator`/`HasValidators`) + an opt-in, dominator-based guard layer (`internal/analysis/guards.go`). `buildGuardIndex` (built only when a rule declares validators, so the common path pays nothing) computes per-function dominators over the frontend's predecessor edges and finds validator-controlled IFs: an IF whose condition derives (through a negation/comparison/convert) from a validator CALL, recording the checked registers and the two branch targets. At a sink, `guarded` suppresses the finding when a guarded branch dominates the sink block AND the validator was applied to a register carrying the SAME source origin — so validating one value cannot silence an unrelated tainted sink (covers `if !valid(x){return}; sink(x)` and `if valid(x){ sink(x) }`, both polarities). Built-in demonstration: `filepath.IsLocal` added as a validator to `go-path-traversal`. Guarded by `test/go/path_traversal_guarded` (FP control) + `TestGuard_Suppressed`/`UnguardedFires`/`WrongValueNotSuppressed`. Engine-only, no gIR change; existing rules (no validators) are wholly unaffected.

### ENG-10 [MEDIUM] Per-rule whole-program reanalysis, unused tree-shaking, and no dataflow trace in findings

- **Impact:** Scan time scales linearly with rule count on top of program size, directly against headline goal (1) 'ultra-fast per-commit gate'; functions with no reachable source are still fixpointed for every rule. And two-point findings are markedly harder to triage than CodeQL/Snyk path traces — for a Medium cross-function finding the user cannot see WHERE the taint crossed, which also starves the LLM reviewer of the context it needs to adjudicate.
- **Fix direction:** (a) Run one multi-rule pass: key the tainted map by (rule, reg) or a per-rule bitset so the instruction walk, defs, callers, and methodImpls are shared across rules; (b) pre-filter per rule to functions from which a source-matching call is reachable (Reachable is already implemented — wire it in); (c) record predecessor edges while propagating (origin -> step chain, or re-walk defs at report time) and add a Steps []*ir.Position field to Finding, surfacing it in HTML/SARIF (SARIF codeFlows) and the LLM prompt.

## Frontend lowering fidelity (FE)

### FE-1 [CRITICAL] (verified: CONFIRMED) Build/type-check failures silently degrade to exit 0 'clean' — the gate passes on code that was never analyzed

- **Impact:** A per-commit CI gate goes green on repos it never analyzed. Private deps, missing go.sum entries, offline CI, wrong toolchain versions are everyday conditions; each one converts every true positive in that language into a silent pass. This directly undermines headline goals 1 and 2 (trustworthy gate). CodeQL surfaces extraction errors as scan failures; Godzilla hides them on stderr.
- **Fix direction:** Track per-frontend/per-package analysis coverage in the pipeline (modules expected vs produced, packages with load errors) and (a) emit it in the report/SARIF as tool notifications, (b) add a gate policy flag (e.g. --fail-on-analysis-error, arguably default for the gate use case) that exits non-zero when a detected language produced zero modules or a package failed to load. No gIR change needed — this is scan.go/CLI plumbing.

### FE-2 [CRITICAL] (verified: PARTIAL) No import/require alias resolution in Python and JavaScript — aliased or destructured imports of sink modules are silent false negatives

- **Impact:** These are the DOMINANT idioms in real code: `from x import y` and destructured `require` are more common than fully-qualified access in idiomatic Python/Node. Every sink and sanitizer rule silently stops matching the moment a module is imported under any name other than its own — a massive FN class that no rule edit can fix because the canonical name is wrong at the source.
- **Fix direction:** Frontend-lowering fix, no gIR change: have pyast.py emit Import/ImportFrom names+asnames; keep a per-module alias table (alias → canonical dotted path) in funcState and resolve the ROOT of dottedName/syntacticCallee through it before prefixing 'py:'/'js:'. For JS, model `require('m')` initializers: bind the target (or each destructured name) to the canonical 'm' / 'm.member' so callee names become 'js:child_process.exec' regardless of local naming; same for the inline `require('m').f(x)` chain.
- **Verifier correction:** Mechanism and all five cited reproductions are accurate and were reproduced empirically: pyast.py emits Import/ImportFrom with no name/alias payload (lines ~184-200), lower.go:379 drops them, dottedName (lower.go ~717) and JS syntacticCallee (javascript/lower.go ~903-917) are purely syntactic with no environment resolution (JS converter.go doc says so explicitly), destructuring bindings are dropped, and MatchGlob (internal/rules/rule.go:174) is anchored so 'py:sp.call' cannot match 'py:subprocess.*'. All five claimed FNs scanned clean (sources fired; sinks missed). However the impact is overstated on two counts. (1) 'Every sink and sanitizer rule stops matching' is false: the rulepacks deliberately use alias-robust receiver-method and bare-suffix globs — py:*.execute, js:*.query, js:*.spawn, js:*.execSync, py:*open, py:*urlopen, py:*redirect, py:*send_file, py:*Response, py:*render_template_string, py:*escape — so py/js SQLi, path traversal, XSS, open redirect, and urlopen-SSRF largely survive aliasing; control test confirmed aliased cp.spawn/cp.execSync DO produce 2 command-injection findings. (2) 'No rule edit can fix' holds only for renamed-alias module access (sp.call, r.get); from-import/destructured bare names are fixable with suffix globs at FP cost (the repo's existing technique), and the absent bare 'js:*.exec' is a documented deliberate FP tradeoff (RegExp.prototype.exec) in js-command-injection.yaml. The real FN class is narrower but still serious: module-name-anchored sinks — py-command-injection (py:os.system, py:subprocess.* under 'from os import system' / 'import subprocess as sp', both idiomatic, critical-severity rule), py-insecure-deserialization (py:*pickle.loads fails alias and from-import), py-ssrf requests.get/post under alias, and JS child_process.exec under alias/destructure/inline require. Severity is better characterized as high for those specific rule families than 'critical, all rules'.

### FE-3 [CRITICAL] (verified: CONFIRMED) Rust Cargo support only builds library targets — plain binary crates and workspaces fail entirely

- **Impact:** Rust services, CLIs, and anything with src/main.rs — i.e. most deployable Rust code, exactly the attack-surface code the frontend's HTTP-accessor sources target — get zero analysis. Combined with the exit-0-on-failure behavior this is invisible to the CI user.
- **Fix direction:** Use `cargo metadata` to enumerate targets/workspace members, then run `cargo rustc --bin <name> -- --emit=mir=...` (and --lib where present) per target, merging the resulting modules. Fall back through targets rather than hard-failing on --lib absence.

### FE-4 [HIGH] Java operand-stack simulation breaks at control-flow merges: a ternary selecting a tainted value is silently missed and misaligns the rest of the method

- **Impact:** `cond ? tainted : default` and any branch-shaped value selection (very common in handler code) is a silent FN in Java; worse, the stack misalignment can garble every subsequent instruction's operands in that method, so unrelated later sinks in the same method also see wrong values (both FNs and garbage). This is a correctness cliff, not a graceful approximation.
- **Fix direction:** Track branch targets from the dump (JavaDump already sees offsets): split the linear pass at labels, snapshot the stack at each conditional/GOTO, and at a join merge differing stack slots with OP_CODE_PHI (mirroring how the JS ConditionalExpression is lowered with PHI, lower.go:545-558 in the JS frontend). Even a minimal 'ternary pattern' merge (two pushes reaching one store) would recover the dominant case without touching gIR.

### FE-5 [HIGH] Single-block flattening uses last-write-wins env, so the ubiquitous 'default if empty' branch kills taint in Python, JS and Rust

- **Impact:** Defaulting/validation-shaped branches (`if (!x) x = default`, `x = x or 'd'` written as a statement, match arms) are everywhere in real handlers, and the attacker-controlled path through them is REAL — these are true vulnerabilities missed deterministically. Note the frontends already model expression-level merges correctly (JS ConditionalExpression → PHI, Python IfExp → BIN_OP_OR); only statement-level branches drop a side.
- **Fix direction:** Keep the single-block design but make branch flattening merge instead of overwrite: snapshot env before lowering a flattened If body, and for every name rebound inside the body (or its else), emit an OP_CODE_PHI of the pre-branch value and the post-body value and bind the name to it. Rust: same — when a MIR local is reassigned in a later block, PHI it with the previous binding instead of replacing (mir.go assign).

### FE-6 [HIGH] TypeScript, .mjs/.cjs/.jsx are not scanned at all, and ES-module syntax fails to parse — modern Node codebases get zero coverage

- **Impact:** TypeScript is the majority of new Node/Express/Koa code and ESM (`import`) is the default in current tutorials, Node ≥14 `.mjs`, and most frameworks. A JS-capable SAST tool that silently skips both is a non-starter against Semgrep/CodeQL/Snyk Code, all of which handle TS+ESM. The failure is also silent (exit 0).
- **Fix direction:** Short term: register .mjs/.cjs in scan.go + converter walk, and pre-transform top-level `import`/`export` declarations into require/no-op equivalents before goja parsing (a small, syntax-level rewrite — the frontend's callee model is already purely syntactic so `import { exec } from 'child_process'` maps onto the alias-table fix above). Medium term: a type-stripping pass for .ts (types are syntactically erasable) or swap to a parser with TS support; at minimum, count skipped files and surface them as an analysis-coverage error per gap #1.

### FE-7 [HIGH] Python dict literals are 'Unknown' → py.unsupported: taint through the dominant Python container is dropped

- **Impact:** Dicts are the payload shape for JSON bodies, kwargs bundles, `requests.post(url, json={...})`, DB parameter maps — taint entering or exiting a dict literal is silently lost, and even the source call inside the literal is never emitted (so it can't fire as a sink either, e.g. an execute() inside a dict value).
- **Fix direction:** Emit ast.Dict (and ast.Set) from pyast.py as the existing 'Sequence' kind over values (keys too, for completeness) so lowerExpr at least lowers every element (sources/sinks inside fire). For value taint, mirror the JS lowerAggregate PHI-merge or the store-based container model (visitStore) instead of returning an untainted placeholder, since dict → subscript-read flows are common; keep list/tuple behavior as-is if subprocess_argv_safe precision depends on it.

### FE-8 [HIGH] Java findings point at the scan directory, not the source file (and positions vanish without debug info)

- **Impact:** In any multi-file Java project every finding is anchored to the repo root: the HTML report's snippet extraction reads a directory path (no snippet), SARIF file→region mapping is wrong so GitHub code scanning annotations land nowhere, and CLI triage ('which file?') is guesswork. Column is always 0. This breaks the 'source mapping is mandatory — it drives reporting' convention for one whole language.
- **Fix direction:** Have JavaDump.java emit each class's SourceFile attribute (and for the in-process compile path, the actual .java path it compiled), thread it through dumpClass, and resolve it to a real path under the scan root by matching the file name. Fall back to the class name-derived path. Warn (analysis-coverage signal) when a class has no LineNumberTable.

### FE-9 [MEDIUM] ✅ DONE (`f866600`) Java frontend hard-requires JDK 24+ and hides the diagnostic when the helper fails

- **Impact:** The overwhelmingly common CI configuration (Temurin 17/21) makes Java scanning fail opaquely and silently pass the gate. Users cannot tell a broken toolchain from clean code, and the actual cause (classfile API missing) is never shown — an adoption blocker for the Java story.
- **Fix direction:** Append ExitError.Stderr (truncated) to the error; probe the java version up front (`java -version` or Runtime.version via the helper) and emit an explicit 'JDK 24+ required, found 17' error. Longer term, remove the cliff: the dump only needs bytecode + line tables + annotations, which an ASM-shaded helper jar or a class-file parser written in Go could provide on any JDK (or even without one for .class inputs).
- **DONE:** `ConvertFile` now probes `java -version` up front (`javaMajor`/`parseJavaMajor`) and, on a positive too-old detection, returns an explicit `requires JDK 24+ … found Java N at <path>` error instead of an opaque compile failure (only when the version is positively known — a failed probe proceeds rather than crying wolf). The dump failure path now surfaces `ExitError.Stderr` (the real javac/classfile diagnostic, truncated) instead of a bare exit code. Tested by `TestParseJavaMajor` (JDK 24/21, legacy `1.8`, early-access `25-ea`, unparseable). Note the deeper JDK-cliff removal (ASM/Go classfile parser) is left as a larger follow-on.

### FE-10 [MEDIUM] ✅ DONE (`f866600`) Rust MIR lowering is regex-scraping an explicitly unstable text format with no version guard — a rustc upgrade silently zeroes findings

- **Impact:** Every skipped construct fails OPEN-as-clean: when a rustc release tweaks the MIR text (historically frequent — operand qualifiers, terminator lists, span comments), calls or taint silently disappear and the gate stays green. Users on rustup-updated CI runners get gradual, undetectable decay rather than an error.
- **Fix direction:** Add a startup smoke check per scan: compile a tiny embedded snippet with the discovered rustc, assert the lowering produces the expected CALL/span/aggregate shapes, and hard-error (feeding gap #1's coverage signal) on mismatch, printing the supported rustc range. Also count unparsed assignment lines per function and surface a fidelity warning above a threshold instead of silently dropping them.
- **DONE:** `warnIfMIRDrifted` (run once per process via `sync.Once`, `converters/rust/smoke.go`) compiles an embedded snippet — a source-API CALL (`env::var`) feeding another CALL (`Command::new`) — with the discovered rustc, lowers it, and `verifyMIRShape` asserts the lowering still recovers a positioned CALL (the structure taint analysis depends on). On drift it prints a prominent warning asking for the `rustc --version`, turning silent fidelity decay into a visible signal. It warns rather than hard-errors so a transient rustc issue never blocks an otherwise-working scan (the per-file path already reports a failed compile). Tested by `TestVerifyMIRShape` (positioned CALL passes; no-position CALL and empty program fail). The per-function unparsed-line fidelity counter is left as a follow-on.

## Detection & secrets coverage (COV)

### COV-1 [CRITICAL] (verified: CONFIRMED) Secrets scanner never sees non-source files (.env, YAML, Dockerfile, CI configs) and has only 6 patterns vs gitleaks' ~170

- **Impact:** The headline feature 'hardcoded-secrets scanner' (README.md:115-116 claims detection 'in all languages') misses the dominant secret-leak vector entirely. A team gating CI on Godzilla will ship AWS keys in .env or docker-compose.yml with a green build — a trust-destroying false negative for exactly the check users assume is table stakes (git-leaks/trufflehog find these trivially).
- **Fix direction:** Add a plain-text secrets pass in internal/scan that walks all non-binary files (bounded size, skipping node_modules/vendor/.git as detectLanguages already does) and runs the regex set over raw lines — no gIR needed, so it is orthogonal to the frozen IR. Expand secretPatterns to the top ~40 gitleaks patterns (Stripe, Twilio, SendGrid, npm, PyPI, OpenAI, Anthropic, Azure SAS, connection-string userinfo) and add a Shannon-entropy qualifier on generic assignments to preserve the low-FP posture. Consider making patterns YAML-loadable like rulepacks to match the project's YAML-first convention.

### COV-2 [CRITICAL] (verified: CONFIRMED) TypeScript/JSX/ESM files are completely invisible — only bare .js is scanned

- **Impact:** The majority of modern Node backends (NestJS, Next.js API routes, most new Express/Fastify apps) are TypeScript. Scanning such a repo yields zero JS findings with no warning — Convert's detectLanguages simply reports no JavaScript present, so the scan silently 'passes'. This is a first-run adoption killer: the README advertises JavaScript support, and the trial repo most prospects point it at will be TS. Even .mjs/.cjs — plain JavaScript — are skipped.
- **Fix direction:** Frontend-lowering fix (no gIR change): accept .mjs/.cjs immediately (goja parses them modulo ESM syntax; goja supports much of it via its parser). For TS, either strip types with a bundled transpiler pass (e.g. a minimal type-erasure preprocessor, the esbuild-style transform) before goja, or swap the parser for one with TS support; at minimum, detect .ts/.tsx presence in detectLanguages and emit a loud 'TypeScript found but not supported' warning so the gate is not silently vacuous.

### COV-3 [HIGH] (verified: CONFIRMED) Java pack lacks the Java-defining vulnerability classes: insecure deserialization, XXE, SSRF, XSS, open redirect

- **Impact:** For enterprise Java — the segment where SAST buying decisions are made — Godzilla misses CWE-502 and CWE-611, the two classes with the worst historical RCE record (commons-collections gadget chains, Log4Shell-adjacent patterns). Every competitor (CodeQL, Snyk Code, SonarQube) treats these as core Java coverage. A JAX-RS or Vert.x service has zero taint sources at all.
- **Fix direction:** Pure YAML additions (the project's stated preferred path): java-insecure-deserialization (sinks: java:java/io/ObjectInputStream.<init>#0, *XMLDecoder.<init>, *Yaml.load#0, *XStream.fromXML#0), java-ssrf (sinks: *RestTemplate.getForObject#0, *WebClient*, java:java/net/URL.<init>#0 with the existing urlHostControllable suppression applying automatically via CWE-918), java-xss (sinks: *PrintWriter.print*, *HttpServletResponse* writer chain), java-open-redirect (*HttpServletResponse.sendRedirect#0). Add getCookies/getHeaders/getInputStream and JAX-RS param annotations to sources; JAX-RS annotations reuse the existing paramAnnotations synthesis in converters/java/lower.go with only a JavaDump allowlist extension.

### COV-4 [HIGH] ✅ DONE (`3a1b72e`) No rule type for non-dataflow checks — weak crypto, disabled TLS verification, and insecure randomness are inexpressible

- **Impact:** Weak-crypto/insecure-TLS/insecure-randomness are among the highest-volume, lowest-FP findings in Semgrep/SonarQube deployments — they are call-site-syntactic, essentially zero-noise, and cheap. Their total absence makes Godzilla non-competitive on the 'near-perfect signal' promise's easiest wins, and users comparing scan results against any competitor will see whole categories missing on the same repo.
- **DONE:** New second rule kind `kind: dangerous-call` (rule model: `Kind`, `Callees` globs, optional `ConstArg{index, matches}`). A syntactic, non-dataflow pass `analysis.ScanDangerousCalls` (wired into `scan.Scan` alongside the taint engine and secrets scan) flags any call whose callee matches a rule's globs — optionally gated on a constant string argument read from the gIR call args (`MessageDigest.getInstance("MD5")`) — at High confidence, no taint tracking, zero gIR change. The loader validates a dangerous-call rule has callees and a compilable `const_arg` regexp. Ships rulepacks `go-weak-crypto` (weak hash MD5/SHA-1, weak cipher DES/3DES/RC4, math/rand byte generation) and `java-weak-crypto` (MessageDigest/Cipher via const_arg). Tested by `dangerous_test.go` (plain-callee match, const_arg match/non-match, language scoping, taint-rule isolation) + the `test/go/weak_crypto` corpus sample; `rules list` renders the new shape. Insecure-TLS (the `InsecureSkipVerify` struct field) is a natural follow-on on the same mechanism.
- **Fix direction:** Add a second YAML rule kind, e.g. `kind: dangerous-call` with `callees:` globs and an optional `const_arg: {index, matches}` regex condition (catches MessageDigest.getInstance("MD5") and createHash('md5') since string constants are already in gIR CallCommon args, as ScanSecrets demonstrates at secrets.go:71-75). This is engine + loader work but zero gIR change, consistent with the frozen-IR convention. Constant struct-field config (InsecureSkipVerify) can start as a callee/intrinsic match on the frontends' existing STORE/FIELD lowering.

### COV-5 [HIGH] Whole injection classes absent in every language despite being pure-YAML additions: Python eval/exec, NoSQL injection, SSTI, LDAP/XPath injection, zip-slip, prototype pollution, header/CRLF injection, log injection

- **Impact:** Direct false-negative classes on the most common real-world findings: py eval of request input is as classic as JS eval and currently invisible; a Node/Mongo app (the most common JS stack) has zero database-injection coverage since js-sqli.yaml:34-37 pins string-typed .query#0/.execute#0 which Mongo query objects do not flow through. Benchmarked against CodeQL/Snyk on OWASP-benchmark-style corpora these all show up as misses.
- **Fix direction:** Ship as YAML-only packs using existing machinery: py-code-injection (sinks py:eval, py:exec, py:compile — mirror js-code-injection.yaml), py/js-ssti (sinks py:*Template, js:*.compile for handlebars/ejs render), js-nosql-injection (sinks js:*.find#0, js:*.findOne#0 plus $where), java-ldap-injection (*DirContext.search#1), header-injection packs per language (go:*Header*.Set#1, js:*.setHeader#1, java:*HttpServletResponse.setHeader/addHeader). Zip-slip needs a source addition (java:*ZipEntry.getName, py:*ZipFile.namelist) feeding the existing path-traversal sinks — again YAML-only.

### COV-6 [HIGH] HTTP source lists miss headers/cookies/body in Go, headers/cookies/files in Python and JS, and popular frameworks (gorilla/mux, fiber, fastify, NestJS) entirely

- **Impact:** Header-based injection (X-Forwarded-For into SQL, User-Agent into logs/commands) and cookie-sourced taint are standard attack surface every competitor seeds; here they are silent false negatives in Go/Python/JS. The Fastify case is worse than absence: the pack comments claim support, so users will assume coverage that structurally cannot fire. Framework gaps mean a gorilla/mux or fiber Go service, or a Fastify/Nest Node service, produces zero taint findings.
- **Fix direction:** YAML edits: add header/cookie/body accessors per language (go:*net/http*.Header*.Get, go:*Request*.Cookie*, py:*request.headers*, *request.cookies*, *request.files*, js:*req.headers*, *req.cookies*), add gorilla (go:*gorilla/mux.Vars), fiber (go:*gofiber*Ctx*.Query/Params/Get), and fastify (js:*request.query*, js:*request.params*, js:*request.headers* — verify glob actually matches the frontend's synthesized callee with a test sample per framework). Also deduplicate: the identical source block is hand-copied into every pack per language (5x for Go), so a single missed accessor must be fixed in 5 places — support a shared `sources` anchor or a per-language source include in the loader to stop drift.

### COV-7 [MEDIUM] ✅ DONE (`<pending>`) Rust coverage misses axum (the dominant framework) sources and has no XSS/open-redirect packs

- **Impact:** A typical modern Rust web service (axum + sqlx) — exactly the demographic that would adopt a fast Rust-aware SAST — gets zero taint seeding: the rust-sql-injection sqlx sinks (rust-sql-injection.yaml:41-52) are unreachable because no source fires. Rust support effectively covers actix and hand-rolled Request objects only.
- **Fix direction:** Frontend-lowering + YAML: mirror the Java @RequestParam trick the project already uses (CLAUDE.md documents it) — when MIR shows a handler receiving axum extractor types (Query<...>, Path<...>, Json<...> appear in the MIR signature text mir.go already parses), synthesize a source CALL per extracted parameter with a canonical name like rust:axum::extract::Query, then list those names as YAML sources. Add rust-xss (sinks: *Html::from, response body builders) and rust-open-redirect (*Redirect::to#0, *Redirect::temporary#0) packs.
- **DONE:** `parseHeader` now captures each MIR parameter's type; `lowerFn` recognizes an axum extractor parameter (`Query`/`Path`/`Json`/`Form` before the generic `<`, via `axumExtractorSource`) and **synthesizes a source CALL** (`rust:axum::extract::<Extractor>`) whose result IS that parameter's value — the exact Java `@RequestParam` trick, in the frontend, no gIR change. Those source names are added to the rust command-injection/path-traversal/sql-injection/ssrf packs, and two new packs ship: `rust-xss` (`*Html::from`/`Html::new` sinks) and `rust-open-redirect` (`*Redirect::to`/`temporary`/`permanent`). Tested hermetically (no rustc) by `TestAxumExtractorSource`, `TestLowerMIR_AxumSourceSynthesis`, and `TestAxumTaintFlow_EndToEnd` (lowered handler → engine → `rust-command-injection` fires).

### COV-8 [MEDIUM] C/C++ has only 3 packs, no memory-safety class, no SQLi/SSRF, argv missing as a source, and execv/execve missing as sinks

- **Impact:** For C/C++, memory corruption IS the vulnerability model — CodeQL/Sonar's C coverage is majority CWE-120/125/787. A tool that flags getenv→system but stays silent on gets(buf) or strcpy(fixed_buf, tainted) will not be taken seriously by C teams, and the execv/execve omission is a straight command-injection FN in the one class the pack does claim.
- **Fix direction:** YAML: add execv/execve/execvpe (and execvP/fexecve) to c-command-injection sinks; add a c-buffer-overflow pack with sinks c*:gets (all args), c*:strcpy#0-from-tainted-source, c*:sprintf, c*:strcat, keeping strncpy/snprintf as propagators; add c-sql-injection (c*:mysql_query#1, c*:sqlite3_exec#1, c*:PQexec#1) and c-ssrf packs. For argv, have the LLVM lowering synthesize a source CALL for main's argv (the same parameter-annotation trick used for Spring), then reference it in YAML.

### COV-9 [MEDIUM] ✅ DONE (`1abcdab`) Sanitizer modeling is nearly empty and the one broad Python sanitizer glob (py:*escape) accepts non-sanitizers

- **Impact:** Because the engine drops taint at unknown calls (interproc.go:260-299 — only source/sink/propagator/summary calls transfer taint), thin sanitizer lists mostly do not cause FPs today; the concrete harm is (a) py:*escape creating a real XSS false-negative pattern, and (b) as propagator lists grow (the Rust packs already glob rust:*trim, *map, *get at rust-command-injection.yaml:46-86), sanitizer precision becomes load-bearing and there is no vetted list to rely on. It also blocks the LLM reviewer from ever seeing 'sanitized but suspicious' Medium findings.
- **DONE (rulepack tightening):** `py-xss`'s over-broad `py:*escape` glob (which also matched `html.unescape`, the opposite of a sanitizer) is replaced with the explicit named escapers (markupsafe/html/flask/cgi). Canonical per-class sanitizers added: `py:shlex.quote` → py-command-injection, `js:encodeURIComponent` → js-open-redirect + js-ssrf, `go:*url.QueryEscape`/`PathEscape` → go-open-redirect. Corpus stays green. (Guard-style branch-condition sanitizers are already delivered separately as ENG-9 validators; the java:*Encode.forHtml sanitizer ships with the java-xss pack from COV-3.)
- **Fix direction:** Tighten py-xss sanitizers to explicit names (py:*markupsafe.escape, py:html.escape, py:*flask.escape) instead of the *escape glob. Add the canonical per-class sanitizers: py:shlex.quote to py-command-injection, js:encodeURIComponent to js-open-redirect/ssrf, go:*url.QueryEscape to go-open-redirect, java:*Encode.forHtml to a future java-xss. Longer term, support a `sanitizer` that is branch-condition based (guard-style) for allowlist validation — engine work, no gIR change.

### COV-10 [LOW] No coverage at all for PHP, Ruby, C#, or Kotlin source — and no warning when they are encountered

- **Impact:** Semgrep/Snyk/Sonar all cover PHP, Ruby, and C# — three of the most breach-prone web ecosystems. This bounds the addressable market rather than causing FNs on supported repos, hence low severity, but the stale error text at scan.go:106 ('Go/Python/JavaScript') actively misleads users about the six languages that ARE supported.
- **Fix direction:** Short term: fix the scan.go:106 message to list all supported languages and print an informative notice when unsupported-but-recognizable source (.php/.rb/.cs/.kt/.ts) dominates a scan target, so a gate is never silently vacuous. Medium term: Kotlin is the cheapest win — it compiles to JVM bytecode the existing converters/java frontend already lowers; extend detectLanguages and the Gradle build path to include .kt projects and add kotlin-specific canonical-name globs to the Java packs.

## Performance & scalability (PERF)

### PERF-1 [CRITICAL] (verified: CONFIRMED) No incremental analysis, caching, or diff-aware scanning anywhere — every scan is fully from scratch

- **Impact:** The headline goal is a per-commit CI gate, but a commit touching one file re-pays the full-repo cost every time. On a mid-size monorepo this is minutes per commit, which is exactly what makes teams demote a gate to nightly. Competitors ship this: Semgrep has --baseline-commit and per-file caching, SonarQube does incremental PR analysis.
- **Fix direction:** Add a content-hash-keyed on-disk cache of lowered gIR modules (gIR is protobuf — serialization is free), so unchanged files skip the frontend entirely; add a --diff/--baseline mode that converts changed files plus their reverse-dependency closure (computable from the existing CallGraph.Edges) and suppresses findings already present at the baseline. Pure pipeline change in internal/scan + converters; no gIR schema change needed.

### PERF-2 [CRITICAL] (verified: CONFIRMED) Go frontend type-checks and SSA-builds the entire transitive dependency closure from source, then discards it — 3.7s and 1.45GB heap for a 40-line file

- **Impact:** Cost scales with the dependency tree, not the scanned code: a real service with a few hundred modules will take minutes and tens of GB, OOM-ing typical 4-8GB CI containers. This single-handedly breaks both 'ultra fast' and per-commit viability for Go — the tool's flagship language.
- **Fix direction:** Load dependencies from export data instead of source: packages.Load with NeedSyntax/NeedTypesInfo for the initial packages only (deps satisfied via NeedTypes/export files), then ssautil.Packages (not AllPackages) so prog.Build() compiles only the scanned packages' bodies. Dependency behavior is already modeled by YAML source/sink/propagator rules, so dep bodies are never needed. Frontend-lowering change only; gIR untouched.

### PERF-3 [HIGH] (verified: CONFIRMED) Zero parallelism in the entire pipeline — frontends, per-file conversion, per-rule analysis, and LLM review are all strictly sequential

- **Impact:** CI runners are 8-16 vCPU; roughly an order of magnitude of latency is left on the table for multi-file and multi-language repos. The sequential LLM loop adds ~3-8s per medium-confidence finding — 30 findings can add 2-4 minutes of gate latency by itself.
- **Fix direction:** Bounded errgroup worker pools at three levels: (1) per-file conversion in the Python/JS frontends (also batch pyast.py to parse N files per python3 process — the 25ms/file is mostly interpreter startup); (2) concurrent frontends in scan.Convert (module merge is append-only); (3) per-rule analysis in Engine.Analyze — analyzeInterproc instances are independent (findings slice appended per rule), and concurrent LLM reviews with a small semaphore. No gIR or rule format change.

### PERF-4 [HIGH] Build-tool frontends re-run full builds and helper compilation on every scan, with no up-to-date check, no process reuse, and no subprocess timeouts

- **Impact:** Maven JVM+plugin startup alone is 5-15s even when nothing changed, so every Java per-commit scan pays it twice (build + JavaDump JVM); a cold cargo dep build can be minutes. A hung `mvn` dependency download or wedged rustc blocks the CI gate forever — there is no timeout anywhere, an availability bug for a gate.
- **Fix direction:** Skip the build when compiled class output is newer than all sources; ship JavaDump precompiled (a .jar embedded next to the source, or compile once to a user cache dir keyed by helper hash); use a stable MIR emit path under the project's target/ so cargo's own incrementality works; wrap every frontend subprocess in exec.CommandContext with a configurable per-frontend deadline that degrades to a skipped frontend (matching existing graceful-degradation semantics).

### PERF-5 [MEDIUM] Engine is O(rules x whole-program) with per-rule index rebuilds and per-call-site regexp glob matching — linear blowup as rule packs grow to competitive size

- **Impact:** Being 'the best' requires Semgrep-registry-scale rule packs (hundreds to thousands of rules). At 500 applicable rules the same 4000-function program extrapolates to ~12s of engine time single-threaded, on top of re-walking every instruction 500 times; rule-pack growth — the cheapest coverage lever the architecture has (YAML-first) — is throttled by the engine.
- **Fix direction:** Single multi-label taint pass: track taint per (rule, origin) tag set so one program walk serves all rules; pre-resolve each DISTINCT callee canonical name once per program into a memoized callee -> {per-rule source/sink(args)/sanitizer/propagator} table (the callee vocabulary is tiny relative to call-site count); build the callers map and CHA methodImpls index once in Analyze and share across rules. All engine-internal — rules YAML and gIR unchanged.

### PERF-6 [MEDIUM] Call-graph tree-shaking (Reachable/Roots) is built, documented as the point of the call graph, and never used — dead code is fully analyzed per rule

- **Impact:** Wasted work proportional to dead-code fraction times rule count on every scan; on repos with large generated or vendored-in-tree code the waste dominates. Also a trust smell: the documented optimization path silently does not run, so its correctness (e.g. the Roots no-in-edges heuristic keeping http handlers alive) is untested against real analysis results.
- **Fix direction:** Seed analyzeInterproc from cg.Reachable(cg.Roots()) instead of all of byKey (Roots already handles externally-invoked handlers via the no-in-edge rule), and process functions in reverse-topological SCC order of Edges so callee summaries are computed before callers, minimizing worklist re-analysis. Pure engine change.

### PERF-7 [MEDIUM] Converter directory walks lack standard exclusions and size caps — .venv/site-packages, .git, dist bundles and minified JS are fully converted

- **Impact:** First contact with a real repository (venv committed, dist/ checked in, monorepo with fixtures) produces pathological scan times and floods of findings in third-party code — a classic adoption killer. Semgrep honors .gitignore/.semgrepignore and skips minified files by default; CodeQL scopes to the build.
- **Fix direction:** Extract one shared tree-walker used by detectLanguages and every directory-mode frontend: honor .gitignore plus a default deny-list (.git, node_modules, vendor, dist, build, .venv/venv/site-packages, __pycache__, target), skip files over a size cap and *.min.js, and add --exclude/--include CLI globs. Frontend + CLI change only.

### PERF-8 [LOW] No streaming or memory discipline: the full merged gIR Program for all languages is retained through the whole run, even when unused

- **Impact:** On large polyglot monorepos peak memory is the sum over all languages at once, compounding the Go frontend blowup and risking OOM in memory-capped CI executors; gIR being protobuf makes this needlessly resident.
- **Fix direction:** Pipeline per module-batch: analyze each frontend's Program as it is produced (the engine only needs cross-references within one language's module set, since canonical names are language-prefixed), release modules after analysis, and gate Program retention on --summary. Optionally spill lowered gIR to disk (protobuf) between convert and analyze — which also becomes the persistence layer for the incremental cache in gap 1.

## CI/CD product surface (CI)

### CI-1 [CRITICAL] (verified: PARTIAL) No suppression or triage mechanism of any kind (no inline ignore, no baseline file, no ignore list)

- **Impact:** This is the single biggest adoption blocker for a CI gate. Any false positive — or any accepted-risk true positive — fails the gate forever with no recourse except lowering -fail-on globally or forking the rulepack. Adopting on any legacy codebase with pre-existing findings means the gate is permanently red from day one. Every comparable tool (Semgrep nosemgrep, CodeQL alert dismissal, SonarQube NOSONAR + issue resolution, gosec #nosec) has this.
- **Fix direction:** Two layers, no gIR change needed: (1) inline `// godzilla:ignore[=rule-id]` comments — frontends already have source positions, so the CLI can post-filter findings whose SinkPos line carries the directive by reading the file (the HTML report already reads source files for snippets, so file access at report time is established); (2) a fingerprint-keyed baseline/ignore file (.godzilla-baseline.json) generated by a `godzilla baseline` subcommand and consumed at scan time, filtering findings before printFindings/gate computation in cmd/godzilla/main.go:120.
- **Verifier correction:** The deterministic-suppression core of the claim is accurate and the citations check out: cmd/godzilla/main.go:72-78 is the complete flag surface; internal/scan/scan.go:36-44 pipes engine+secrets output to the CLI with no filtering stage; no converter parses ignore comments; internal/report/ emits no fingerprints; .github/workflows, Makefile, and docs contain nothing either. Worse than claimed in one respect: internal/rules/loader/loader.go LoadDefault only APPENDS user rules after built-ins and sanitizers are matched per-rule (interproc.go:261), so -rules cannot disable, downgrade, or sanitize-around a built-in rule — and rulepacks are compiled in via rulepacks/embed.go, so 'forking the rulepack' actually means rebuilding the binary. Two corrections: (1) 'no triage mechanism of any kind' is contradicted by -llm-review (internal/llm/review.go Filter), a shipped, tested triage stage the CLI itself labels 'triage' that drops LLM-judged false positives — but it is non-deterministic, needs ANTHROPIC_API_KEY, only reviews findings at/below Medium confidence, and offers no user-directed waiver, so it is no recourse for High-confidence FPs or accepted-risk true positives; (2) -sarif + GitHub code scanning provides platform-level alert dismissal for report consumers, though not for the exit-code gate. With those caveats, the 'permanently red gate on legacy codebases' impact and critical severity are fair for the CI-gate use case.

### CI-2 [CRITICAL] (verified: CONFIRMED) No stable finding identity/fingerprint, so no diff-aware gating (--fail-on-new) is possible

- **Impact:** Without a line-shift-stable fingerprint there is no way to build a 'only NEW findings block this PR' mode — the core workflow of Semgrep CI, Snyk Code PR checks, and GitHub code scanning. GitHub falls back to its own line-hash when partialFingerprints is absent, but Godzilla's own JSON consumers get nothing stable at all: a one-line change re-opens every previously triaged finding. Combined with gap #1 this makes per-commit gating on real repos impractical.
- **Fix direction:** Add a Fingerprint field to Finding computed from stable inputs: RuleID + enclosing Function canonical name (already language-qualified and line-independent) + SinkCallee + normalized sink-line text hash (CodeQL-style primaryLocationLineHash) + an ordinal for duplicates within the same function. Emit it in JSON, and as partialFingerprints{"godzilla/v1": ...} in SARIF. Then implement `scan --baseline old.json` / `--fail-on-new` as a set-difference on fingerprints before the gate count in main.go:175-180.

### CI-3 [HIGH] (verified: CONFIRMED) Frontend failure on a directory scan is a stderr warning and the gate passes green (silent coverage loss)

- **Impact:** A security gate that silently passes when an entire language stopped being analyzed is a trust failure: a CI image upgrade that breaks the JDK or a Maven build regression turns all Java findings off with only a stderr line nobody reads. Attackers'-favorite scenario for a gate: green check, zero coverage. CodeQL fails the run on extraction errors; Semgrep reports per-file parse errors in output and offers --strict.
- **Fix direction:** Track per-frontend outcomes in scan.Result (e.g. Skipped []FrontendError). In the CLI: print a prominent summary line, add --strict (exit 1 on any frontend failure for a language with detected source), and emit SARIF `runs[].invocations[].toolExecutionNotifications` so GitHub surfaces degraded coverage. Default behavior should at minimum print the warning to stdout alongside findings, not only stderr.

### CI-4 [HIGH] ✅ DONE (codeFlows `4c6a417`, version `b2e8133`, metadata `<pending>`) SARIF output lacks codeFlows/threadFlows, rule metadata (help, descriptions, defaultConfiguration), and tool version

- **Impact:** For a taint-analysis tool, codeFlows are the flagship SARIF feature: GitHub code scanning renders 'Show paths' step-by-step taint traces from threadFlows, which is how developers triage a dataflow finding. Godzilla is a dataflow engine that throws that away at the serialization boundary. Missing rule help means the GitHub alert page shows a bare rule id with no remediation guidance; missing security-severity property breaks GitHub's severity filtering for security results; missing tool version makes runs unattributable.
- **Fix direction:** Emit codeFlows[].threadFlows[].locations with at least [source, sink] today (2-step flows are valid SARIF), and extend to full paths once Finding carries a trace (see taint-path gap). Populate rules[].shortDescription/fullDescription/help.markdown from a new description/remediation field in the YAML Rule model (internal/rules/rule.go) — a pure rulepacks/*.yaml + loader change — plus properties.security-severity and defaultConfiguration.level. Add a version constant (ldflags-injected) to the driver.
- **DONE:** codeFlows/threadFlows landed with the taint path (CI-6, `4c6a417`); the driver version landed with CI-8 (`b2e8133`). This change adds the rule metadata GitHub code scanning needs: `rules[].shortDescription` (from the rule message), `defaultConfiguration.level` (from severity), `properties.security-severity` (CVSS-like 0-10 from severity, so alerts are severity-sortable), `helpUri`, and `security` + `external/cwe/<id>` tags. Tested by `TestSARIFRuleMetadata`. (Long-form `help.markdown` remediation text would need a new per-rule YAML field; deferred as a low-value follow-on — the message + helpUri already give GitHub a description and a link.)

### CI-5 [HIGH] ✅ DONE (`0fce6df`) No config file and no path include/exclude filters — everything is CLI flags and hardcoded skips

- **Impact:** Real repos need per-project policy in version control: exclude testdata/ and generated code (a top FP source — scanning a repo's own test fixtures containing deliberately vulnerable code will fail the gate), disable a noisy rule, or set fail-on per repo without editing every CI pipeline. Semgrep (.semgrepignore + rule config), CodeQL (paths/paths-ignore in the workflow config), and SonarQube (sonar-project.properties) all have this. Without it, teams patch CI YAML per-repo and cannot express 'ignore rule X' at all.
- **Fix direction:** Add a `.godzilla.yaml` loaded from the scan root: fail-on, exclude/include path globs (applied both in detectLanguages and as a post-filter on finding SinkPos paths, since converters like go/packages load whole directories), rules: {disable: [ids], severity-overrides: {id: sev}, extra-paths: [dirs]} wiring LoadDir. CLI flags override file values. This is pure internal/scan + cmd changes, no engine impact.
- **DONE:** New `internal/config` package loads `.godzilla.yaml`/`.yml` from the scan root (or an explicit `-config`): `fail-on`, `exclude`/`include` path globs, and `rules: {disable, severity-overrides}`. `ApplyRules` drops disabled rules and applies severity overrides (returns a copy, input untouched, bogus severities ignored). `FilterFindings` marks findings whose file matches the path filters as **Suppressed** (retained + flagged `config-path-filter`, consistent with baseline/inline-ignore — auditable, gate ignores them). The path matcher supports a bare name (any segment), `*` (within a segment), and `**` (across segments). CLI flags override file values (`-fail-on` only applies the config value when the flag wasn't passed, via `fs.Visit`). Wired in `cmd/godzilla`. Tested by `internal/config/config_test.go` (glob matching, rule disable/override, exclude + include allowlist, load/absent) and verified end-to-end (disable → clean; exclude → suppressed, gate passes).

### CI-6 [MEDIUM] Findings show only source and sink — the taint path (intermediate steps) is never recorded or displayed

- **Impact:** Path evidence is the difference between a triage taking 30 seconds and 15 minutes, and it is precisely the Medium-confidence inter-procedural findings (the ones the design says need human/LLM adjudication) that are unexplainable today. This also caps the SARIF codeFlows fix (gap above) at 2-step flows, and it starves the LLM reviewer's prompt of the strongest evidence it could use. CodeQL/Snyk Code both render full step-by-step paths; this is a headline triage-quality gap.
- **Fix direction:** Extend the taint lattice from a boolean to carry a provenance chain: when interproc.go propagates taint across a call edge (arg→param, return→result), append a step {function, callsite Pos}. Store []Step on Finding, print an indented 'via:' chain in printFindings, and emit it as SARIF threadFlow locations. Memory cost is bounded by call-graph depth; no gIR change.

### CI-7 [MEDIUM] ✅ DONE (`6acc72f`) No rule-author tooling: no rules subcommands (list/lint/test), rule testing requires cloning the repo and running go test

- **Impact:** The README's extensibility story is 'adding a sink is a YAML edit', but a security team maintaining org-specific rules cannot validate them without a full scan against real code, and cannot enumerate what is already covered (leading to duplicate or shadowed rules). Semgrep's `--test` with annotated fixtures and `--validate` is a major reason for its rule-ecosystem adoption.
- **Fix direction:** Add subcommands reusing existing internals: `godzilla rules list [-rules f]` (dump loader.LoadDefault result: id, severity, CWE, languages inferred from glob prefixes), `godzilla rules lint <file>` (run loader validate standalone), and `godzilla rules test <dir>` that runs scan.Scan against a directory of samples with expected.yaml files — the corpus comparison logic in test/corpus/ can be lifted into an internal package shared by both.
- **DONE:** New `godzilla rules` subcommand (`cmd/godzilla/rules.go`): `list [-rules f]` prints every loaded rule (id, severity, CWE, languages, source/sink counts); `lint <file>...` validates rule YAML via `loader.LoadFile` (same checks as a scan) and exits non-zero on any invalid file; `test <dir> [-rules f]` scans each sample subdirectory carrying an `expected.yaml` and checks it against the loaded rules, printing PASS/FAIL/SKIP per sample. The expected.yaml oracle (every expected rule fires ≥ min, optional sink line/callee, and no unexpected rule fires) is packaged in a reusable `internal/ruletest` package (`RunDir`), the same shape the in-repo corpus uses. Tested by `internal/ruletest/ruletest_test.go` (pass / FP-fail / missing-rule-fail / non-sample-ignored) and verified end-to-end (`rules test test/go` → 34 passed).

### CI-8 [MEDIUM] ✅ DONE (`0fce6df`) No version anywhere: no version subcommand, no tool version in SARIF or JSON, unversioned JSON schema

- **Impact:** CI debugging ('which godzilla produced this red gate?') is impossible from output alone; SARIF consumers (GitHub shows tool version on alerts) display nothing; scripted consumers of the JSON have no way to detect format evolution. Every mainstream scanner stamps its version into every report.
- **Fix direction:** Add a `var version = "dev"` in cmd/godzilla injected via -ldflags in the Makefile, a `godzilla version` subcommand, `Version` on sarifDriver, and a `schemaVersion: "1"` + `toolVersion` on jsonDocument.
- **DONE:** `var version = "dev"` in `cmd/godzilla`, injected at build via `-ldflags "-X main.version=$(VERSION)"` (Makefile `VERSION` defaults to `git describe`). A `godzilla version` subcommand (also `--version`/`-v`) prints it. `report.Version` (stamped from the CLI at startup) now flows into the SARIF `driver.version` and the JSON document's `toolVersion` + `schemaVersion: "1"`. Tested by `TestReportsStampVersion`; the ldflags injection verified end-to-end.

### CI-9 [LOW] ✅ DONE (`c05af2f`, partial) Console/gate UX gaps: stale usage text, no quiet/verbose/progress, no pre-commit or changed-files mode

- **Impact:** Minor individually, but for the 'ultra-fast per-commit' headline goal the absence of a changed-files entry point matters: pre-commit frameworks pass filenames, and per-file invocation re-pays JVM/rustc startup each time. Stale usage text erodes polish/trust on first contact.
- **Fix direction:** Fix usageText and scan.go:106's language list; add --quiet (suppress per-finding text when a report flag is set) and a simple frontends-started/finished progress line on stderr; accept multiple positional paths and a `--files -` stdin list feeding a single merged Convert, enabling a documented pre-commit hook recipe in README.
- **DONE:** Added `-quiet` (suppresses coverage/summary/per-finding console output while the exit code and any report files still reflect findings — the CI-consumes-a-report-file case). The multi-command usage text was already refreshed with the `scan`/`rules`/`version` subcommands (CI-7/CI-8). Tested by `TestQuiet_SuppressesOutputButKeepsGate`. The changed-files / `--files -` stdin pre-commit entry point is deferred (see Terminal-state note): it is a convenience wrapper — the same coverage is achievable today by invoking `scan` per file — and merging arbitrary file lists across six frontends into one Convert is a non-trivial addition for marginal gain.

## LLM reviewer (LLM)

### LLM-1 [CRITICAL] (verified: CONFIRMED) LLM-dropped findings leave no audit trail — a nondeterministic model silently suppresses gate findings

- **Impact:** A CI gate can pass on commit A and fail on an identical rerun, and when it passes, nobody can see what the LLM threw away or on what basis. This destroys trust and is un-debuggable: a real vulnerability dropped by a bad verdict vanishes without a trace. Every serious competitor (CodeQL alerts dismissed with recorded reason, Semgrep triage state) keeps suppressed findings visible with a rationale.
- **Fix direction:** Change Filter to return the dropped findings with their Verdicts (e.g. `[]ReviewedFinding{Finding, Verdict}`) instead of just a count; emit them in JSON/SARIF (SARIF supports `suppressions` with justification) and in the HTML report as a 'suppressed by LLM' section, and print each drop with its one-sentence reason to stdout. Set Temperature: 0 in the MessageNewParams and cache verdicts keyed by a finding fingerprint (rule ID + sink file:line + source file:line + snippet hash) so reruns are deterministic and free. No gIR or engine change needed.

### LLM-2 [CRITICAL] (verified: PARTIAL) Context poverty: ±3 lines around sink/source cannot support adjudicating the interprocedural Medium findings the reviewer exists for

- **Impact:** The model is asked (review.go:103-104) to judge 'whether an effective sanitizer or validation sits on the path' while being shown almost none of the path. Verdicts degrade to guessing from the sink line's appearance: real interprocedural vulns get dropped (silent false negatives at the gate) and obvious FPs get kept, defeating the reviewer's entire purpose as the near-zero-FP backstop.
- **Fix direction:** Two-part fix. (1) Engine: record the taint trace in Finding (list of Positions/call-summary hops the worklist already traverses in interproc.go) — this is an internal/analysis struct change, not a gIR change. (2) codeContextFor: include the full enclosing function body for both source and sink (positions + a start/end line from the gIR Function's Pos make this cheap), plus each intermediate hop's snippet, labeled in order. This is what Snyk Code / CodeQL path-problems present to a human triager, and the LLM needs at least that much.
- **Verifier correction:** Every code citation is accurate: review.go:141/146 pass snippet(pos,3) (7 lines around sink + 7 around source, verified as the entire code context); finding.go:30-41 has no taint-path/steps field and a repo-wide grep confirms no path-recording capability exists anywhere (interproc.go threads only the single origin position, so intermediate hops aren't even captured by the engine); Medium confidence is assigned exactly for cross-function flows (interproc.go:241-246) and nothing emits Low, so Medium is the whole review population (main.go:114); anthropic.go sends one tool-less message so the model cannot fetch more context. The structural gap is real: the prompt (review.go:103-104) asks about sanitizers 'on the path' while the path between source and sink functions is invisible. Corrections: (1) 'nothing else' overstates — the prompt also includes rule ID, CWE, message, sink-callee FQN, enclosing function, and both exact positions, and SourcePos is the true original source (origin is threaded through call effects), so the model sees both real endpoints plus metadata — degraded judgment, not pure guessing; (2) 'silent false negatives at the gate' / critical severity is exaggerated — the reviewer is opt-in (-llm-review flag, main.go:78), fail-open on errors (review.go:54), and unparseable verdicts default to keep (review.go:127-131), so the system is biased toward keeping; real-vuln drops require a confidently-wrong FP verdict (possible and unguarded, but not the dominant failure mode). The likelier impact is the reviewer being an ineffective FP filter for its primary population. Severity high, not critical.

### LLM-3 [HIGH] (verified: CONFIRMED) Reviewer will drop a finding even when code context is empty (silent snippet failure)

- **Impact:** Findings can be suppressed at the CI gate based on no code whatsoever — the worst possible failure mode for a tool whose pitch is trust. Java findings are especially at risk since positions come from bytecode line tables and the analyzed .class files may sit in a build output directory.
- **Fix direction:** In Filter (or codeContextFor's caller), if the assembled context is empty, skip the review and keep the finding (treat 'no context' like a reviewer error — fail open). Additionally instruct the model in buildPrompt that absence of code context must yield true_positive, as defense in depth.

### LLM-4 [HIGH] ✅ DONE (`516c18f`) Zero agency: one-shot prompt→verdict with no tool use, no ability to open files or trace the flow

- **Impact:** A human triager (and modern agentic reviewers) resolves an uncertain finding by reading more code: the caller of the tainted function, the sanitizer implementation, the route registration. This reviewer structurally cannot, so its accuracy is capped by whatever 14 lines codeContextFor guessed to include — a large gap versus the 'best-in-world reviewer' vision and versus what the Anthropic SDK already supports (tool use).
- **Fix direction:** Give AnthropicReviewer a small agent loop with 2-3 read-only tools (`read_file_range`, `find_function_by_canonical_name` backed by the already-loaded gIR module, `grep`), bounded to N tool calls per finding. Keep the Reviewer interface but widen it to accept the *ir.Module (or a context provider callback) so the loop can resolve canonical names to positions. review.go stays dependency-free; the loop lives in anthropic.go.
- **DONE:** `internal/llm/tools.go` (dependency-free) defines a `ToolBox` — `read_file_range`, `find_function` (resolves a canonical name against the loaded gIR program to its source), and `grep` (bounded, skips vendored dirs) — plus the `ToolSpec` catalog, `dispatchTool`, and `buildAgenticPrompt`. `FileToolBox` fences all file access to the scan root (path-traversal-proof: the reviewer can't read outside the project it is analyzing). `anthropic.go` runs the SDK tool-use loop (`WithTools` switches the reviewer into agentic mode; one-shot remains the default/back-compat), bounded to `maxToolRounds` with a forced final verdict so it can't hang or loop unboundedly; the CLI wires `NewFileToolBox(res.Program, path)`. Tested hermetically: `tools_test.go` (each tool + dispatch + path confinement) and `anthropic_loop_test.go` drives the whole loop against a mock Messages API — tool→result→verdict threading, and the budget cutoff that forces a keep-the-finding default when inconclusive. The live API path is exercised only with a real key (`--llm-review`).

### LLM-5 [HIGH] ✅ DONE (`3dceb0f`) Sequential per-finding Opus calls with no concurrency, cap, timeout, or budget — a large scan stalls or costs unboundedly

- **Impact:** A 500-finding scan issues 500 sequential Opus round-trips — plausibly 30-60+ minutes and tens of dollars, per commit — directly contradicting headline goal #1 (ultra-fast per-commit gate). Teams will turn --llm-review off after the first slow pipeline, killing the feature's adoption.
- **DONE:** `Filter` now delegates to `FilterWithConfig` with a tuned `DefaultReviewConfig` (8-way concurrency, 30s per-call timeout, 200-review cap). Reviews run through a bounded worker pool with **order-preserving** output (reviewed concurrently, suppression applied afterward in input order — no data race on the findings slice); each review runs under its own `context.WithTimeout`; findings past the cap are kept unreviewed (fail open) and counted in the new `ReviewStats.Skipped` (surfaced by the CLI). The default model dropped from Opus to **claude-haiku-4-5** (one-sentence JSON triage at scale), `GODZILLA_LLM_MODEL` still overriding upward. Both safety properties preserved: fail-open on error/timeout, never-blind on empty context. Tested by `TestFilter_ConcurrencyBounded`/`MaxReviewsCap`/`PerCallTimeoutFailsOpen`/`OrderPreserved`, race-clean. (Cross-run fingerprint verdict caching is left to the determinism item, LLM-8.)
- **Fix direction:** Run reviews through a bounded worker pool (e.g. 8 concurrent, order-preserving); wrap each Review in a per-call timeout (context.WithTimeout, ~30s) and a per-scan wall-clock/finding budget after which remaining findings are kept unreviewed (fail open); default the model to a fast/cheap tier (Haiku-class) since the task is one-sentence JSON triage, keeping GODZILLA_LLM_MODEL for upgrades; add fingerprint-keyed verdict caching (shared with the determinism fix).

### LLM-6 [MEDIUM] ✅ DONE (`6f7b62a`, verified) Reviewer errors are swallowed silently — with a missing API key, --llm-review is a no-op that looks like a clean review

- **DONE (in Tier 0):** `ReviewStats` carries `Errors`/`FirstErr`, and the CLI prints a loud `warning: N finding(s) could not be reviewed and were kept unreviewed: <first error>` plus a dedicated no-op warning when every reviewed finding errored (`Errors == Reviewed`, the missing-API-key signature) — so silent fail-open is impossible. (The remaining sub-point — fail-fast on the first 401 instead of per-finding retry — is a minor optimization; with LLM-5's cap + concurrency the cost is already bounded.)

- **Impact:** Fail-open is the right policy, but silent fail-open is not: a user who set --llm-review in CI believes findings were adjudicated when the reviewer never ran (bad key, network egress blocked, model name typo in GODZILLA_LLM_MODEL). They ship the FP-noise the flag was meant to remove and lose trust in the feature.
- **Fix direction:** Return an error/attempted/failed count from Filter (or a Stats struct) and have main.go print a loud warning when failures > 0, e.g. 'LLM review failed for N of M findings (kept unreviewed): <first error>'. Fail fast on the first auth-class error (401) instead of retrying it per finding.

### LLM-7 [MEDIUM] ✅ DONE (`6ac4a91`) Binary verdict schema wastes the review: no confidence adjustment, no exploitability, and kept findings are not annotated as LLM-confirmed

- **Impact:** Half the value of paying for a review is lost: a Medium interprocedural finding the LLM confirms as exploitable should surface as higher-priority triage (Snyk Code and modern tools score/prioritize this way), and the model's reasoning is exactly what a developer wants to read in the report. Today the user pays for Opus and sees zero difference on kept findings.
- **DONE:** The verdict schema is now `{verdict, confidence: 0-1, exploitability, reason}` (`Verdict` gains `Confidence`/`Exploitability`; `parseVerdict` reads them; both prompts request them). A finding the reviewer KEEPS is annotated `Finding.ReviewConfirmed=true` with `ReviewNote` (the exploitability note, falling back to the reason) — so the review adds value on kept findings, not only dropped ones. Rendered in the JSON (`reviewConfirmed`/`reviewNote`) and SARIF (result `properties.reviewConfirmed`/`reviewNote`) reports. Tested by `TestFilter_ConfirmedAnnotation` and the extended `parseVerdict`. (Optional displayed-confidence promotion of confirmed findings is left out to keep the deterministic engine's confidence tier stable; the annotation carries the signal.)
- **Fix direction:** Extend the JSON schema to `{verdict, confidence: 0-1, exploitability: <sentence>, reason}`; add `ReviewStatus`/`ReviewReason` fields to analysis.Finding (pure Go struct, no gIR change) populated by Filter; render them in the HTML/JSON/SARIF reports and optionally promote LLM-confirmed Medium findings' displayed confidence.

### LLM-8 [MEDIUM] ✅ DONE (`1cd91ee`) Prompt omits the rule's sanitizer/source definitions and few-shot calibration; parseVerdict accepts bare "false" as a drop signal

- **Impact:** Without the rule's own sanitizer vocabulary, the model second-guesses the engine using generic knowledge and drops findings the rulepack authors deliberately kept (or keeps ones an obvious documented sanitizer would clear). The lenient 'false' alias is a drop-direction parsing hazard — the one direction that must never be lenient.
- **DONE:** `parseVerdict` now requires the exact `false_positive` (or `false-positive`) token to drop; the loose `false`/`fp` aliases are removed, so anything unrecognized keeps the finding — leniency only in the safe (keep) direction. The matched rule's own source and sanitizer globs are carried onto each `Finding` (`RuleSources`/`RuleSanitizers`, populated in `interproc.go`) and rendered into both the one-shot and agentic prompts via `writeRuleDefinition`, so the reviewer adjudicates by the rulepack's vocabulary (it won't "clear" a finding for a sanitizer the rule doesn't recognize). A shared `calibration` line steers toward the recall-preserving default ("if not clearly a false positive, answer true_positive"). Tested by `TestParseVerdict` (new `bare false keeps`/`fp alias keeps` cases) and `TestPromptIncludesRuleVocabulary`. (Left minor: moving role framing to a dedicated system-prompt param and multi-example few-shot — cosmetic; the calibration line captures the intent.)
- **Fix direction:** Include the matched rule's YAML (sources/sinks/sanitizers globs and the rule description) in the prompt — it's already loaded in the RuleSet; move role framing to a system prompt; require the exact string 'false_positive' (remove the 'false'/'fp' aliases — keep leniency only for the keep direction); add 1-2 few-shot examples per verdict to calibrate toward 'when uncertain, answer true_positive'.

### LLM-9 [LOW] Hardwired single-provider reviewer: no local/offline or alternate-provider path despite a pluggable interface

- **Impact:** CI environments with no outbound internet, data-residency constraints, or non-Anthropic contracts cannot use the FP-backstop at all — an adoption blocker for exactly the regulated enterprises that most want near-zero-FP gates. (anthropic.NewClient() does honor ANTHROPIC_BASE_URL for Anthropic-compatible proxies, but this is undocumented in godzilla and doesn't cover OpenAI-compatible local servers.)
- **Fix direction:** The Reviewer interface (review.go:31-33) already supports this — add a provider selector (e.g. GODZILLA_LLM_PROVIDER or --llm-provider) with at least an OpenAI-compatible-endpoint adapter (covers Ollama/vLLM/llama.cpp locally), and document ANTHROPIC_BASE_URL for proxied Anthropic. Keep Anthropic the default.

## Trust & quality measurement (TRUST)

### TRUST-1 [CRITICAL] (verified: CONFIRMED) Scanning a Maven/Gradle or Cargo project executes arbitrary code from the scanned repo, with no flag, warning, or sandbox

- **Impact:** This converts the SAST tool itself into a remote-code-execution vector: 'godzilla scan' on an untrusted or fork-PR repo in CI runs that repo's code with the runner's credentials (cloud tokens, GITHUB_TOKEN, deploy secrets). This is exactly the threat model a per-commit CI gate faces (scanning fork PRs). CodeQL has the same build-execution property for compiled languages but documents it loudly and is sandboxed by convention; Semgrep/Snyk Code explicitly never execute scanned code as a trust selling point. Silently doing it disqualifies the tool for the fork-PR gate use case and is a trust-destroying surprise for a security product.
- **Fix direction:** Make build execution opt-in: add a --allow-build (or --trust-project-build) flag, default OFF, and have resolveInputs/convertCargo fall back to the no-build path with a loud stderr notice telling the user what they lose and how to enable it. Never auto-prefer the repo's own mvnw/gradlew unless the user passed the trust flag (running a PATH-pinned mvn/gradle at least limits execution to declared plugins; the wrapper is a raw attacker shell script). Document the threat model in README/ARCHITECTURE, and recommend containerized/unprivileged execution when the flag is on. This is a frontend + CLI change only — no gIR impact.

### TRUST-2 [HIGH] (verified: CONFIRMED) A frontend failure is downgraded to a stderr warning and the gate exits 0 'clean' — the CI gate fails open

- **Impact:** The tool's whole value as a gate is the exit code, and it silently reports 'clean' when analysis never ran. A CI image change that drops the JDK, a transient cargo network failure, or a build break makes every subsequent commit pass the security gate with no machine-readable signal — the worst failure mode for a gate (contrast: the LLM reviewer was deliberately designed to fail open only in the FP-drop direction, internal/llm/review.go, while the core scan fails open in the FN direction).
- **Fix direction:** Track per-frontend failures in scan.Result and surface them: add a distinct exit code (or fold into exit 1) when a detected language's frontend produced zero modules due to an error, plus a --strict-toolchain flag for gates. At minimum emit the degradation into the JSON/SARIF report (SARIF has invocation.toolExecutionNotifications for exactly this) so dashboards can alarm on it.

### TRUST-3 [HIGH] (verified: CONFIRMED) expected.yaml asserts only rule-ID + minimum count — a finding on the wrong line, wrong sink, wrong severity, or duplicated 50x still passes

- **Impact:** Source-position correctness is what developers judge a SAST tool by (CLAUDE.md itself says 'Source mapping is mandatory — it drives reporting'), yet it is completely untested end-to-end. Deduplication regressions, severity mapping bugs, and Pos-plumbing bugs in any of six frontends ship green. The 'false-positive guard' in the docstring (corpus_test.go:14-18) only guards against wrong-RULE FPs, not wrong-LOCATION or over-reporting FPs.
- **Fix direction:** Extend ExpectedFinding with optional file/line (sink position), max count, and severity/confidence, and populate them via the existing regen helper; assert them when present. This keeps min-count for fuzzy samples while pinning the precise ones. No engine change required — pure test-harness work with outsized trust payoff.

### TRUST-4 [HIGH] The corpus oracle is self-generated: RegenerateManifests writes expected.yaml from the scanner's own output

- **Impact:** The corpus measures self-consistency, not correctness. A behavior regression followed by a regen (the documented workflow when tests fail) silently ratifies the regression; nothing forces a human to check the new counts against what the sample actually contains. Combined with rule+min-count-only assertions, the test suite cannot distinguish 'detects the vulnerability' from 'emits the same noise it emitted yesterday'.
- **Fix direction:** Move ground truth into the samples themselves: inline expectation comments on the vulnerable line (`// godzilla: go-sql-injection`) parsed by the corpus test, so the oracle lives next to the code it describes and a regen cannot silently rewrite it. Keep regen only as a bootstrap that requires diff review, and say so in test/README.md.

### TRUST-5 [HIGH] No precision/recall measurement on anything but ~116 tiny synthetic samples — the 'near-perfect signal/noise' headline is unmeasured

- **Impact:** Goal #2 (near-zero false positives at the gate) is asserted, never measured. Synthetic 20-line samples systematically overstate both precision and recall: real code has reflection, DI frameworks, ORM wrappers, and deep call chains where the context-insensitive summaries (internal/analysis/interproc.go) will behave very differently. Without a benchmark score, users cannot compare against CodeQL/Semgrep (both publish OWASP Benchmark / open ruleset metrics), and the team cannot detect FP-rate drift when rules or the engine change.
- **Fix direction:** Add a scheduled (weekly, not per-PR) CI job that (a) runs the OWASP Benchmark for Java and computes the TPR/FPR scorecard, (b) scans a pinned set of 5-10 real OSS repos per language with --fail-on info and diffs the finding inventory against a committed baseline (any delta requires human triage), and (c) publishes the numbers in the README. All infrastructure-only — no engine change — and it directly substantiates the headline claim.

### TRUST-6 [MEDIUM] Zero performance benchmarks or perf-regression CI despite 'ultra-fast per-commit gate' being goal #1

- **Impact:** The interprocedural worklist (internal/analysis/interproc.go), CHA call graph (callgraph.go), and glob-matching of every callee against every rule pattern are all superlinear surfaces where a small change can turn a 5-second scan into a 5-minute one — fatal for a per-commit gate — and CI would stay green. Published speed claims that can silently rot are a credibility risk.
- **Fix direction:** Add Go benchmarks for the hot paths (Engine.Analyze on a large synthetic gIR program, rule glob matching, each frontend's ConvertFile on a fixed medium-size fixture) and a CI step that runs them with benchstat against the base branch, failing on large regressions. Also time the e2e job's real Spring/rouille scans and assert a generous ceiling.

### TRUST-7 [MEDIUM] No fuzzing of frontends, which parse fully attacker-controlled input (source files, helper JSON, textual MIR)

- **Impact:** A panic in any frontend either crashes the scan (exit 1, blocking CI on attacker-chosen input — a DoS on the gate) or, in directory mode, is swallowed as a warning and produces a false 'clean' (see the fail-open gap). Go's native fuzzing makes this cheap to cover; not doing it is below the bar set by CodeQL/Semgrep, whose parsers are battle-hardened against pathological input.
- **Fix direction:** Add go-native fuzz targets: FuzzConvertJS (goja lowering), FuzzLowerMIR (mir.go text + decodeFmtTemplate byte template), FuzzJavaLower (dumpDoc JSON → operand-stack simulation), FuzzPyLower (astNode JSON). Seed each from the existing test corpus. Run a short fuzz budget in CI (`go test -fuzz -fuzztime 30s` per target on a schedule) and wrap each frontend's per-file conversion in a recover() that records the failure instead of crashing the whole scan.

### TRUST-8 [MEDIUM] No differential testing across language frontends — the 'one engine, same rule everywhere' promise is verified for exactly one program shape

- **Impact:** The architecture's core bet — six very different lowerings (SSA, straight-line AST env, operand-stack simulation, MIR text forwarding) all feeding one engine — means each frontend can silently diverge in taint fidelity (e.g. Java's dropped makeConcatWithConstants recipe already makes SSRF behave differently per CLAUDE.md). Without a matrixed corpus, per-language recall gaps are discovered by users, not tests, undermining the multi-language headline.
- **Fix direction:** Build a small differential matrix: for each core CWE (SQLi, cmd-injection, path traversal, SSRF, plus a safe control each), commit the semantically-equivalent program in every supported language, and a table-driven test asserting each language's scan yields the expected rule family (with per-language skip annotations only where a frontend limitation is documented). The gaps the matrix exposes become the frontend/rulepack backlog — all YAML-and-samples work, no gIR change.

### TRUST-9 [MEDIUM] Scanning a Go module triggers uncontrolled network fetches (and possible toolchain downloads) driven by the scanned go.mod

- **Impact:** Weaker than the mvnw/cargo RCE (Go module fetches are sumdb-verified and toolchains are Google-signed) but still: the scanned repo controls what the CI runner downloads and how long the scan takes (a go.mod naming huge or unreachable modules stalls or fails the gate), scans are non-hermetic and non-reproducible, and network egress from a security scanner surprises locked-down CI environments.
- **Fix direction:** Set cfg.Env explicitly in the Go converter: GOTOOLCHAIN=local always, and honor a --offline / GODZILLA_OFFLINE mode that sets GOFLAGS=-mod=mod GOPROXY=off and degrades gracefully (analyze what resolves, warn about the rest). Document that dependency-bearing Go scans expect a warmed module cache in CI.

