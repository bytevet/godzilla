# Godzilla Backlog — status

> **Goals measured against** (`README.md`, `ARCHITECTURE.md`): (1) ultra-fast per-commit CI gate;
> (2) near-zero false positives at the gate; (3) multi-language via one taint engine over the frozen
> gIR SSA IR; (4) an optional LLM reviewer that adjudicates only low/medium findings and fails open.

Produced by a 7-lens code audit (engine, frontend, coverage, perf, CI/CD, LLM, trust); the 21
highest-severity claims went through adversarial re-verification (18 confirmed, 3 partial, 0 refuted).
IDs are stable. Fix-order convention (per `CLAUDE.md`): intrinsic + engine teaching → YAML rule edit →
frontend lowering → engine change; touch `proto/*.proto` only as a last resort.

**Status:** ✅ done · 🟡 partial (note says what's left) · ⏸ deferred with rationale.
Every CRITICAL/HIGH from the original 7-lens audit is done. A **real-world CVE benchmark** (11
famous projects at known-CVE commits, ~1.02M LOC) then caught **0/12** despite a 1.000 corpus F1,
opening a new class of high-severity **breadth** gaps (COV-11, TRUST-10) — modeling coverage, not
engine defects. The rest is toolchain-gated, net-new frontends, or deferred perf work.

## Engine precision & soundness (ENG)

| ID | Sev | Status | Note |
|----|-----|--------|------|
| ENG-1 | crit | ✅ `4f445c9` | Sanitizer result no longer re-tainted by the return summary (early-return in `handleCall`). |
| ENG-2 | high | ✅ `41ae16f` | Flow-sensitive per-block dataflow (RPO + union join) with strong updates on non-escaping allocs. |
| ENG-3 | high | ✅ `5c26335` | Field-sensitive containers via one-level access-path keys; whole-container fallback kept for INDEX/variadic. |
| ENG-4 | high | ✅ `ea27eb3` | Shared default-propagator pack (stdlib string/path/url); extended this session with net/http+net/url request accessors. |
| ENG-5 | high | ✅ `4f445c9` | Receiver-aware INVOKE arg→param mapping for Java instance methods. |
| ENG-6 | high | ✅ `e88e46a`,`72ed5d4` | Taint through globals (a) and callee out-parameter fills (b); both Medium confidence. |
| ENG-7 | med | ✅ `4f445c9` | Return-flow findings marked Medium (`interprocOrigins`) so the reviewer sees them. |
| ENG-8 | med | ✅ `b8344be` | SSRF sink marked reported only when a finding is emitted (below the host-controllable check). |
| ENG-9 | med | ✅ `8e33f7c` | Guard/barrier validators: a dominating validation check on the source value suppresses the sink. |
| ENG-10 | med | 🟡 | Taint path recorded (`4c6a417`); per-rule reanalysis addressed by shared indexes + demand-driven `ScopeSeed` + per-rule parallelism. A single multi-rule pass is unneeded and not planned. |

## Frontend lowering fidelity (FE)

| ID | Sev | Status | Note |
|----|-----|--------|------|
| FE-1 | crit | ✅ `96ff41e` | Coverage tracked in `scan.Result`; `-strict` fails closed when a detected language produced nothing. |
| FE-2 | crit | ✅ | Python/JS import + require alias resolution to canonical FQNs (relative requires excluded to keep cross-file links). |
| FE-3 | crit | ✅ `6fb8ad5` | Rust bin crates + workspaces via `cargo metadata` per-target MIR emit. |
| FE-4 | high | ✅ `9300e96` | Java CFG reconstruction + operand-stack/local PHI merge at control-flow joins. |
| FE-5 | high | ✅ | "Default if empty" branch-merge PHI in Python, JS, and Rust (block-by-block for MIR). |
| FE-6 | high | ✅ `803dcfd` | TypeScript / JSX / `.mjs`/`.cjs` / ESM via in-process esbuild transform + sourcemap remap. |
| FE-7 | high | ✅ `0a60df8` | Python dict/set literals lowered as sequences so inner sources/sinks fire. |
| FE-8 | high | ✅ `12389e9` | Java findings anchor to each class's `.java` via the SourceFile attribute. |
| FE-9 | med | ✅ `f866600` | Java probes `java -version` and surfaces the real javac diagnostic on failure. |
| FE-10 | med | ✅ `f866600` | Rust MIR-shape smoke test warns on rustc format drift. |

## Detection & secrets coverage (COV)

| ID | Sev | Status | Note |
|----|-----|--------|------|
| COV-1 | crit | ✅ `9b142bd` | Secrets scanned over raw file bytes (.env/compose/Dockerfile/CI YAML); pattern set expanded + entropy qualifier. |
| COV-2 | crit | ✅ `803dcfd` | Same as FE-6 (TS/ESM visible). |
| COV-3 | high | ✅ `39c5cf3` | Java insecure-deserialization / SSRF / XSS / open-redirect packs + JAX-RS param sources. |
| COV-4 | high | ✅ `3a1b72e` | `kind: dangerous-call` non-dataflow rule type (weak crypto / weak cipher / insecure RNG). |
| COV-5 | high | 🟡 `315bbf6` | Python `eval`/`exec`/`compile` code injection shipped. **Open (pure-YAML):** NoSQL, SSTI, LDAP/XPath, zip-slip, prototype-pollution, header/CRLF, log injection. |
| COV-6 | high | ✅ `55d4f15` | Header/cookie/body sources + gorilla/fiber/fastify; extended this session to a framework-agnostic request-object source + stdlib request-accessor propagators (covers unmodeled frameworks). |
| COV-7 | med | ✅ `dcfda8d` | Rust axum extractor sources (`Query`/`Path`/`Json`/`Form`) + XSS/open-redirect packs. |
| COV-8 | med | ✅ `8e313f7` | C/C++ CFG-edge fix + exec-family/argv sources + buffer-overflow & SQLi packs (SSRF is a follow-on). |
| COV-9 | med | ✅ `1abcdab` | Sanitizer realism: real sanitizer globs; the over-broad `py:*escape` glob tightened. |
| COV-10 | low | 🟡 `af8d696` | Ruby frontend shipped. **Open (net-new frontends):** PHP, C#, Kotlin. |
| COV-11 | high | 🟡 | **Framework handler-parameter sources** (branch `claude/realworld-recall`). Shipped: Go free-function accessors (`go:*web.Params`); Python FastAPI/Tornado/MethodView handler-param source synthesis (`py:@http.param`); `with open(...)` context-manager lowering; split/join propagators. Corpus TP 133→142, FP=0. **Open:** JS handler-param synthesis; method-propagator chaining (`path.split()`/`.strip()` don't forward through the param source — blocks Streamlit); per-CVE inter-proc transforms. |
| COV-12 | med | ✅ | **Ruby rulepack parity** — `ruby-xss` / `ruby-path-traversal` / `ruby-ssrf` / `ruby-open-redirect` shipped, plus a Ruby frontend fix resolving namespaced-constant receivers (`Net::HTTP.get`). Samples + FP=0. |
| COV-13 | med | 🟡 | **Framework-abstracted sinks + library sources** — shipped FastAPI/Starlette `FileResponse` path-traversal sink (+ narrowed py-xss `*Response` to fix the resulting FP). **Open:** `express.static`, `knex.raw`/ORM raw-query, Jinja→SQL propagator; opt-in "exported-API parameter = untrusted" library-scan mode (systeminformation CVE-2021-21315). |

## Performance & scalability (PERF)

| ID | Sev | Status | Note |
|----|-----|--------|------|
| PERF-1 | crit | ⏸ | Incremental/per-file caching. Deferred: PERF-2/3/4/5/7 already deliver "ultra-fast", and diff-aware *gating* ships via CI-2; caching's marginal gain doesn't justify the invalidation/concurrency risk. |
| PERF-2 | crit | ✅ (PR #17) | Two-phase load: stdlib arrives as export data with bodyless SSA (was typechecked + SSA-built from source and discarded). No-deps Go scan 1.77s→0.19s; gin_gorm 5.0s→3.1s. |
| PERF-3 | high | ✅ `c99075e`+ | Parallelism across per-rule analysis, frontends, Go/JS lowering, Python/Ruby chunked helper processes, and LLM review. |
| PERF-4 | high | 🟡 `a53dec4` | Subprocess timeouts (`internal/proc`) + JavaDump persistent per-user cache + version-probe cache. **Open:** up-to-date build skip, JVM process reuse. |
| PERF-5 | med | ✅ `d049e80` | CHA method index built once + rule glob patterns precompiled to lock-free matchers. |
| PERF-6 | med | ⏸ | Call-graph tree-shaking removed as dead code; superseded by demand-driven `ScopeSeed`, which scopes analysis without the CHA-soundness trade-off. |
| PERF-7 | med | ✅ `b73af85` | Directory excludes (vendor/.git/node_modules/…) + size caps (`internal/walkignore`). |
| PERF-8 | low | ⏸ | Streaming/memory discipline — not a bottleneck after PERF-2 cut peak heap. |

## CI/CD product surface (CI)

| ID | Sev | Status | Note |
|----|-----|--------|------|
| CI-1 | crit | ✅ `b9f3df7` | Baseline file + inline `// godzilla:ignore`. |
| CI-2 | crit | ✅ `b9f3df7` | Stable finding fingerprints → `--fail-on-new` diff-aware gating. |
| CI-3 | high | ✅ `96ff41e` | Same as FE-1 (frontend failure fails the gate under `-strict`). |
| CI-4 | high | ✅ `4c6a417`,`b2e8133` | SARIF codeFlows/threadFlows + rule metadata + tool version. |
| CI-5 | high | ✅ `0fce6df` | Project config file + path include/exclude filters. |
| CI-6 | med | ✅ `4c6a417` | Taint path (`Finding.Steps`) recorded and rendered in HTML/SARIF. |
| CI-7 | med | ✅ `6acc72f` | `rules list`/`lint`/`test` author tooling. |
| CI-8 | med | ✅ `0fce6df` | Version subcommand + version in SARIF/JSON. |
| CI-9 | low | ✅ `c05af2f`,`38cd351` | `-quiet`, usage cleanup, and changed-files/pre-commit mode (`ScanFiles`). |

## LLM reviewer (LLM)

| ID | Sev | Status | Note |
|----|-----|--------|------|
| LLM-1 | crit | ✅ `6f7b62a` | Suppressed findings retained + flagged with reason in JSON/SARIF/HTML (audit trail). |
| LLM-2 | crit | ✅ `531ac68` | Reviewer context includes the taint path + rule source/sanitizer definitions. |
| LLM-3 | high | ✅ `6f7b62a` | Never adjudicates on empty code context (never-blind). |
| LLM-4 | high | ✅ `516c18f` | Agentic, tool-using reviewer that can open files and trace the flow. |
| LLM-5 | high | ✅ `3dceb0f` | Bounded concurrency + per-review timeout + cap. |
| LLM-6 | med | ✅ `6f7b62a` | Reviewer errors surfaced (missing key is no longer a silent no-op). |
| LLM-7 | med | ✅ `6ac4a91` | Richer verdict (confidence/exploitability) + kept findings annotated as LLM-confirmed. |
| LLM-8 | med | ✅ `1cd91ee` | Prompt carries rule vocabulary; `parseVerdict` no longer treats a bare "false" as a drop. |
| LLM-9 | low | ✅ `0302ec7` | OpenAI-compatible adapter (Ollama/vLLM/llama.cpp) routed by `GODZILLA_LLM_PROVIDER`. |

## Trust & quality measurement (TRUST)

| ID | Sev | Status | Note |
|----|-----|--------|------|
| TRUST-1 | crit | ✅ `96a5dbe` | Build execution gated behind `--allow-build` (default off) with a loud warning; no-build fallback otherwise. |
| TRUST-2 | high | ✅ `96ff41e` | Same as FE-1 (fails closed, not open). |
| TRUST-3 | high | ✅ `99abf24` | `expected.yaml` asserts sink position + severity, not just rule + min count. |
| TRUST-4 | high | ⏸ | Corpus oracle is scanner-generated. Inline per-line expectation comments are the follow-on; regen currently requires diff review. |
| TRUST-5 | high | ✅ `f04483e` | Corpus precision/recall/F1 scorer with a regression floor. |
| TRUST-6 | med | ✅ `2326058` | Benchmarks + perf-regression guard on the hot paths. |
| TRUST-7 | med | ✅ `09f40e1` | Frontend fuzz targets + glob-DoS fix; the `termination_stress` sample guards the analyzer's termination invariants. |
| TRUST-8 | med | ✅ `2326058` | Cross-frontend differential corpus (same CWE in every language). |
| TRUST-9 | med | ⏸ | Go scans still allow module fetches. Not enforcing `GOTOOLCHAIN=local`/offline mode; document a warmed cache for CI. |
| TRUST-10 | high | ✅ | **Secret-scanner precision** — both secret scanners now skip vendored deps + test-fixture/i18n/API-schema paths (`secretPathExcluded`), first-party only. The ~40 benchmark FPs (Superset i18n, Ghost fixtures, NocoDB swagger, gogs `x/crypto`) are gone; a real secret in a normal config still fires. FP-guard sample + corpus FP=0. |
| TRUST-11 | med | ✅ | **Real-world CVE benchmark harness** — `test/cvebench` (opt-in `GODZILLA_CVE_BENCH=1`): a fix-diff-verified CVE manifest + a scan/score test reporting recall alongside the corpus F1. The regression guard for the COV-11/13 breadth gaps. |

## Open items (all deferred or partial above)

- **COV-5** — remaining injection classes (NoSQL, SSTI, LDAP/XPath, zip-slip, prototype-pollution,
  header/CRLF, log). Pure-YAML packs; ship when a target framework/sample justifies each.
- **COV-10** — PHP / C# / Kotlin frontends. Each is a net-new project.
- **COV-11 / COV-12 / COV-13** — real-world recall (from the CVE benchmark): framework
  handler-parameter sources (the highest-leverage fix), Ruby rulepack parity, and
  framework-abstracted sinks + library-parameter sources.
- **TRUST-10 / TRUST-11** — secret-scanner precision (scope out deps/data/fixtures); a repeatable
  real-world CVE recall harness alongside the corpus F1.
- **PERF-1 / PERF-4 (residual) / PERF-6 / PERF-8** — incremental caching, build up-to-date skip / JVM
  reuse, tree-shaking, streaming. Reasoned deferrals in the PERF table.
- **TRUST-4 / TRUST-9** — inline-expectation oracle; Go scan hermeticity.
- **ENG-10 (residual)** — single multi-rule pass; unneeded given the shipped shared-index + scoping design.
