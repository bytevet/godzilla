# Godzilla Architecture & Design

> Status: **design** — this document is the agreed target architecture, not a description of
> current code. As of writing, only the Go frontend exists; the Rule Engine, Analysis Engine,
> Report module, LLM module, and CLI are stubs. See `CLAUDE.md` for the current implementation state
> and `spec.md` for the original product brief.

Godzilla is a **rapid, multi-language SAST tool** built for CI/CD quality gates. Source code in any
supported language is lowered to a single language-neutral IR (**gIR**), and one set of analysis
engines runs over that IR regardless of source language. The headline goals from `spec.md` are:

1. **Ultra fast** — usable as a per-commit CI checkpoint.
2. **Perfect signal/noise** — near-zero false positives at the gate.
3. **Multi-language** — one analysis core, many frontends.

These goals pull against each other (precision is expensive; speed favors approximation). The design
below resolves that tension with **demand-driven analysis**, **tree-shaking**, and an **optional LLM
reviewer** as the final false-positive backstop.

---

## 1. Design decisions

Locked via a design interview. Each row records the choice and the primary reason.

| Area | Decision | Rationale |
|---|---|---|
| First development focus | Language-neutral gIR + multi-language foundation | Getting the IR wrong forces rework of every frontend and every analysis pass; build it right first. |
| IR shape | **Small universal core + tagged intrinsics** | Keeps the core tiny and neutral; language-specific behavior lives in named intrinsics that rules/analysis interpret. |
| IR form | **SSA mandated** (frontends emit phi nodes) | SSA def-use chains make taint, dataflow, and pointer analysis dramatically simpler and faster. |
| Symbol naming | **Canonical FQN + globs** | Cross-language rule reuse; a rule matches `*.Query` shapes across Go/Python/JS by stable names. |
| Detection model | **Inter-procedural taint** (intra-proc as a stepping stone) | The target vuln classes are all source→sink flows that cross function boundaries. |
| Pointer analysis | **Demand-driven (on-demand)** | Compute points-to only for values a taint query touches — precision where it matters, without whole-program cost. |
| Frontend deployment | **In-process Go, single self-contained binary** | Fast startup and trivial CI deployment (no orchestration of external services). |
| Parsing source | **Mixed per language** | Use the most accurate cheap source per language rather than forcing one representation. |
| Python parsing | **Prefer local `python3` bytecode; fall back to tree-sitter** | CPython bytecode captures dynamic dispatch faithfully; tree-sitter keeps the tool runnable when Python is absent. |
| JavaScript parsing | **tree-sitter** (embedded) → AST → SSA | Embeddable in the Go binary; no Node runtime required. |
| Rules | **YAML**, two kinds: taint + pattern | Taint rules for dataflow vulns; pattern rules for non-dataflow findings (secrets). |
| Initial vuln scope | Injection (SQLi + command), path traversal, XSS/SSRF, hardcoded secrets | Covers the existing samples and the highest-value web classes. |
| Confidence & LLM | **Confidence scoring now; Claude reviewer later (pluggable)** | Build the routing hook immediately so the LLM stage drops in without pipeline changes. |
| Reporting | **HTML first** + exit-code gating; JSON/SARIF later | HTML gives the richest triage experience; exit codes make it a real gate. |

---

## 2. High-level architecture

```
          ┌───────── Frontends (in-process Go, one binary) ─────────┐
 Go  ─────► x/tools SSA ──┐
 Python ──► python3 dis  ─┤─► SSA construction ─► gIR v2 (core + intrinsics, canonical FQNs)
         └► tree-sitter  ─┤                              │
 JS  ─────► tree-sitter  ─┘                              ▼
                                    ┌──────────── Analysis Engine ────────────┐
   YAML rules ──► Rule Engine ─────►│ call graph → tree-shake → inter-proc     │
   (FQN globs)   (taint + pattern)  │ taint w/ demand-driven pointer analysis  │
                                    │ + confidence scoring                     │
                                    └───────────────────┬──────────────────────┘
                                                        ▼
                              Findings ──► (later: LLM reviewer) ──► HTML report + exit code
```

The pipeline is a straight line: **Frontend → gIR → Rule Engine + Analysis Engine → Findings →
Report**. gIR is the single contract between frontends and everything downstream. No analysis pass
should ever branch on source language — only on gIR structure and intrinsic/symbol names.

---

## 3. gIR v2 — the core contract

The current gIR is effectively a 1:1 mirror of Go SSA (dedicated opcodes for channels, `defer`,
`go`, `select`, `range`, etc.). gIR v2 replaces that with a **small core plus an intrinsic escape
hatch**.

### 3.1 Core opcodes (language-neutral)

The complete opcode set stays small and universal:

- **Terminators:** `RET`, `JUMP`, `IF`, `SWITCH`, `UNREACHABLE`
- **Memory:** `ALLOC`, `LOAD`, `STORE`
- **Aggregates:** `FIELD` / `FIELD_ADDR`, `INDEX` / `INDEX_ADDR`
- **Compute:** `BIN_OP`, `UN_OP`, `PHI`
- **Calls:** `CALL` (statically resolved) and `INVOKE` (dynamic/virtual dispatch)
- **Types:** `CONVERT`, `TYPE_ASSERT`, `MAKE_INTERFACE` (box a value into an interface/`any`)
- **`INTRINSIC`** — the escape hatch (below)

### 3.2 Intrinsics

Everything language-specific is an **`INTRINSIC`**: a call carrying a **canonical name** plus operands.
The analysis engine and rules interpret intrinsics by name; the core has no opcode per language
feature.

Examples of constructs that become intrinsics:

- Go: `go.chan.send`, `go.chan.recv`, `go.select`, `go.defer`, `go.go` (goroutine), `go.range`,
  `go.map.update`, `go.builtin.append`
- Python: `py.dict.__getitem__`, `py.attr.get`, `py.call.kw`, `py.magic.__add__`
- JavaScript: `js.property.get`, `js.property.set`, `js.spread`, `js.template`
- Cross-language: `builtin.sprintf`, `builtin.string.concat`, `builtin.len`

Intrinsics may declare **default taint semantics** in rules (e.g. `builtin.string.concat` and
`builtin.sprintf` propagate taint from any tainted argument to the result), so the engine handles the
common propagators uniformly.

### 3.3 SSA is mandatory

Every frontend emits SSA: unique value definitions and explicit `PHI` nodes at control-flow joins.
Frontends whose source is not already SSA (Python bytecode, JS AST) run **SSA construction** during
lowering. Braun et al.'s "Simple and Efficient Construction of Static Single Assignment Form" is the
recommended algorithm because it builds SSA directly from an AST/bytecode walk without a separate
dominance-frontier pass.

### 3.4 Canonical symbol naming

Every function, method, and global carries a **stable canonical fully-qualified name** so rules match
across languages:

```
go:net/http.(*Request).FormValue
py:flask.request.args.get
js:express.Request.query
```

Scheme: `lang:module/path.Type.member`. Frontends own the mapping from their native naming to this
scheme; the analysis core and rules only ever see canonical names. Rules match with globs
(e.g. `*/http.*.FormValue`, `py:flask.request.*`).

### 3.5 Source mapping

Every instruction, function, and global carries a `Position` (file/line/column), as today. This is
non-negotiable — it drives both reporting and the HTML path visualization.

---

## 4. Analysis Engine

Inter-procedural taint tracking with the following pipeline:

1. **Call-graph construction.** Static `CALL`s resolve directly. `INVOKE` (dynamic dispatch) targets
   are resolved on demand via pointer analysis (below).
2. **Tree-shaking (reachability pruning).** Starting from entry points and taint sources, prune
   functions that cannot participate in any tainted flow. This is the primary speed lever — the
   engine never analyzes unreachable code.
3. **Taint propagation.** Over SSA def-use chains, propagate taint from **sources** to **sinks**,
   killed by **sanitizers** and forwarded by **propagators** (including intrinsic default semantics).
   Field-sensitive where type info allows.
4. **Demand-driven pointer analysis.** Points-to sets are computed *only* for values a taint query
   actually reaches (demand-driven Andersen / CFL-reachability style), rather than whole-program.
   This keeps precision high on the paths that matter without paying for the rest of the program.
5. **Confidence scoring.** Each finding gets a confidence based on path certainty — e.g. ambiguous
   dynamic dispatch, possibly-bypassed sanitizer, or cross-file inference lower it. Low-confidence
   findings are tagged for the (later) LLM reviewer.

**Implementation order:** build intra-procedural taint first (single-function flows) to get a working
detector fast, then extend the same propagation to inter-procedural via call-graph traversal and
per-function taint **summaries**.

---

## 5. Rule Engine

YAML rules, loaded and matched against canonical symbols. Two rule kinds:

### 5.1 Taint rules

```yaml
id: go-sql-injection
languages: [go]
severity: high
cwe: CWE-89
message: "Untrusted input flows into a SQL query"
sources:
  - "go:net/http.(*Request).FormValue"
  - "go:net/http.Values.Get"
sanitizers:
  - "*/database/sql.Named"          # parameterized query helpers
sinks:
  - "*/database/sql.(*DB).Query"
  - "*/database/sql.(*DB).Exec"
propagators:
  - "builtin.sprintf"               # taint flows through format strings
  - "builtin.string.concat"
```

Sources/sinks/sanitizers/propagators are all **FQN globs**, enabling one logical rule to cover
multiple languages (or a shared cross-language rule with per-language symbol lists).

### 5.2 Pattern rules (non-dataflow)

For findings that are not source→sink flows — chiefly **hardcoded secrets** — a separate rule kind
matches over gIR string constants (and optionally raw source) using regex / entropy checks. This path
is deliberately distinct from taint so the dataflow engine stays focused.

---

## 6. Frontends

All frontends run **in-process** and emit gIR v2 with canonical FQNs and SSA. The tool ships as a
single Go binary.

- **Go** — refactor the existing `converters/go/` (built on `golang.org/x/tools` SSA, already SSA) to
  emit the core+intrinsics schema and `go:` canonical names. Go-specific opcodes collapse into
  intrinsics.
- **Python** — **prefer a local `python3`**: compile to CPython bytecode (`dis`), then lower bytecode
  → SSA. When no compatible `python3` is on `PATH`, **fall back to pure-Go tree-sitter** AST → SSA.
  Bytecode gives higher fidelity on dynamic dispatch and magic methods; the fallback keeps the tool
  usable everywhere. Emits `py:` names.
- **JavaScript** — tree-sitter (embedded) → AST → SSA. Handles CommonJS and ESM. Emits `js:` names.

**Note on cgo:** tree-sitter is a C library, so the JS frontend and Python fallback pull in cgo. This
slightly complicates the "single static binary" story (a C toolchain is needed to build, and fully
static linking needs care). Accepted trade-off; flagged here as a build-time constraint.

---

## 7. Confidence, LLM reviewer, and Reporting

- **Confidence model (build now):** every finding is scored; the pipeline has an explicit hook to
  route low-confidence findings to a reviewer stage.
- **LLM reviewer (build later):** a pluggable stage that sends uncertain findings to Claude
  (Anthropic API) for adjudication, discarding false positives. Optional and off the hot path — the
  precision backstop for the "perfect signal/noise" goal.
- **Report module:** **HTML first** — findings with severity, confidence, code snippets (via
  `Position`), and source→sink path visualization. The CLI sets a process **exit code** based on a
  severity threshold so CI can gate on it. JSON and SARIF outputs come later (SARIF unlocks GitHub
  code scanning).

---

## 8. Phased roadmap

Each phase is independently verifiable.

- **Phase 0 — Baseline.** Implement `cmd/godzilla/main.go` (currently empty), make `go build ./...`
  green, add CI scaffolding.
- **Phase 1 — gIR v2.** New proto schema (core opcodes + `INTRINSIC` + canonical `Symbol` +
  finding/confidence types); regenerate bindings; refactor the Go frontend to emit it; golden tests on
  the existing samples (no `unsupported instruction` fallbacks; intrinsics correctly tagged).
- **Phase 2 — Rules + intra-procedural taint (Go vertical slice).** YAML loader + FQN glob matcher;
  taint over SSA def-use within a function; detect SQL injection in the Go sample end-to-end.
- **Phase 3 — Inter-procedural depth.** Call graph + tree-shaking; demand-driven points-to for
  `INVOKE` resolution and field sensitivity; cross-call taint summaries; confidence scoring.
- **Phase 4 — Python frontend.** `python3`→bytecode→SSA with tree-sitter fallback; `py:` rules;
  validate taint on a Flask sample.
- **Phase 5 — JavaScript frontend.** tree-sitter→SSA; `js:` rules; validate XSS/SSRF on an Express
  sample.
- **Phase 6 — Reports + secrets.** HTML report (path viz, snippets, severity/confidence) + exit-code
  gating; add the pattern-rule path for hardcoded secrets.
- **Phase 7 — LLM reviewer (later).** Pluggable Claude stage over low-confidence findings.

The MVP vuln scope (injection, path traversal, XSS/SSRF, secrets) is delivered incrementally through
rules across Phases 2–6.

---

## 9. Key risks & tensions

- **Speed vs. precision.** Inter-procedural + pointer analysis is precise but costly. Mitigations:
  tree-shaking, demand-driven points-to, and the LLM reviewer as the residual-FP filter.
- **gIR v2 churn.** The core+intrinsics schema is the foundation for two frontends and all analysis;
  changes are expensive once frontends exist. Phase 1 exists to get it right before that cost lands.
- **Python fidelity vs. deployment.** The `python3`-preferred / tree-sitter-fallback split means two
  Python code paths and behavior that varies with the environment. Golden tests should cover both.
- **cgo / static binary.** tree-sitter's C dependency complicates fully-static builds; needs a
  deliberate build setup.
- **Canonical naming drift.** Rule reuse depends on frontends producing stable, consistent FQNs. The
  naming scheme should be specified precisely and covered by tests per frontend.

---

## 10. Implementation status

All phases below are implemented, tested, and validated end-to-end (every vuln class is detected across
the languages that have samples). See `CLAUDE.md` for the package-level map.

| Component | Status |
|---|---|
| gIR v2 (small core + intrinsics, SSA, canonical FQNs) | ✅ Done — `proto/`, `pkg/ir/v1/` |
| Go frontend (x/tools SSA; funcs + methods + closures) | ✅ Done |
| Python frontend (`python3` `ast` → gIR) | ✅ Done (straight-line lowering; tree-sitter fallback not built — errors if `python3` absent) |
| JavaScript frontend (goja → gIR) | ✅ Done (straight-line lowering) |
| Rule engine (YAML, FQN globs, built-in rules) | ✅ Done — SQLi/command-injection/path-traversal/SSRF/XSS for Go, plus Python & JS packs |
| Intra-procedural taint | ✅ Done |
| Inter-procedural taint (call graph + summaries) | ✅ Done |
| Tree-shaking (reachability pruning primitive) | ✅ `CallGraph.Reachable`/`Roots` implemented; not yet used to prune the analysis set |
| Pointer analysis | ⚠️ Approximated — CHA for dynamic dispatch + value-flow alias tracking (def-use + container taint). A full **demand-driven Andersen points-to** (the interview's stated goal) is a documented future precision upgrade; the current approach is sound and sufficient for the target vuln classes |
| Confidence scoring | ✅ Done — intra = High, cross-function = Medium |
| Secrets (pattern) scanning | ✅ Done — regex over gIR string constants (CWE-798) |
| HTML report + exit-code gating | ✅ Done |
| LLM reviewer (pluggable) | ✅ Done — Anthropic-backed, confidence-gated, fail-open; off by default (`--llm-review`) |

**Known frontend limitations** (documented in each converter's package doc): Python and JS lowering is
straight-line (control flow flattened, one conceptual iteration; classes/comprehensions/async partial).
This maximizes taint recall for the common web-handler vulnerability shape at the cost of path precision —
consistent with the "recall-oriented analysis + LLM/confidence backstop" design.

**Interface / dynamic dispatch — crossed inter-procedurally (CHA).** An `OP_CODE_INVOKE` call names the
abstract interface method, so the taint transfer resolves it to every concrete method of that name
(class-hierarchy analysis) and flows taint into each — with the receiver offset (invoke args exclude the
receiver, which is `Call.Value`). This catches taint through interfaces (`http.Handler`, custom
service/repository interfaces). It over-approximates (any same-named method matches), so such findings stay
Medium confidence and lean on the confidence/LLM backstop. See `interproc.go` (`methodImpls`).

**Known analysis limitations** (surfaced by review, tracked here):
- **Go field-access sources aren't matchable.** A source read as a struct field (`r.URL.Path`,
  `r.Header[...]`) lowers to `FIELD`/`INDEX` with no `Callee`, so rules (which match `Call.Callee`) can't
  flag it. Method-call sources (`FormValue`, `Query().Get`, `Header.Get`, …) cover the common Go cases;
  field-access sources would need a JS-style "opaque-base → synthetic source call" heuristic in the Go
  frontend (the dead `go:*Request*.URL*` globs that claimed this were removed).
