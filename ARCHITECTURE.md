# Godzilla Architecture & Design

> This document describes the **as-built** architecture and the reasoning behind
> it. The whole pipeline — seven frontends (Go, Python, JavaScript, Java, Rust,
> Ruby, C/C++), the rule engine, analysis engine, report module, LLM reviewer,
> and CLI — is implemented and tested. See [CLAUDE.md](CLAUDE.md) for the
> package-level code map and [docs/writing-rules.md](docs/writing-rules.md) for
> rule authoring.

Godzilla is a **rapid, multi-language SAST tool** for CI/CD quality gates. Source
code in any supported language is lowered to a single language-neutral IR
(**gIR**), and one analysis core runs over that IR regardless of source language.
The three design goals:

1. **Ultra fast** — usable as a per-commit CI checkpoint.
2. **High signal/noise** — few false positives at the gate.
3. **Multi-language** — one analysis core, many frontends.

These pull against each other (precision is expensive; speed favors
approximation). The design resolves that tension with a small IR, demand-driven
analysis scoping, recall-oriented taint, and an optional LLM reviewer as a
false-positive backstop.

## Design principles

- **gIR is the contract.** A single language-neutral SSA IR sits between frontends
  and analysis; no analysis pass ever branches on source language, only on gIR
  structure and canonical symbol names. Getting the IR right first avoids reworking
  every frontend and pass later.
- **Small core + tagged intrinsics.** The opcode set stays tiny and universal;
  every language-specific construct is an `INTRINSIC` carrying a canonical name that
  rules and analysis interpret. No opcode is ever added for a single language.
- **SSA is mandatory.** Frontends emit SSA with explicit `PHI` nodes, because
  def-use chains make taint and dataflow dramatically simpler and faster.
- **Canonical FQN + globs.** Every symbol has a stable `lang:module/path.Type.member`
  name, so one rule shape matches equivalent APIs across languages.
- **Inter-procedural taint.** The target vuln classes are source→sink flows that
  cross function boundaries; the engine follows them via per-function summaries.
- **In-process, single binary.** Frontends run in-process for fast startup and
  trivial CI deployment; each merely shells out to a language toolchain where one is
  unavoidable (Python/Java/Rust).
- **Recall first, precision backstop.** Lowering favors catching the common
  web-handler vulnerability shape; a confidence score plus the optional LLM reviewer
  trim the residual false positives.

## High-level architecture

```
          ┌───────── Frontends (in-process Go, one binary) ─────────┐
 Go   ────► x/tools SSA ───┐
 Python ──► python3 ast  ──┤
 JS   ────► goja AST     ──┤
 Java ────► JVM bytecode ──┤─► lower ─► gIR (core + intrinsics, canonical FQNs)
 Rust ────► rustc MIR    ──┤                            │
 Ruby ────► ruby Ripper  ──┤                            │
 C/C++ ───► LLVM IR (cgo) ─┘                            ▼
                                       ┌──────────── Analysis Engine ────────────┐
   YAML rules ──► Rule Engine ────────►│ call graph → inter-procedural taint with │
   (FQN globs)   (taint +              │ value-flow + CHA alias tracking          │
                  dangerous-call)      │ + confidence scoring                     │
                                       └───────────────────┬──────────────────────┘
                                                           ▼
                              Findings ──► (optional LLM reviewer) ──► HTML/JSON/SARIF report + exit code
```

The pipeline is a straight line: **frontend → gIR → rule engine + analysis engine
→ findings → report**. gIR is the single contract between frontends and everything
downstream.

## gIR — the core contract

gIR is a **small universal SSA core plus an intrinsic escape hatch**, defined in
`proto/*.proto` (authoritative) and generated into `pkg/ir/v1/`.

### Core opcodes

The opcode set stays small and language-neutral:

- **Terminators:** `RET`, `JUMP`, `IF`, `SWITCH`, `UNREACHABLE`
- **Memory:** `ALLOC`, `LOAD`, `STORE`
- **Aggregates:** `FIELD` / `FIELD_ADDR`, `INDEX` / `INDEX_ADDR`
- **Compute:** `BIN_OP`, `UN_OP`, `PHI`
- **Calls:** `CALL` (static) and `INVOKE` (dynamic/virtual dispatch)
- **Types:** `CONVERT`, `TYPE_ASSERT`, `MAKE_INTERFACE`, `EXTRACT`
- **`INTRINSIC`** — the escape hatch (below)

### Intrinsics

Everything language-specific is an `INTRINSIC`: a call carrying a **canonical
name** plus operands, which the engine and rules interpret by name. Examples: Go
`go.chan.send`, `go.defer`, `go.range`; map ops; closures (`builtin.make_closure`);
aggregate construction (`builtin.aggregate`). Intrinsics may declare default taint
semantics in rules, so common propagators (concatenation, formatting) are handled
uniformly. This keeps the core neutral while every language construct still has a
home — no opcode per language feature.

### SSA is mandatory

Every frontend emits SSA: unique value definitions and explicit `PHI` nodes at
control-flow joins. Frontends whose source is not already SSA run SSA construction
during lowering.

### Canonical symbol naming

Every function, method, and global carries a stable canonical FQN so rules match
across languages:

```
go:net/http.(*Request).FormValue
py:flask.request.args.get
js:express.Request.query
rust:std::process::Command.arg
ruby:params
```

Scheme: `lang:module/path.Type.member`. Frontends own the mapping from native
naming to this scheme; analysis and rules only ever see canonical names, matched
with globs (`*` spans `/` and `.`).

### Source mapping

Every instruction, function, and global carries a `Position` (file/line/column).
This is non-negotiable — it drives both reporting and the HTML path visualization.

## Analysis engine

Inter-procedural taint tracking (`internal/analysis/`):

1. **Call-graph construction.** Static `CALL`s resolve directly; `INVOKE` (dynamic
   dispatch) resolves via class-hierarchy analysis (CHA) to every concrete method of
   the named signature.
2. **Taint propagation** over SSA def-use chains, from **sources** to **sinks**,
   stopped by **sanitizers** and **validators** (guard predicates) and forwarded by
   **propagators** (including intrinsic default semantics). `BIN_OP` is a universal
   propagator so `+` concatenation carries taint.
3. **Inter-procedural flow** via per-function summaries: a tainted argument taints
   the callee's matching parameter, and a taint-returning function taints its
   caller's call result.
4. **Alias tracking** is approximated with value-flow (def-use + container taint for
   aggregates/variadics) plus CHA — sound and sufficient for the target vuln classes,
   short of a full demand-driven points-to.
5. **Confidence scoring.** Intra-procedural findings are High; cross-function are
   Medium. Low-confidence findings are the ones the LLM reviewer adjudicates.

Analysis cost is scoped **demand-driven**: `Engine.ScopeSeed` seeds only user
functions, so a lowered dependency function is analyzed only when taint actually
reaches it (see the Go frontend's dependency lowering). A regex-based **secrets
scanner** (`ScanSecrets`, CWE-798) runs alongside taint over gIR string constants.

## Rule engine

YAML rules matched against canonical symbols (`internal/rules/`), in two kinds:

- **Taint rules** (default) — a source→sink dataflow spec with
  sanitizers/validators/propagators. A sink may pin its injection-point argument
  with `#<index>` to avoid parameterized-query false positives.
- **Dangerous-call rules** (`kind: dangerous-call`) — a non-dataflow, call-site
  match: any call to a banned/weak API (optionally gated on a constant argument) is a
  finding. Backs the weak-crypto packs (weak hash/cipher CWE-327, insecure
  `math/rand` CWE-338).

Hardcoded-secrets detection is a **separate scanner** (regex over string constants),
not a YAML rule kind, so the dataflow engine stays focused. Built-in packs live in
`rulepacks/` and are embedded into the binary; `--rules` merges user rules on top.
For the full authoring reference see [docs/writing-rules.md](docs/writing-rules.md).

## Frontends

All frontends run **in-process** and emit gIR with canonical FQNs and SSA; the tool
ships as a single Go binary. Only C/C++ needs cgo — the rest are pure Go, and
Python/Java/Rust/Ruby merely shell out to a toolchain on `PATH`.

- **Go** (`converters/go/`) — `golang.org/x/tools` SSA (already SSA). Enumerates all
  functions incl. closures via `ssautil.AllFunctions`, since vulnerable code often
  lives in `http.HandleFunc` closures. Emits `go:` names.
- **Python** (`converters/python/`) — shells out to `python3` for an `ast` JSON
  dump, then lowers it (straight-line). Emits `py:` names; requires `python3`.
- **JavaScript** (`converters/javascript/`) — pure-Go parse via **goja**, then
  lowers. TS/JSX/ESM are stripped/lowered in-process by esbuild (no Node) before
  parsing, with source maps remapping positions back. Emits `js:` names.
- **Java** (`converters/java/`) — analyzes JVM **bytecode**. An embedded helper
  (`JavaDump.java`, run via a JDK 24+ `java`) compiles `.java` in-process and reads
  `.class` with `java.lang.classfile`; `lower.go` simulates the operand stack to
  recover SSA. Maven/Gradle projects are built first so deps are on the classpath.
  Emits `java:<owner>.<method>`.
- **Rust** (`converters/rust/`) — shells out to `rustc --emit=mir` and lowers the
  textual MIR (value-forwarding). MIR names the source-level API (`std::env::var`,
  not the monomorphized internal) and assigns call results directly to locals (no
  `sret` indirection), so no LLVM/cgo is needed. A `Cargo.toml` project is built with
  `cargo` so framework deps resolve. Emits `rust:<normalized-path>`.
- **Ruby** (`converters/ruby/`) — an embedded helper (`rbdump.rb`, run via `ruby`)
  parses with the stdlib **Ripper** and emits its S-expression AST as JSON;
  `lower.go` lowers that tree (straight-line). Ripper ships with every MRI Ruby.
  Emits `ruby:` names.
- **C / C++** (`converters/cpp/` + shared `converters/llvm/`) — clang compiles each
  unit to **LLVM IR** (`-O1 -g`), parsed via libLLVM and lowered. This is the
  **opt-in cgo backend** (`-tags "llvm byollvm"`), *not* in the default binary, which
  ships a stub. Emits `c:`/`cpp:`.

Python, JS, and Ruby name modules by their path relative to the scan root, so
same-named functions in different files get distinct canonical names.

## Confidence, LLM review, and reporting

- **Confidence** — every finding is scored (intra = High, cross-function = Medium),
  and the pipeline routes low-confidence findings to the reviewer stage.
- **LLM reviewer** (`internal/llm/`) — a pluggable, Anthropic-backed stage that
  adjudicates uncertain findings and discards false positives. Confidence-gated,
  **fail-open** (never drops a finding on an API error), and off by default
  (`--llm-review`).
- **Report** (`internal/report/`) — a self-contained **HTML** report with severity,
  confidence, and code snippets, plus **JSON** and **SARIF 2.1.0** (`--json` /
  `--sarif`, the latter for GitHub code scanning). The CLI sets a severity-gated
  process **exit code** so CI can gate on it.

## Implementation status

Every component below is implemented and tested end-to-end; every vuln class is
detected across the languages that have samples.

| Component | Status |
|---|---|
| gIR (small core + intrinsics, SSA, canonical FQNs) | ✅ `proto/`, `pkg/ir/v1/` |
| Go frontend (x/tools SSA; funcs + methods + closures) | ✅ |
| Python frontend (`python3` `ast` → gIR) | ✅ straight-line lowering; requires `python3` |
| JavaScript frontend (goja → gIR; TS/JSX/ESM via esbuild) | ✅ straight-line lowering |
| Java frontend (JVM bytecode → gIR) | ✅ `java.lang.classfile` dumper + operand-stack simulation; needs a JDK 24+ |
| Rust frontend (rustc MIR → gIR) | ✅ value-forwarding over MIR; pure Go, default binary; needs `rustc` |
| Ruby frontend (Ripper AST → gIR) | ✅ `rbdump.rb` dumper + straight-line lowering; pure Go, default binary; needs `ruby` |
| C/C++ frontend (LLVM IR → gIR) | ✅ **opt-in cgo** (`-tags "llvm byollvm"` + libLLVM); default build ships a stub |
| Rule engine (YAML, FQN globs, built-in packs) | ✅ taint + dangerous-call kinds across Go/Python/JS/Java/Rust/Ruby/C·C++ (see the [detection matrix](README.md#supported-languages--detections)) |
| Inter-procedural taint (call graph + summaries) | ✅ intra = High, cross-function = Medium confidence |
| Analysis scoping | ✅ demand-driven: `Engine.ScopeSeed` seeds only user functions, so a lowered dependency is analyzed only when taint reaches it |
| Pointer analysis | ⚠️ approximated (CHA + value-flow); a full demand-driven points-to is a future precision upgrade |
| Secrets scanning | ✅ regex over gIR string constants (CWE-798) |
| Report (HTML / JSON / SARIF) + exit-code gating | ✅ |
| LLM reviewer (pluggable) | ✅ Anthropic-backed, confidence-gated, fail-open; off by default |

### Known limitations

- **Straight-line Python/JS lowering.** Control flow is flattened into one
  conceptual iteration. Taint flows through the common expression forms (f-strings /
  template literals, `or`/`and`, ternary, walrus, destructuring/unpacking, optional
  chaining, `await`, tainted-iterable loop variables, comprehensions) and class-based
  handlers with cross-method calls (`self.method(x)` / `this.method(x)`). The main
  remaining gap is taint carried across methods via **instance attributes**
  (`self.attr` / `this.attr`). This maximizes recall for the common web-handler shape
  at the cost of path precision — consistent with the recall-first design.
- **Context-insensitive dispatch (CHA).** An `INVOKE` names the abstract method, so
  the taint transfer resolves it to every concrete method of that name and flows taint
  into each (with the receiver offset handled). This catches taint through interfaces
  but over-approximates, so such findings stay Medium confidence.
- **SSRF host-awareness.** An SSRF finding is suppressed when the untrusted value
  only reaches the **path or query of a fixed host** — reconstructed from
  concatenation and format strings (including Rust's packed `fmt::Arguments`
  template). It is conservative: it drops a finding only when a constant
  `scheme://host/…` prefix is *proven* to precede the taint, so no real SSRF is lost.
  The one construction whose literal template is absent from gIR — Java string `+`
  (`makeConcatWithConstants`) — keeps firing (a possible false positive over a fixed
  host, never a false negative).
- **Go field-access sources.** A source read as a struct field (`r.URL.Path`) lowers
  to `FIELD`/`INDEX` with no `Callee`, so a rule (which matches `Call.Callee`) cannot
  flag it directly. The Go frontend closes this for HTTP handlers by synthesizing a
  request-object source: a function taking both `http.ResponseWriter` and
  `*http.Request` gets its request parameter tainted at entry (`addHTTPRequestSource`),
  so whole-object taint flows to every field read off it — the same boundary-source
  idea the JS/Java/Rust frontends use. Field reads off request objects that reach the
  handler by other means (a custom framework context we don't recognize) still rely on
  method-accessor rules.
