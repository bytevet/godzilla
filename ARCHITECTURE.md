# Godzilla Architecture & Design

> This document describes the **as-built** architecture and the reasoning behind
> it. The whole pipeline — seven frontends (Go, Python, JavaScript, Java, Rust,
> Ruby, C/C++), the rule engine, analysis engine, report module, LLM reviewer,
> and CLI — is implemented and tested. See [CLAUDE.md](CLAUDE.md) for the
> package-level code map and [docs/writing-rules.md](docs/writing-rules.md) for
> rule authoring.

Godzilla is a **rapid, multi-language SAST tool** for CI/CD quality gates. Any
supported language is lowered to a single language-neutral IR (**gIR**), and one
analysis core runs over it. Three design goals:

1. **Ultra fast** — usable as a per-commit CI checkpoint.
2. **High signal/noise** — few false positives at the gate.
3. **Multi-language** — one analysis core, many frontends.

These pull against each other (precision is expensive; speed favors
approximation). The design resolves the tension with a small IR, demand-driven
analysis scoping, recall-oriented taint, and an optional LLM reviewer as a
false-positive backstop.

## Design principles

The sections below describe each component; these are the commitments that shaped
all of them.

- **gIR is the contract.** No pass ever branches on source language — only on gIR
  structure and canonical symbol names. Getting the IR right first avoids reworking
  every frontend and pass later, which is also why it is now frozen.
- **SSA is mandatory,** because def-use chains make taint dramatically simpler and
  faster. A frontend whose source is not already SSA constructs it during lowering
  (`converters/ssabuild`).
- **In-process, single binary,** for fast startup and trivial CI deployment,
  shelling out to a language toolchain only where unavoidable.
- **Recall first, precision backstop.** Lowering favors catching the common
  web-handler vulnerability shape; a confidence score plus the optional LLM reviewer
  trim the residual false positives.

## High-level architecture

```
          ┌───────── Frontends (in-process Go, one binary) ─────────┐
 Go   ────► x/tools SSA ───┐
 Python ──► python3 ast  ──┤
 JS   ────► esbuild AST  ──┤
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

Small and language-neutral:

- **Terminators:** `RET`, `JUMP`, `IF`, `SWITCH`, `PANIC`, `UNREACHABLE`
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
uniformly. The core stays neutral while every language construct has a home — no
opcode per language feature.

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
naming to this scheme; analysis and rules only see canonical names, matched with
globs (`*` spans `/` and `.`).

### Source mapping

Every instruction, function, and global carries a `Position` (file/line/column) —
non-negotiable, since it drives both reporting and the HTML path visualization.

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
   caller's call result. Two out-of-band summary channels carry taint that flows
   through, not out of, a dependency: an **out-parameter fill** (the callee writes
   taint into memory reachable from a parameter) and a **sink-parameter summary**
   (the callee routes a *string* parameter into a sink internally — a dependency
   "sink wrapper" like `Run(cmd string){ exec.Command(cmd) }`), so the finding is
   reported at the user call site the dep-internal sink was scoped out of. The
   string-parameter restriction keeps reflective-ORM over-approximations (an
   `interface{}` bean bound as a `?` placeholder) from surfacing.
4. **Alias tracking** is approximated with value-flow (def-use + container taint for
   aggregates/variadics) plus CHA — sound and sufficient for the target vuln classes,
   short of a full demand-driven points-to.
5. **Confidence scoring.** Intra-procedural findings are High; cross-function are
   Medium. Low-confidence findings are the ones the LLM reviewer adjudicates.

Analysis cost is scoped **demand-driven**: `Engine.ScopeSeed` seeds only user
functions, so a lowered dependency function is analyzed only when taint reaches it
(see the Go frontend's dependency lowering). The **secrets scanner**
(`ScanSecrets`, CWE-798) runs alongside taint, applying the `kind: secret` rules'
regexps to gIR string constants and to config files no frontend parses.

## Rule engine

YAML rules matched against canonical symbols (`internal/rules/`), in three kinds:

- **Taint rules** (default) — a source→sink dataflow spec with
  sanitizers/validators/propagators, and a sink that may pin its injection-point
  argument with `#<index>`.
- **Dangerous-call rules** (`kind: dangerous-call`) — a non-dataflow, call-site
  match, optionally gated on a constant argument. Backs the weak-crypto packs
  (weak hash/cipher CWE-327, insecure `math/rand` CWE-338).
- **Secret rules** (`kind: secret`) — no call at all: a regexp over string
  constants and config-file lines, backing the CWE-798 pack. Keeping these as
  rules rather than a Go table means a project can add its own credential format
  through `--rules`, and `rules list|lint|test` covers them like anything else.

Built-in packs live in `rulepacks/` and are embedded into the binary; `--rules`
merges user rules on top. Shared pattern lists live in `_`-prefixed **fragments**
that a pack pulls in with `extend:`, with one exception the loader applies to
every rule automatically: `_default-propagators.yaml`, the taint-preserving
stdlib transforms (`strings.TrimSpace`, `str.strip`, `String.trim`) that no rule
should have to restate.
Full authoring reference: [docs/writing-rules.md](docs/writing-rules.md).

## Frontends

All frontends run **in-process** and emit gIR with canonical FQNs and SSA; the tool
ships as a single Go binary. Only C/C++ needs cgo — the rest are pure Go, with
Python/Java/Rust/Ruby shelling out to a toolchain on `PATH`.

- **Go** (`converters/go/`) — `golang.org/x/tools` SSA (already SSA). Enumerates all
  functions incl. closures via `ssautil.AllFunctions`, since vulnerable code often
  lives in `http.HandleFunc` closures. Emits `go:` names.
- **Python** (`converters/python/`) — shells out to `python3` for an `ast` JSON
  dump, then lowers it to a real CFG (`ssabuild`). Emits `py:` names; requires `python3`.
- **JavaScript** (`converters/javascript/`) — pure-Go parse of **esbuild's AST**
  (`github.com/bytevet/esbuild-jsast`, which re-exports the parser esbuild keeps under
  `internal/`), then lowers. TypeScript, JSX and ES modules are parsed as themselves —
  no text transform, no Node, and no sourcemap in the position path, since a node's byte
  offset already indexes the source as written. One extension covers four dialects, so the
  dialect is found by trying them (`parseLadder`) rather than predicted. Flow, which is
  neither JS nor TS, is blanked in place beforehand (`flowstrip.go`) so byte offsets — and
  therefore positions — are preserved. `.vue`/`.svelte` SFCs are also handled (`sfc.go`):
  the `<script>` block lowers as JS/TS and each dangerous template directive (`v-html`,
  `{@html}`) compiles to a synthetic sink call. Emits `js:` names.
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
  `lower.go` lowers that tree to a real CFG (`ssabuild`). Ripper ships with every MRI Ruby.
  `.erb` templates are stripped to plain Ruby first (`erb.go`), blanking the markup IN PLACE so
  byte offsets — and therefore positions — survive; `<%== %>` becomes the `raw()` call
  ruby-xss.yaml already models. Emits `ruby:` names.
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

Every component described above is implemented and tested end-to-end, and every
vuln class is detected across the languages that have samples (see the
[detection matrix](README.md#supported-languages--detections)). Two components are
deliberately approximate rather than complete:

| Component | Status |
|---|---|
| Pointer analysis | ⚠️ approximated (CHA + value-flow); a full demand-driven points-to is a future precision upgrade |
| Python / JS / Ruby lowering | ⚠️ real CFG + SSA, but exceptions and `break`/`continue` stay approximate (below) |

### Known limitations

- **Residual lowering approximations (Python/JS/Ruby).** These frontends build a
  real CFG via `converters/ssabuild`, so branches, loops and their PHI joins are
  modeled; what is still approximated is exceptions (merged into one untyped
  handler block) and `break`/`continue` (dropped). Taint flows through the common expression forms (f-strings /
  template literals, `or`/`and`, ternary, walrus, destructuring/unpacking, optional
  chaining, `await`, tainted-iterable loop variables, comprehensions) and class-based
  handlers with cross-method calls (`self.method(x)` / `this.method(x)`), and across
  **instance attributes** for Python and Ruby (`self.attr` / `@ivar`); JS
  `this.attr` remains a gap. This maximizes recall for the common web-handler shape at the cost of
  path precision — consistent with the recall-first design.
- **Context-insensitive dispatch (CHA).** An `INVOKE` names the abstract method, so
  taint transfer resolves it to every concrete method of that name and flows into
  each (receiver offset handled). This catches taint through interfaces but
  over-approximates, so such findings stay Medium confidence.
- **SSRF host-awareness.** An SSRF finding is suppressed when the untrusted value
  only reaches the **path or query of a fixed host** — reconstructed from
  concatenation and format strings (including Rust's packed `fmt::Arguments`
  template). Conservative: it drops a finding only when a constant `scheme://host/…`
  prefix is *proven* to precede the taint, so no real SSRF is lost. The one
  construction whose literal template is absent from gIR — Java string `+`
  (`makeConcatWithConstants`) — keeps firing (a possible false positive over a fixed
  host, never a false negative).
- **Go field-access sources.** A source read as a struct field (`r.URL.Path`) lowers
  to `FIELD`/`INDEX` with no `Callee`, so a rule (which matches `Call.Callee`) cannot
  flag it directly. The Go frontend closes this for HTTP handlers by synthesizing a
  request-object source: a function taking both `http.ResponseWriter` and
  `*http.Request` gets its request parameter tainted at entry (`addHTTPRequestSource`),
  so whole-object taint flows to every field read off it — the same boundary-source
  idea the JS/Java/Rust frontends use. Field reads off request objects reaching the
  handler by other means (an unrecognized custom framework context) still rely on
  method-accessor rules.
