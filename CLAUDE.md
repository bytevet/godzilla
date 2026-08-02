# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Godzilla is a multi-language SAST analyzer for CI/CD gates. Seven frontends lower Go, Python, JavaScript,
Java, Rust, Ruby and C/C++ into one language-neutral SSA IR (**gIR**, a Protobuf schema), and a single
taint engine runs over that IR regardless of source language:

```
source → frontend → gIR v2 → rule engine + taint analysis → findings → report / gate
                                                    └→ optional LLM review
```

Design rationale lives in [ARCHITECTURE.md](ARCHITECTURE.md); this file is the code map and the
conventions to work by.

## Commands

```bash
go build ./...
go test ./...

# One package / one test
go test ./internal/analysis/
go test ./converters/go/ -run TestGIRv2Metadata

# Scan a project (directory or single .go/.py/.js/.java/.rs/.rb/.c/.cpp file). Exit codes:
# 0 clean, 1 error, 2 usage, 3 findings at/above -fail-on (default: medium).
go run ./cmd/godzilla scan ./test/go/sql_injection
go run ./cmd/godzilla scan --summary --html /tmp/report.html --fail-on high <path>
go run ./cmd/godzilla scan --llm-review <path>          # needs ANTHROPIC_API_KEY (or `ant auth`)

# Java scanning needs a JDK 24+ `java`; Rust needs `rustc`; both degrade gracefully if absent.
# C/C++ is the opt-in cgo backend — build/test it via the Makefile *-llvm targets (needs libLLVM):
make build-llvm && make test-llvm    # LLVM_CONFIG=/path/to/llvm-config if not on PATH

# Regenerate gIR Go bindings after editing any proto/*.proto file (requires protoc + protoc-gen-go).
export PATH=$PATH:$(go env GOPATH)/bin
go generate ./...
```

Note: the vulnerable samples under `test/{go,python,js,java,rust,ruby,c,cpp}/*` are asserted test cases
(each carries an `expected.yaml`). The Go samples are each their own isolated module (own `go.mod`) —
never add their dependencies to the root `go.mod`.

## Architecture

**gIR v2 — the contract (`proto/` → `pkg/ir/v1/`).** A small, language-neutral SSA opcode core
(RET/JUMP/IF/SWITCH/PANIC/UNREACHABLE, ALLOC/LOAD/STORE, FIELD(_ADDR)/INDEX(_ADDR), BIN_OP/UN_OP/PHI,
CALL/INVOKE, CONVERT/TYPE_ASSERT/MAKE_INTERFACE/EXTRACT) plus **`OP_CODE_INTRINSIC`**, the escape hatch:
every language-specific construct (Go `defer`/channels/`select`, map ops, closures, builtins) is an
intrinsic with a canonical name (`go.chan.send`, `builtin.make_closure`) the engine interprets. Functions
carry a **canonical FQN** (`go:net/http.HandleFunc`, `py:flask.request.args.get`); `CallCommon.Callee` holds
the callee's; modules carry a `language` tag. **Treat it as frozen — see Conventions.**

**Frontends (`converters/`, all in-process, one binary).** Each package's own doc carries its lowering
model and residual limits, and ARCHITECTURE.md the rationale for the substrate choices. What matters when
changing one:
- `go/` — x/tools SSA. Enumerates **all** functions via `ssautil.AllFunctions` including closures, since
  vulnerable code often lives in an `http.HandleFunc` closure. Third-party **dependency bodies ARE lowered**
  (stdlib is not — rules model it) so taint flows THROUGH library code rather than dropping at it. Two
  guards make that affordable and must both hold: findings are **scoped to user code** (`internal/scan`
  `scopeFindings` + `Finding.Package`) and dependency functions are analyzed **demand-driven**
  (`Engine.ScopeSeed` seeds only user functions). `addHTTPRequestSource` seeds a handler's request
  parameter — see its doc comment.
- `python/`, `ruby/` — shell out to `python3` / `ruby` for an AST dump via an embedded helper
  (`pyast.py`, `rbdump.rb`), then lower it.
- `javascript/` — pure-Go goja parse. Extensions that always need one (`.ts/.tsx/.jsx/.mjs/.cjs`) take
  esbuild's in-process `Transform` up front, with a source-map consumer remapping positions back
  (`transform.go`). Plain `.js` does NOT: it is the ambiguous extension — plain script, ESM, Flow and
  JSX all ship as `.js` — so it goes straight to goja and the PARSE FAILURE drives `loaderLadder`,
  which is exact where predicting the dialect was not. `flowstrip.go` is that ladder's last rung:
  Flow has no esbuild loader, so it blanks Flow-only syntax IN PLACE, every removed byte becoming a
  space, because positions must survive and the sourcemap library cannot compose two maps.
  `.vue`/`.svelte` SFCs (`sfc.go`) lower the `<script>` block as the module body and append each
  dangerous template directive (`v-html`, `{@html}`) as a synthetic sink CALL.
- `java/` — JVM **bytecode**, via an embedded `JavaDump.java` (JDK 24+, `java.lang.classfile`) plus an
  operand-stack simulation in `lower.go`. Instance calls become `OP_CODE_INVOKE` with the receiver in
  `Call.Value`, so sink `#0` pinning and the engine's arg→param mapping line up. A Maven/Gradle target is
  built by its own tool first (`resolveInputs`) to get deps on the classpath.
- `rust/` — **rustc MIR**, pure Go, in the default binary. `format!` lowers to `fmt::Arguments::new` with a
  packed byte-template that `decodeFmtTemplate` decodes to `{}` placeholders, which is what lets the SSRF
  host check read its constant pieces. A `Cargo.toml` target is built with `cargo rustc`.
- `cpp/` + `llvm/` — C/C++ via LLVM IR; the opt-in **cgo** backend (`-tags "llvm byollvm"`), NOT in the
  default build. See the Makefile `*-llvm` targets.
- **A source that is not a call in the source language** — a member read off an opaque base (`req.query`),
  a Spring `@RequestParam`, a Rails `params[:x]` — is lowered as a **synthetic source CALL** with a
  canonical name. JS, Python, Ruby and Java all use this, so such a source costs a frontend + YAML change
  and **no gIR/engine change**. Sinks use the mirror trick (the Vue/Svelte directives above).
- Python, JS and Ruby share their scaffolding rather than re-implementing it: `internal/walkignore`
  (target resolution, pruned walk, and the scan-root-relative module names that stop same-named functions
  in different files from colliding), `internal/proc.WriteEmbeddedScript`, `internal/chunks.Run`
  (concurrent per-file lowering), and `converters/ssabuild` (the real-CFG builder with on-demand PHIs).

**Analysis (`internal/analysis/`).** The engine's design and its precision guards — and the failures that
motivated them — are documented in the package itself (`internal/analysis/doc.go`, `go doc ./internal/analysis`);
this is a file map.
- `taint.go` — the taint transfer helpers (SSA def-use, `visitStore`/`taintContainer` for aggregate/variadic
  aliasing, intrinsic + opcode propagators). `BIN_OP` is a universal propagator so `+` concatenation carries
  taint across **every** language — including Rust, whose frontend lowers `String + &str` (rustc's `Add::add`
  call) to `BIN_OP_ADD` just like Go/JS/Python `+`, so the engine needs no Rust-callee special case. That
  works because a comparison is never lowered to `BIN_OP`: a frontend emits the inert **`builtin.compare`**
  intrinsic instead (Go/JS/Python do), since a boolean result carries influence, not content — which is what
  stops `fmt.Sprint(user == "admin")` reading as an injection. Teaching a frontend to emit it is the whole
  opt-in; the engine has no comparison-specific code.
- `interproc.go` — `Engine.Analyze`, the inter-procedural worklist: cross-function summaries, the
  framework-agnostic HTTP request sources (rule source globs + the net/http entries in the
  `_default-propagators.yaml` fragment, plus `buildReqSourceHosts` for a dependency that reads an
  `*http.Request` field without exposing one in its signature), and the sink-parameter summary channel.
- `ssrf.go` — supplies the **`hostFixed()` FACT** behind the CWE-918/601 false-positive reduction; rules opt
  in with `when: 'not hostFixed()'`. It reads only **neutral IR the frontends emit**, never callee names:
  `BIN_OP_ADD` concatenation (every language's `+`), Python `%` (`BIN_OP_REM`), and two frontend-set intrinsic
  markers — **`builtin.format`** (printf-style formatter, template in `Args[0]`: Go `fmt.Sprint*`, Java
  `String.format`, Rust `fmt::Arguments::new`, whose packed byte-template `mir.go` `decodeFmtTemplate` decodes)
  and **`builtin.identity`** (a forwarding string conversion: `to_string`/`as_str`/`clone`/…). Both markers are
  inert to taint propagation. Emitting either from a frontend is what opts that language into the reduction.
- `callgraph.go` — `BuildCallGraph` (CHA for dynamic dispatch); the engine consumes its reverse edges
  (`buildCallers`) to re-enqueue a callee's callers when the callee becomes taint-returning.
- `walk.go` — the `funcs`/`instrs` gIR iterators the once-per-scan passes share instead of each
  re-writing the nil-guarded module→function→block→instruction nest.
- `secrets.go` — `ScanSecrets`: applies the `kind: secret` rules' regexps to gIR string constants and to
  config files no frontend parses (CWE-798). The patterns are data in `rulepacks/secrets.yaml`, not Go.
- `finding.go` — the `Finding` type shared across the pipeline.

**Rules (`internal/rules/` + `rulepacks/`).** `rule.go` — the `Rule` model (sources/sinks/sanitizers/
propagators as canonical-FQN globs, where `*` matches across `/` and `.`) and the glob matcher. A **sink**
may pin its injection point with a `#<idx>` suffix (`"go:*database/sql*.Query#0"`): only taint reaching
that LOGICAL (receiver-excluded) argument fires, which is what stops `db.Query("... = ?", tainted)` from
being a false positive. A bare pattern means all args. `guard.go` — the `when:` expression DSL and the
`hostFixed()` fact; a rule-level `when:` is the default every unguarded sink inherits, and a fragment
may supply that default. `loader/` — YAML
loading; the built-in packs live in the top-level `rulepacks/`, embedded by `rulepacks/embed.go` and
returned by `Builtin()`. `validate` rejects an empty ID or an unrecognized severity. Three `kind:`s —
dataflow (default), `dangerous-call`, and `secret`. `_`-prefixed **fragments** are pulled in with
`extend:`, except `_default-propagators.yaml`, which the loader applies to EVERY rule
(`RuleSet.DefaultPropagators`); anything constructing a RuleSet from another must carry that field over. Which classes ship per
language is the [detection matrix](README.md#supported-languages--detections); authoring reference is
`docs/writing-rules.md`.

**Report & LLM (`internal/report/`, `internal/llm/`).** `WriteHTML` renders a self-contained, auto-escaped
report with code snippets; `WriteJSON` and `WriteSARIF` (2.1.0, severity→level) feed tooling and GitHub
code scanning. `llm/review.go` is dependency-free (interface, confidence-gated `Filter` with fail-open
semantics, prompt builder, verdict parser); `anthropic.go` and `openai.go` are the backends (default
`claude-haiku-4-5`; `GODZILLA_LLM_MODEL` overrides the model,
`GODZILLA_LLM_PROVIDER=openai` + `GODZILLA_LLM_BASE_URL` selects an
OpenAI-compatible endpoint, e.g. a local model).

**CLI (`cmd/godzilla/`).** `main.go` parses flags and sets the severity-gated exit code; `rules.go` adds
`rules list|lint|test`. The per-extension frontend dispatch, module merge, engine + dangerous-call +
secrets passes, and `scopeFindings` live in **`internal/scan`**, not `main.go`.

**Supporting packages.** `internal/scan` (orchestration, `Result.Coverage` — a frontend that failed to run is
NOT a clean scan, which `-strict` turns into a non-zero exit), `internal/triage` (baseline +
`godzilla:ignore`), `internal/config` (`.godzilla.yaml`), `internal/buildpolicy` (the `-allow-build` gate on
running a scanned project's build tool), `internal/ruletest` (backs `rules test`), plus the shared frontend
scaffolding: `internal/chunks`, `internal/proc`, `internal/walkignore`, `internal/memlimit`.

## Conventions

- **gIR is frozen; changing it is a last resort.** Every frontend emits the schema (`proto/*.proto` →
  `pkg/ir/v1/`) and the single engine consumes it, so a schema change ripples across all of them. Reach in
  this order instead: (1) a YAML rule edit; (2) an `OP_CODE_INTRINSIC` with a canonical name the
  engine/rules interpret — never a new opcode for a language-specific construct; (3) the frontend's own
  lowering. Change the proto only when a genuinely new *structural* concept cannot be expressed by the
  existing opcodes plus intrinsics, and say why in the change. If it is unavoidable, edit `proto/*.proto`
  and run `go generate` — never hand-edit `pkg/ir/v1/*.pb.go`.
- **Canonical names are the cross-language join.** Frontends must emit stable `<lang>:...` FQNs; rules match
  them with globs. Adding a sink/source is usually a YAML edit, not code.
- **The guard and rule contract needs the maintainer's explicit approval — ASK FIRST, every time.** This
  covers the `when:` DSL surface (`internal/rules/guard.go`: the `guardEnv` roots `arg`/`kwargs`, the `Arg`
  fields, and the engine-supplied facts like `hostFixed()`) and the `Rule` model itself
  (`internal/rules/rule.go`: `sources`/`sinks`/`sanitizers`/`propagators`, `kind:`, `extend:`, `#<idx>`
  pinning). It is a PUBLIC API: every built-in pack and every user-authored rules directory is written
  against it, and unlike Go code they are not compiled — a removed field or a changed fact silently
  suppresses findings instead of failing the build, and a guard that errors at runtime suppresses its entry.
  Adding a field or fact is as breaking as removing one, because rules then depend on it. Propose the change
  and the rule edits it forces, get agreement, then implement. Using the existing surface — a new `when:` on
  a rule, a new sink glob — is ordinary work and needs no approval.
- **Source mapping is mandatory** — every instruction/function/global populates `Pos`; it drives reporting.
- **Isolated sample modules.** Vulnerable test code lives under `test/{go,python,js,java,rust,ruby,c,cpp}/`;
  Go samples are isolated modules — never pollute the root `go.mod` with sample dependencies.
- **Instruction coverage is tested by absence of fallback comments** — an unhandled SSA/AST node yields a
  `comment`/intrinsic like `unsupported instruction`; converter tests fail if one appears.
- **Confidence drives triage.** Intra-procedural findings are High; cross-function are Medium. The LLM
  reviewer only adjudicates at/below Medium and fails open (never drops a finding on an API error).
