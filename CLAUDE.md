# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Godzilla is a multi-language SAST (Static Application Security Testing) analyzer for CI/CD gates. Source
code is lowered to a language-neutral SSA IR called **gIR** (a Protobuf schema), and one taint-analysis
engine runs over that IR regardless of source language. The full pipeline is implemented and working:

```
source (Go / Python / JS) → frontend → gIR v2 → rule engine + taint analysis → findings → report / gate
                                                                                    └→ optional LLM review
```

Three frontends (Go, Python, JavaScript), an inter-procedural taint engine, a YAML rule engine, a
secrets scanner, an HTML report, and a pluggable LLM reviewer all exist and are tested.

## Commands

```bash
# Build everything (works — the CLI and all packages compile)
go build ./...

# Run the whole test suite
go test ./...

# Run one package / one test
go test ./internal/analysis/
go test ./converters/go/ -run TestGIRv2Metadata

# Scan a project (directory or single .go/.py/.js file). Exit codes: 0 clean, 1 error,
# 2 usage, 3 findings at/above -fail-on (default: medium).
go run ./cmd/godzilla scan ./test/go/sql_injection
go run ./cmd/godzilla scan --summary --html /tmp/report.html --fail-on high <path>
go run ./cmd/godzilla scan --llm-review <path>          # needs ANTHROPIC_API_KEY (or `ant auth`)

# Regenerate gIR Go bindings after editing any proto/*.proto file (requires protoc + protoc-gen-go).
export PATH=$PATH:$(go env GOPATH)/bin
go generate ./...
```

Note: the vulnerable samples under `test/{go,python,js}/*` are each their own isolated module (own
`go.mod` for Go) — never add their dependencies to the root `go.mod`.

## Architecture

**gIR v2 — the contract (`proto/`, generated into `pkg/ir/v1/`).** A deliberately small, language-neutral
SSA opcode core (RET/JUMP/IF/SWITCH/PANIC, ALLOC/LOAD/STORE, FIELD(_ADDR)/INDEX(_ADDR), BIN_OP/UN_OP/PHI,
CALL/INVOKE, CONVERT/TYPE_ASSERT/MAKE_INTERFACE/EXTRACT) plus **`OP_CODE_INTRINSIC`**, the escape hatch:
every language-specific construct (Go `defer`/channels/`go`/`select`, map ops, closures, builtins) is an
intrinsic with a canonical name (e.g. `go.chan.send`, `builtin.make_closure`) that the engine interprets.
Functions carry a **canonical FQN** (`go:net/http.HandleFunc`, `py:flask.request.args.get`,
`js:res.send`); `CallCommon.Callee` holds the callee's canonical name; modules carry a `language` tag. The
proto schema is authoritative — change it first, then `go generate`.

**Frontends (all in-process, single binary).**
- `converters/go/` — uses `golang.org/x/tools` SSA. `ConvertFile` accepts a file or directory and
  enumerates **all** functions via `ssautil.AllFunctions` (package funcs, methods, and closures — vulnerable
  code often lives in `http.HandleFunc` closures, so closure coverage is essential).
- `converters/python/` — shells out to `python3` (`converters/python/pyast.py`, embedded) to get an `ast`
  JSON dump, then lowers it. Straight-line env-based lowering (documented limitations in the package doc).
- `converters/javascript/` — pure-Go parse via `github.com/dop251/goja`, then lowers. Member-read chains
  off an opaque base (`req.query`) become a synthetic source CALL so taint seeds correctly; chained calls
  (`axios.get(u).then(cb)`) lower the inner call via `lowerNestedCallees`.
- `converters/java/` — analyzes **JVM bytecode**. An embedded single-file helper (`JavaDump.java`, run
  via `java`, JDK 24+) compiles `.java` in-process (compiler API) and reads `.class` with the standard
  `java.lang.classfile` API, emitting JSON; `lower.go` runs an **abstract operand-stack simulation** to
  recover SSA values. Instance calls → `OP_CODE_INVOKE` (receiver in `Call.Value`, so a sink `#0` and the
  engine's arg→param mapping both line up); string concat (`makeConcatWithConstants`) → BIN_OP. Canonical
  names `java:<owner>.<method>`.
- `converters/rust/` — analyzes **rustc MIR** (Mid-level IR). Shells out to `rustc --emit=mir
  -Zmir-include-spans=on` (`RUSTC_BOOTSTRAP=1` unlocks the span flag; the MIR text format is itself
  unstable, so this adds no new assumption), then `mir.go` runs a **straight-line value-forwarding**
  pass over the textual MIR. MIR — not LLVM IR — is the right substrate: it names the source-level
  public API (`std::env::var`, `Command::arg`, not the internal monomorphized `std::env::__var`) and
  assigns call results directly to locals (no `sret` out-pointer indirection), so no cgo/libLLVM and
  no memory modeling are needed. Method calls → `OP_CODE_CALL` with the receiver as operand 0 (rules
  pin the tainted arg with `#1`); tuple/array/struct construction → `builtin.aggregate` intrinsic and
  field reads fold to the stored element, so taint flows through `format!`. Canonical names
  `rust:<normalized-path>` (generics stripped). Pure Go, in the default binary; only `rustc` is needed
  at scan time (std-only flows compile standalone; crate-based sources/sinks need the crate present).
- `converters/cpp/` + `converters/llvm/` — C/C++ via **LLVM IR** (clang `-O1 -g -emit-llvm`), lowered
  by the shared `converters/llvm` package. This is the opt-in **cgo** backend (`-tags "llvm byollvm"`
  + libLLVM), NOT in the default build; see the Makefile `*-llvm` targets. (Rust was formerly on this
  path too but moved to the pure-Go MIR frontend above.)
- Both Python and JS name modules by their **path relative to the scan root** (`moduleNameFor`), so
  same-named functions in different files get distinct canonical names instead of colliding in the analyzer.

**Analysis (`internal/analysis/`).**
- `taint.go` — the taint transfer helpers (SSA def-use, `visitStore`/`taintContainer` for aggregate/variadic
  aliasing, intrinsic + opcode propagators).
- `interproc.go` — `Engine.Analyze`: **inter-procedural**, context-insensitive worklist. Taint flows across
  calls via function summaries (tainted arg → callee param; taint-returning function → caller's call result).
  Findings get a `Confidence`: intra-procedural = High, cross-function = Medium.
- `callgraph.go` — `BuildCallGraph` (CHA for dynamic dispatch) + `Reachable`/`Roots` (tree-shaking primitive).
- `secrets.go` — `ScanSecrets`: non-dataflow, regex-based hardcoded-secret detection over gIR string constants
  (CWE-798).
- `finding.go` — the `Finding` type shared across the pipeline.

**Rules (`internal/rules/`).** `rule.go` — the `Rule` model (sources/sinks/sanitizers/propagators as
canonical-FQN globs, `*` matches across `/` and `.`) + `AppliesTo`/glob matcher. A **sink** entry may pin
its injection point with a `#<idx>` suffix (`"go:*database/sql*.Query#0"`): only taint reaching that
LOGICAL (receiver-excluded) argument fires — this is what prevents parameterized-query false positives
(`db.Query("... = ?", taintedParam)` binds a safe placeholder). A bare pattern means all args.
`loader/` — YAML loader (`LoadFile`/`LoadDir`/`Builtin`/`LoadDefault`) with built-in rules embedded via
`//go:embed builtin/*.yaml` (Go/Python/JS rules for SQLi, command injection, path traversal, SSRF, XSS,
open redirect, plus Python insecure deserialization / CWE-502 and JS code injection / CWE-95);
`validate` rejects rules with an empty ID or an unrecognized severity.

**Report & LLM (`internal/report/`, `internal/llm/`).** `report.WriteHTML` renders a self-contained,
auto-escaped HTML report with code snippets; `WriteJSON` and `WriteSARIF` (SARIF 2.1.0, severity→level) emit
machine-readable output for tooling / GitHub code scanning. `llm` is the pluggable reviewer: `review.go` is
dependency-free (interface, confidence-gated `Filter` with fail-open semantics, prompt builder, verdict
parser); `anthropic.go` is the Anthropic-SDK adapter (default `claude-opus-4-8`, override via
`GODZILLA_LLM_MODEL`).

**CLI (`cmd/godzilla/main.go`).** `scan` dispatches to frontends by extension (or runs all on a directory
and merges modules), runs the engine + secrets scan, optionally LLM-reviews, prints findings, writes HTML,
and sets a severity-gated exit code.

## Conventions

- **The proto schema is authoritative.** Any IR change starts in `proto/*.proto`, then `go generate`.
  Never hand-edit `pkg/ir/v1/*.pb.go`.
- **Small core + intrinsics.** Do NOT add an opcode for a language-specific construct — model it as an
  `OP_CODE_INTRINSIC` with a canonical name and teach the engine/rules about that name.
- **Canonical names are the cross-language join.** Frontends must emit stable `<lang>:...` FQNs; rules match
  them with globs. Adding a sink/source is usually a YAML edit, not code.
- **Source mapping is mandatory** — every instruction/function/global populates `Pos`; it drives reporting.
- **Isolated sample modules.** Vulnerable test code lives under `test/{go,python,js}/`; never pollute the
  root `go.mod`.
- **Instruction coverage is tested by absence of fallback comments** — an unhandled SSA/AST node yields a
  `comment`/intrinsic like `unsupported instruction`; converter tests fail if one appears.
- **Confidence drives triage.** Intra-procedural findings are High; cross-function are Medium. The LLM
  reviewer only adjudicates at/below Medium and fails open (never drops a finding on an API error).
