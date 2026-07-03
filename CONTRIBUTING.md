# Contributing to Godzilla

Thanks for your interest! This guide covers the essentials.

## Development setup

- **Go 1.25+** is required.
- Optional per-language toolchains (their frontend tests **skip** when absent):
  **`python3`** (Python), a **JDK 24+ `java`** (Java), **`rustc`** (Rust). The Go
  and JavaScript frontends are pure Go and need nothing extra.
- **C/C++** is the opt-in cgo backend: it needs **libLLVM + clang** and builds only
  under `-tags "llvm byollvm"` — use the Makefile `*-llvm` targets. The default
  build/test path does not touch it.
- **`protoc` + `protoc-gen-go`** are only needed if you change the gIR schema
  (`proto/*.proto`) and regenerate bindings.

```bash
go build ./...
go test ./...                              # unit tests + sample corpus + isolated-module builds
go test -short ./...                       # faster: skips the isolated-module builds
go vet ./...
gofmt -l cmd converters internal test/corpus   # must print nothing
```

All must pass before a PR is merged; CI runs the same checks. `go test ./...`
also asserts every sample under `test/` against its `expected.yaml` — see
[test/README.md](test/README.md).

## Project layout

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and [CLAUDE.md](CLAUDE.md)
for a concise map of the codebase. In short:

- `proto/`, `pkg/ir/v1/` — the gIR schema (source of truth) and generated bindings.
- `converters/{go,python,javascript,java,rust,cpp,llvm}/` — language frontends
  (source → gIR); `cpp`/`llvm` are the opt-in cgo backend.
- `internal/analysis/` — call graph + inter-procedural taint + secrets scan.
- `internal/rules/` — rule model, glob matcher, YAML loader, built-in rule packs.
- `internal/report/`, `internal/llm/` — HTML/JSON/SARIF report and optional LLM reviewer.
- `cmd/godzilla/` — the CLI.
- `test/{go,python,js,java,rust,c,cpp}/` — vulnerable samples (Go ones are isolated modules).

## Common contributions

**Add or improve a detection rule.** Usually just YAML in the top-level
`rulepacks/` directory. Sources/sinks/sanitizers/propagators are
canonical-name globs; a sink may pin its injection-point argument with `#<index>`
(e.g. `"go:*database/sql*.Query#0"`). Add a vulnerable sample under `test/<lang>/`
with an `expected.yaml` — the corpus test then asserts it (see
[test/README.md](test/README.md)) — and, ideally, a safe variant that stays clean.

**Add a language frontend.** Mirror the structure of `converters/python` or
`converters/javascript`: parse, then lower to gIR with stable `<lang>:` canonical
names. Emit `OP_CODE_INTRINSIC` (with a canonical intrinsic name) for
language-specific constructs rather than adding new opcodes.

**Change the gIR schema — a last resort.** gIR is the frozen contract every
frontend emits and the single engine consumes, so a schema change ripples across
all of them. First try to model the construct as an `OP_CODE_INTRINSIC` (with a
canonical name), a YAML rule, or frontend lowering. If a change is genuinely
unavoidable, edit `proto/*.proto` first (it is authoritative), then
`go generate ./...` — never hand-edit `pkg/ir/v1/*.pb.go`.

## Conventions

- Keep the gIR core small; model language-isms as intrinsics.
- Every instruction/function/global must populate its source `Pos` — it drives
  reporting.
- Never add sample dependencies to the root `go.mod`; samples are isolated modules.
- Prefer adding a regression test alongside any bug fix.

## Reporting security-relevant issues

If you find a vulnerability in Godzilla itself (as opposed to a detection
gap), please open an issue describing it; avoid posting working exploits against
third-party targets.
