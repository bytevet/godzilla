# Contributing to Godzilla

Thanks for your interest! This guide covers the essentials.

## Development setup

- **Go 1.25+** is required.
- **`python3`** on `PATH` is needed to run the Python frontend's tests (and for
  highest-fidelity Python scanning).
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
- `converters/{go,python,javascript}/` — language frontends (source → gIR).
- `internal/analysis/` — call graph + inter-procedural taint + secrets scan.
- `internal/rules/` — rule model, glob matcher, YAML loader, built-in rule packs.
- `internal/report/`, `internal/llm/` — HTML report and optional LLM reviewer.
- `cmd/godzilla/` — the CLI.
- `test/{go,python,js}/` — vulnerable samples, each its own isolated module.

## Common contributions

**Add or improve a detection rule.** Usually just YAML under
`internal/rules/loader/builtin/`. Sources/sinks/sanitizers/propagators are
canonical-name globs; a sink may pin its injection-point argument with `#<index>`
(e.g. `"go:*database/sql*.Query#0"`). Add a vulnerable sample under `test/<lang>/`
with an `expected.yaml` — the corpus test then asserts it (see
[test/README.md](test/README.md)) — and, ideally, a safe variant that stays clean.

**Add a language frontend.** Mirror the structure of `converters/python` or
`converters/javascript`: parse, then lower to gIR with stable `<lang>:` canonical
names. Emit `OP_CODE_INTRINSIC` (with a canonical intrinsic name) for
language-specific constructs rather than adding new opcodes.

**Change the gIR schema.** Edit `proto/*.proto` first (it is authoritative), then
`go generate ./...`. Never hand-edit `pkg/ir/v1/*.pb.go`.

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
