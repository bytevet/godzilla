# TASKS — Java, C/C++, Rust frontends

Plan: `.claude/plans/sprightly-scribbling-owl.md`. Engine/proto/rule format unchanged; new
languages are additive via `<lang>:` canonical names + `OP_CODE_INTRINSIC`.

## Environment reality (this machine)
- ✅ `javac`/`java` 26, `clang` 21, `protoc` 33.
- ❌ `rustc`, `libLLVM`/`llvm-config`, `opt`.
- **Finding:** pure-Go `llir/llvm` cannot parse clang-21 IR (LLVM-16/21 attrs + debug records).
  → C/C++/Rust use the **cgo `-tags llvm`** backend (built/verified in a libLLVM+rustc env, not here).

## Java (verifiable here — build first)
- [x] Embedded dumper `converters/java/JavaDump.java` (single-file `java`, `java.lang.classfile` +
      compiler API): compile `.java` → read `.class` → emit JSON (classes→methods→bytecode + refs).
- [x] `converters/java/{converter.go,lower.go}`: JSON → abstract-stack simulation → gIR SSA.
      Canonical `java:<owner>.<method>`; invokevirtual/interface→INVOKE, static/special→CALL.
- [x] String concat: `invokedynamic makeConcatWithConstants` + `StringBuilder.append/toString`
      as taint propagators.
- [x] Wire into `internal/scan/scan.go` (3 spots) + `sampleLangs` (`test/corpus/manifest.go`).
- [x] Rules `internal/rules/loader/builtin/java-*.yaml` (command injection, SQLi + safe variants).
- [x] Corpus `test/java/<case>/` + `expected.yaml`; converter unit test (no `java.unsupported`).

## C/C++ + Rust (cgo `-tags llvm`) — env has libLLVM 22 + rustc; VERIFIED
- [x] `converters/llvm/`: go-llvm parser + IR->gIR lowering + demangling (`//go:build llvm`).
- [x] `converters/cpp/` (works: C & C++ command injection), `converters/rust/` (parses; aggregate/sret taint = documented limitation). Stubs for the default build.
- [x] Rules c/rust-command-injection + corpus test/{c,cpp} (gated on `llvm` tag + clang).

## Build / CI / docs
- [x] go.mod deps (go-llvm, demangle); Makefile (build/test + build-llvm/test-llvm). [ ] CI `-tags llvm` job.
- [ ] README/CLAUDE/ARCHITECTURE: build modes, toolchain deps, detection matrix.

## Completion gate
- [ ] Default: `gofmt`/`go vet`/`go build`/`go test ./...` green (no cgo).
- [ ] cgo: `go build -tags llvm ./...` + tests in a libLLVM env.
