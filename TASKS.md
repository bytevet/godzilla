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

## C/C++ (cgo `-tags llvm`) — env has libLLVM 22; VERIFIED
- [x] `converters/llvm/`: go-llvm parser + IR->gIR lowering + demangling (`//go:build llvm`).
- [x] `converters/cpp/` (C & C++ command injection, path traversal, format string). Stub for default build.
- [x] Rules c-* + corpus test/{c,cpp} (gated on `llvm` tag + clang).

## Rust — rebuilt on rustc MIR (pure Go, DEFAULT build); VERIFIED
- [x] LLVM-IR approach abandoned (sret out-pointers, stack-memory flow, internal v0 names).
- [x] `converters/rust/{converter.go,mir.go}`: `rustc --emit=mir -Zmir-include-spans=on` (RUSTC_BOOTSTRAP=1)
      → straight-line value-forwarding → gIR SSA. Source-level names (`rust:var`, `rust:Command::arg`),
      receiver = operand 0, `format!` via `builtin.aggregate` intrinsic + field-read folding. No cgo.
- [x] Rules rust-{command-injection,path-traversal}; samples test/rust/{command_injection,
      command_injection_safe,path_traversal} + expected.yaml; converter unit tests; corpus wired
      (`sampleLangs` + rustc-gated skip). End-to-end: cmd-injection + path-traversal fire, safe = 0. ~40 ms/file.

## Build / CI / docs
- [x] go.mod deps (go-llvm, demangle); Makefile (build/test + build-llvm/test-llvm). [ ] CI `-tags llvm` job.
- [x] README/CLAUDE: build modes, toolchain deps, detection matrix (incl. Rust=MIR/default, Java, C/C++). [ ] ARCHITECTURE.

## Completion gate
- [x] Default: `gofmt`/`go vet`/`go build`/`go test ./...` green (no cgo) — incl. Java + Rust.
- [x] cgo: `go build -tags "llvm byollvm" ./...` + corpus green in the libLLVM env (c/cpp + rust).
