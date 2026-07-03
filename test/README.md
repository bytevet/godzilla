# Test samples & corpus

This directory holds Godzilla's vulnerable code samples and the **corpus test**
that turns them into first-class, asserted test cases.

## Layout

```
test/
  go/<case>/      main.go + go.mod   (each is its own ISOLATED Go module)
  python/<case>/  app.py
  js/<case>/      app.js
  java/<case>/    *.java, or a Maven/Gradle project  (needs a JDK 24+ `java`;
                                     build-tool projects are opt-in, see below)
  rust/<case>/    main.rs            (needs `rustc`)
  c/<case>/       *.c                (opt-in: -tags llvm + clang)
  cpp/<case>/     *.cpp              (opt-in: -tags llvm + clang)
  corpus/         the Go test harness that scans every sample and checks results
```

Coverage spans common web frameworks as well as the language stdlibs: Gin, Gorm,
Echo and Chi (Go); Django and FastAPI, plus Flask (Python); Express and Koa —
Fastify is matched by the same `req.*` globs (JavaScript); and Spring (Java). Each
framework has at least one true-positive sample and, where precision is at stake, a
`*_safe` false-positive control (parameterized queries, ORM-safe methods, etc.).

Each sample directory carries an **`expected.yaml`** declaring what the scan must
produce for it. The corpus **skips** a language's samples when its toolchain is
absent (`python3`/`java`/`rustc`) or, for C/C++, when the binary was built without
`-tags llvm` — so `go test ./...` stays green on a minimal environment.

**Java build-tool samples.** A Java sample may be a full Maven (`pom.xml`) or Gradle
(`build.gradle`) project rather than loose `.java`: the Java frontend builds it with
its own tool so third-party dependencies (e.g. a Spring app's `spring-web` /
`spring-jdbc`) are on the classpath, then analyzes the compiled bytecode. Because
that fetches dependencies over the network, such samples are **opt-in** — the corpus
skips them unless `GODZILLA_SPRING_E2E=1` is set and a build tool (wrapper, or
`mvn`/`gradle` on `PATH`) is available:

```bash
GODZILLA_SPRING_E2E=1 go test ./test/corpus/ -run TestCorpus/java/spring_boot -v
```

Spring's annotated controller parameters (`@RequestParam`, `@PathVariable`,
`@RequestBody`, …) are treated as taint sources. The `spring_annotation` sample
exercises that mechanism deterministically with the JDK alone (it stubs the
annotations), so it runs by default; `spring_boot` validates the real Gradle build
against actual Spring jars.

**Rust Cargo samples.** A Rust sample may be a `Cargo.toml` project rather than a
loose `.rs` file: the Rust frontend builds it with `cargo rustc -- --emit=mir` so a
dependency crate (a web framework) resolves. A project with **no external deps**
(e.g. `web_command_injection`, which uses a local request stub) runs by default when
`cargo` is present; a project with an **external dependency** (e.g. `web_rouille`,
using the real `rouille` framework) fetches crates over the network and is therefore
**opt-in**, skipped unless `GODZILLA_RUST_E2E=1`:

```bash
GODZILLA_RUST_E2E=1 go test ./test/corpus/ -run TestCorpus/rust/web_rouille -v
```

Taint sources across the samples model the real attack surface — an untrusted HTTP
request parameter / header / body — rather than environment variables (env/args
remain a secondary CLI/CGI source; in C, CGI exposes HTTP data as `QUERY_STRING` /
`HTTP_*` env vars and the body on stdin).

## Running

Everything runs through the root module's test command:

```bash
go test ./...           # unit tests + the sample corpus + isolated-module builds
go test -short ./...    # same, but skip the slow isolated-module (cgo) builds
go test ./test/corpus/ -v   # one PASS/FAIL line per sample
```

`test/corpus/` is part of the root module (no `go.mod` of its own), so `./...`
includes it. The Go sample sub-modules under `test/go/*` have their own `go.mod`
and are therefore *excluded* from `./...` — `test/corpus`'s `TestSampleModulesBuild`
compile-checks them separately (`go build`/`go vet` inside each).

## The `expected.yaml` manifest

```yaml
findings:                 # rules that MUST fire; empty list => sample must be CLEAN
  - rule: go-sql-injection
    min: 2                # at least this many findings for that rule (default 1)
```

`TestCorpus` runs the real scan pipeline (`internal/scan.Scan` with the built-in
rules) over each sample and asserts:

1. every listed rule fires at least `min` times, **and**
2. **no other rule fires** — a false-positive guard (e.g. `complex_logic` declares
   `findings: []`, so any finding on that benign code fails the build).

## Adding a sample

1. Create `test/<lang>/<case>/` with the vulnerable source (Go samples also need a
   minimal `go.mod`; keep any dependencies inside that isolated module).
2. Add an `expected.yaml` describing the intended findings.
3. Run `go test ./test/corpus/ -run "TestCorpus/<lang>/<case>" -v`.

To (re)generate the manifests from the current scan output after a rule change —
then **review the diff** so no regression is frozen in:

```bash
GODZILLA_REGEN=1 go test ./test/corpus/ -run RegenerateManifests -v
```
