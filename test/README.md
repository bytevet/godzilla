# Test samples & corpus

This directory holds Godzilla's vulnerable code samples and the **corpus test**
that turns them into first-class, asserted test cases.

## Layout

```
test/
  go/<case>/      main.go + go.mod   (each is its own ISOLATED Go module)
  python/<case>/  app.py
  js/<case>/      app.js
  java/<case>/    *.java             (needs a JDK 24+ `java`)
  rust/<case>/    main.rs            (needs `rustc`)
  c/<case>/       *.c                (opt-in: -tags llvm + clang)
  cpp/<case>/     *.cpp              (opt-in: -tags llvm + clang)
  corpus/         the Go test harness that scans every sample and checks results
```

Each sample directory carries an **`expected.yaml`** declaring what the scan must
produce for it. The corpus **skips** a language's samples when its toolchain is
absent (`python3`/`java`/`rustc`) or, for C/C++, when the binary was built without
`-tags llvm` — so `go test ./...` stays green on a minimal environment.

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
