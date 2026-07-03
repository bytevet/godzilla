# TASKS — realistic HTTP sources (replace env-as-source in samples)

Goal: taint-source test cases should model real attack surface (HTTP header / body /
query·path params), not environment variables. Scope (from survey): Rust (12 samples),
C/C++ (5), Java base cmd/sql (3). Go/Python/JS + Java Spring/servlet already realistic.

Constraint: this sandbox has **no network**, so external crates can't be fetched. Mirror
Session B's Spring pattern — a **hermetic sample runs by default**, a **real-crate/framework
sample is opt-in** (gated, runs only where the toolchain can fetch deps).

## Rust
- [x] HTTP-source rules: add framework request-accessor sources to rust-*.yaml
      (`*Request::header|query|body|get_param`, actix `*HttpRequest*query_string|headers|match_info`).
- [x] Convert the 12 env samples to HTTP sources via a self-contained inline request stub
      (hermetic, single-file, no Cargo) — preserving each sample's engine-mechanics coverage
      (direct / inter-proc / collect+index / argv / format! / File::open / FP sentinels).
- [x] Cargo-project support in `converters/rust` (build via `cargo rustc -- --emit=mir`,
      collect the crate MIR from target/deps). Verify offline with a **no-external-dep Cargo sample**.
- [x] Opt-in **real-framework** Cargo sample (rouille/axum), gated (`GODZILLA_RUST_E2E=1` + cargo),
      skipped when offline — the Rust analogue of `spring_boot`.

## C / C++
- [x] Reframe sources to real web input: CGI (`getenv("QUERY_STRING")`, `getenv("HTTP_*")` — how C
      CGI reads params/headers) and/or socket `recv()`. Update sample vars/comments; add a recv variant.

## Java
- [x] Convert the 3 `System.getenv` base cmd/sql samples to `HttpServletRequest.getParameter/getHeader`
      (servlet rules already exist).

## Wrap-up
- [x] Docs (CLAUDE/README/test) note the HTTP-source model + the hermetic/opt-in split.
- [x] Completion gate: gofmt/vet/build + full `go test ./...` green in BOTH build modes. No gIR change.
