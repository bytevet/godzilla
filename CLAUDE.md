# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Godzilla is a multi-language SAST (Static Application Security Testing) analyzer for CI/CD gates. Source
code is lowered to a language-neutral SSA IR called **gIR** (a Protobuf schema), and one taint-analysis
engine runs over that IR regardless of source language. The full pipeline is implemented and tested:

```
source (Go / Python / JS / Java / Rust / Ruby / C·C++) → frontend → gIR v2 → rule engine + taint analysis → findings → report / gate
                                                                                              └→ optional LLM review
```

Seven frontends — Go, Python, JavaScript, Java (JVM bytecode), Rust (rustc MIR), Ruby (stdlib Ripper),
and C/C++ (LLVM IR, an opt-in cgo build) — plus an inter-procedural taint engine, a YAML rule engine, a
secrets scanner, an HTML/JSON/SARIF report, and a pluggable LLM reviewer.

## Commands

```bash
# Build everything (works — the CLI and all packages compile)
go build ./...

# Run the whole test suite
go test ./...

# Run one package / one test
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

**gIR v2 — the contract (`proto/`, generated into `pkg/ir/v1/`).** A small, language-neutral SSA opcode
core (RET/JUMP/IF/SWITCH/PANIC/UNREACHABLE, ALLOC/LOAD/STORE, FIELD(_ADDR)/INDEX(_ADDR), BIN_OP/UN_OP/PHI,
CALL/INVOKE, CONVERT/TYPE_ASSERT/MAKE_INTERFACE/EXTRACT) plus **`OP_CODE_INTRINSIC`**, the escape hatch:
every language-specific construct (Go `defer`/channels/`go`/`select`, map ops, closures, builtins) is an
intrinsic with a canonical name (e.g. `go.chan.send`, `builtin.make_closure`) that the engine interprets.
Functions carry a **canonical FQN** (`go:net/http.HandleFunc`, `py:flask.request.args.get`,
`js:res.send`); `CallCommon.Callee` holds the callee's canonical name; modules carry a `language` tag. The
proto schema is authoritative — change it first, then `go generate`. **Treat gIR as a frozen contract and
avoid changing it (see Conventions); reach for intrinsics, not new schema.**

**Frontends (all in-process, single binary).**
- `converters/go/` — uses `golang.org/x/tools` SSA. `ConvertFile` accepts a file or directory and
  enumerates **all** functions via `ssautil.AllFunctions` (package funcs, methods, and closures — vulnerable
  code often lives in `http.HandleFunc` closures, so closure coverage is essential). Third-party **dependency
  bodies ARE lowered** (a two-phase load: a metadata-only `go list` classifies the closure by module, then
  syntax is loaded for every non-stdlib package as an explicit root; the stdlib arrives as compiled export
  data with bodyless SSA packages) so taint flows THROUGH library/utility code instead of dropping at it
  (a false-negative class); the Go **stdlib** is skipped (modeled by rules).
  Two things keep this affordable: findings are **scoped to user code** (`internal/scan` `scopeFindings` +
  `Finding.Package`; a sink reached inside a library is not reported), and dependency functions are analyzed
  **demand-driven** (`Engine.ScopeSeed` seeds only user functions; a dependency function is analyzed only when
  taint reaches it), so analysis cost doesn't scale with the dependency closure. Function lowering runs
  concurrently (per-worker `typeCache`). The residual cost is the x/tools SSA build of the dep closure.
  `addHTTPRequestSource` synthesizes a request-object source (`go:@net/http.Request`) at an HTTP handler's
  entry — a func taking `http.ResponseWriter`+`*http.Request`, or one registered via a routing verb
  (`collectRouteHandlers`: `r.GET`/`.Post`/`.HandleFunc`/`.Use`/…) — binding the request/context parameter so
  field reads off it are tainted (fixes the field-access-source gap) and, with the engine's request-object
  rule, framework accessors (`c.Query()`) are covered even for an unmodeled framework.
- `converters/python/` — shells out to `python3` (`converters/python/pyast.py`, embedded) to get an `ast`
  JSON dump, then lowers it. Straight-line env-based lowering (documented limitations in the package doc).
- `converters/javascript/` — pure-Go parse via `github.com/dop251/goja`, then lowers. Member-read chains
  off an opaque base (`req.query`) become a synthetic source CALL so taint seeds correctly; chained calls
  (`axios.get(u).then(cb)`) lower the inner call via `lowerNestedCallees`. **TypeScript/JSX/ESM**
  (`.ts/.tsx/.jsx/.mjs/.cjs`) go through esbuild's in-process `Transform` (pure Go, no Node): it strips
  TS types and lowers ES modules to CommonJS (`require`/`exports`, which the lowering already understands)
  before goja parses, and a `go-sourcemap` consumer remaps finding positions back to the original file
  (`transform.go`, `remapPositions`). esbuild's ESM-interop `(0, import_mod.fn)(x)` callee is recovered by a
  `SequenceExpression` case in `syntacticCallee`. Plain `.js` skips the transform.
  **Vue/Svelte SFCs** (`.vue`/`.svelte`, `sfc.go`) compile to JS: the `<script>` block becomes the
  module body and each dangerous template directive is appended as a synthetic sink CALL
  (`v-html`→`js:__godzilla_vue_vhtml`, `{@html}`→`js:__godzilla_svelte_html`), so template-injection
  XSS flows through the engine with **no gIR/engine change**; escaped interpolation (`{{ }}`/`{ }`)
  emits nothing.
- `converters/java/` — analyzes **JVM bytecode**. An embedded single-file helper (`JavaDump.java`, run
  via `java`, JDK 24+) compiles `.java` in-process (compiler API) and reads `.class` with the standard
  `java.lang.classfile` API, emitting JSON; `lower.go` runs an **abstract operand-stack simulation** to
  recover SSA values. Instance calls → `OP_CODE_INVOKE` (receiver in `Call.Value`, so a sink `#0` and the
  engine's arg→param mapping both line up); string concat (`makeConcatWithConstants`) → BIN_OP. Canonical
  names `java:<owner>.<method>`. A **Maven/Gradle project** target (`pom.xml` / `build.gradle`) is compiled
  by its own build tool first (`resolveInputs` in `converter.go`, preferring a `mvnw`/`gradlew` wrapper,
  else `mvn`/`gradle` on PATH) so third-party deps (Spring, etc.) are on the classpath, and the resulting
  `.class` output is analyzed — falling back to the in-process compile when there's no build tool or the
  build fails. **Spring controller param annotations** (`@RequestParam`/`@PathVariable`/`@RequestBody`/…)
  become taint sources by *synthesizing a source CALL* per annotated parameter (JavaDump emits
  `paramAnnotations`; `lower.go` binds the param slot to a `java:<annotation>` CALL) — the same trick
  JS/Python use for opaque-base member reads, so it's a frontend + YAML change with **no gIR/engine change**.
- `converters/rust/` — analyzes **rustc MIR** (Mid-level IR). Shells out to `rustc --emit=mir
  -Zmir-include-spans=on` (`RUSTC_BOOTSTRAP=1` unlocks the span flag; the MIR text format is itself
  unstable, so this adds no new assumption), then `mir.go` runs a **straight-line value-forwarding**
  pass over the textual MIR. MIR — not LLVM IR — is the right substrate: it names the source-level
  public API (`std::env::var`, `Command::arg`, not the internal monomorphized `std::env::__var`) and
  assigns call results directly to locals (no `sret` out-pointer indirection), so no cgo/libLLVM and
  no memory modeling are needed. Method calls → `OP_CODE_CALL` with the receiver as operand 0 (rules
  pin the tainted arg with `#1`); tuple/array/struct construction → `builtin.aggregate` intrinsic and
  field reads fold to the stored element, so taint flows through `format!`. A `format!` call lowers to
  `fmt::Arguments::new(<packed byte-template>, args)`; `decodeFmtTemplate` turns that `const b"..."`
  template into a readable `{}`-placeholder string so the SSRF host check can read its constant pieces
  (rustc's `fmt::rt` encoding: `0xC0` = an argument, a byte `< 0x80` = the length of a literal run).
  Canonical names `rust:<normalized-path>` (generics stripped). Pure Go, in the default binary; only
  `rustc` is needed at scan time. A **`Cargo.toml`** target is built with `cargo rustc -- --emit=mir`
  (`convertCargo`) so its dependency crates (a web framework, etc.) resolve and the project's calls
  are named by their real crate paths; cargo passes the trailing args to only the final crate's rustc,
  so dependency MIR is not emitted. A build failure (e.g. an unfetchable dep offline) is a skipped
  frontend. Sources model the real attack surface — HTTP request accessors (`*Request::query|header|
  body`, actix `*HttpRequest::query_string|headers`) — with env/args as a secondary CLI/CGI source.
- `converters/ruby/` — analyzes Ruby via the stdlib **Ripper**. An embedded helper (`rbdump.rb`, run
  via `ruby`) parses `.rb` and prints Ripper's S-expression AST as JSON; `lower.go` lowers that tree
  (straight-line, like Python/JS). Ripper ships with every MRI Ruby, so only a `ruby` on `PATH` is
  needed — pure Go, in the default binary. Canonical names `ruby:<module>.<method>`; sources model an
  untrusted HTTP request (Rails/Sinatra `params`), and backtick/`%x` shell literals are a command sink.
- `converters/cpp/` + `converters/llvm/` — C/C++ via **LLVM IR** (clang `-O1 -g -emit-llvm`), lowered
  by the shared `converters/llvm` package. This is the opt-in **cgo** backend (`-tags "llvm byollvm"`
  + libLLVM), NOT in the default build; see the Makefile `*-llvm` targets. (Rust was formerly on this
  path too but moved to the pure-Go MIR frontend above.)
- Python, JS, and Ruby name modules by their **path relative to the scan root** (`moduleNameFor`), so
  same-named functions in different files get distinct canonical names instead of colliding in the analyzer.

**Analysis (`internal/analysis/`).**
- `taint.go` — the taint transfer helpers (SSA def-use, `visitStore`/`taintContainer` for aggregate/variadic
  aliasing, intrinsic + opcode propagators). `BIN_OP` is a universal propagator so `+` concatenation carries
  taint for Go/JS/Python; Rust models `+` as an `Add::add` **call**, so `interproc.go` treats a concat-add
  call (`isConcatAddCallee`) as a built-in propagator too — otherwise taint would drop at every Rust concat.
- `interproc.go` — `Engine.Analyze`: **inter-procedural**, context-insensitive worklist. Taint flows across
  calls via function summaries (tainted arg → callee param; taint-returning function → caller's call result).
  Findings get a `Confidence`: intra-procedural = High, cross-function = Medium.
  **Request-object method sugar** (framework-agnostic HTTP sources): a register seeded from the synthetic
  request source (`go:@net/http.Request`, see the Go frontend) carries **request-object provenance**
  (`reqTainted`); a method call on such a receiver — `c.Query()`, `c.Param()`, `c.Bind(&x)` — is then treated
  as untrusted (result tainted, pointer out-args filled), even for a framework with **no rules**. Gated on
  provenance so ordinary taint is untouched, and only for unresolved/external callees. Provenance is
  **inter-procedural** — a request object passed to a helper makes that helper's parameter a request object too
  (a `reqEffects`/`paramReqTaint` summary channel mirroring the taint one), so the `*http.Request` direct-method
  source globs (`FormValue`/`Cookie`/`PathValue`/`PostFormValue`) are redundant and removed; the kept Go request
  sources are the synthetic `go:@net/http.Request`, `net/http.Header.Get` (a field sub-object), `net/url.Values.Get`,
  and the free-function accessors (`chi.URLParam`, `mux.Vars`). Method sugar only fires for external callees, so a
  **lowered** framework (gin/echo/… whose bodies dep-lowering analyzes) carries taint through its own code instead —
  but that code bottoms out in stdlib request parsers that are NOT lowered (gin's `c.Query` → `c.Request.URL.Query()`
  then a `queryCache[key]` map read), dropping taint there. The framework-agnostic fix lives in the rules:
  the net/http+net/url request accessors (`net/url.URL.Query`, `net/url.Values.Get`, `net/http.Request.FormValue`/
  `Cookie`/…, `net/http.Header.Get`) are **default propagators** (`internal/rules/propagators.go`) — they only
  forward already-present request taint, so any unmodeled framework built on net/http is covered at no FP cost.
- `ssrf.go` — **CWE-918 false-positive reduction (`urlHostControllable`)**, language-agnostic. When an SSRF
  sink fires, it reconstructs how the tainted URL string was built (concatenation `BIN_OP_ADD` / Rust
  `Add::add`, Python `%`, a printf-style/format-string call, or **Rust `format!`** — whose packed
  `fmt::Arguments` byte-template the Rust frontend decodes into a `{}`-placeholder string, see `mir.go`
  `decodeFmtTemplate`) and **suppresses the finding when a constant `scheme://host/…` prefix (`hostFixedRe`)
  precedes the first tainted segment** — i.e. the taint is confined to the path/query of a fixed host and
  cannot redirect the request. Deliberately conservative: it suppresses only when the fixed host is *proven*;
  an opaque or unrecoverable construction (e.g. **Java `+`**, whose `makeConcatWithConstants` recipe is
  dropped from gIR) keeps firing, so no real SSRF is lost.
- `callgraph.go` — `BuildCallGraph` (CHA for dynamic dispatch); the engine consumes its reverse edges
  (`buildCallers`) to re-enqueue a callee's callers when the callee becomes taint-returning.
- `secrets.go` — `ScanSecrets`: non-dataflow, regex-based hardcoded-secret detection over gIR string constants
  (CWE-798).
- `finding.go` — the `Finding` type shared across the pipeline.

**Rules (`internal/rules/`).** `rule.go` — the `Rule` model (sources/sinks/sanitizers/propagators as
canonical-FQN globs, `*` matches across `/` and `.`) + `AppliesTo`/glob matcher. A **sink** entry may pin
its injection point with a `#<idx>` suffix (`"go:*database/sql*.Query#0"`): only taint reaching that
LOGICAL (receiver-excluded) argument fires — this prevents parameterized-query false positives
(`db.Query("... = ?", taintedParam)` binds a safe placeholder). A bare pattern means all args.
`loader/` — YAML loader (`LoadFile`/`LoadDir`/`Builtin`/`LoadDefault`). The built-in rule packs live in
the **top-level `rulepacks/`** directory, embedded into the binary by `rulepacks/embed.go`
(`//go:embed *.yaml`) and consumed by the loader's `Builtin()`:
- **Go / Python / JS** — SQLi, command injection, path traversal, SSRF, XSS, open redirect, plus Python
  insecure deserialization (CWE-502) and code injection (CWE-95: `eval`/`exec`/`compile`, exact-named
  so the safe `ast.literal_eval` is not flagged), and JS code injection (CWE-95), plus `vue-xss`/
  `svelte-xss` for Vue `v-html`/`:href` and Svelte `{@html}` template-injection XSS (CWE-79).
- **Java** — SQLi, command injection, path traversal (CWE-22: `java.io` file streams/readers,
  `java.nio.file.Files`; `Paths.get`/`Path.of`/`Path.resolve` propagate String→Path), XSS
  (CWE-79: servlet/`PrintWriter` response writes; `HtmlUtils`/OWASP-`Encode`/`StringEscapeUtils`
  sanitizers), SSRF (CWE-918: `java.net.URL`/`URI`, `RestTemplate`/`WebClient`/HttpClient/OkHttp),
  open redirect (CWE-601: `sendRedirect`/`RedirectView`), insecure deserialization (CWE-502:
  `ObjectInputStream`/`XMLDecoder`/SnakeYAML/XStream).
- **Rust** — command injection (`std::process::Command`), path traversal (`std::fs`), SQL injection
  (rusqlite/sqlx/diesel), SSRF (reqwest/ureq), XSS (CWE-79), open redirect (CWE-601).
- **Ruby** — SQL injection (CWE-89: ActiveRecord `execute`/`exec_query`/`find_by_sql`/raw `where`) and
  command injection (CWE-78: `system`/`exec`/`spawn`/`IO.popen`/`Open3`, plus backtick/`%x` literals;
  `Shellwords.escape` sanitizes).
- **C / C++** (`c*:` globs match both `c:` and `cpp:`) — command injection, path traversal, format string
  (CWE-134), SQL injection (CWE-89), buffer overflow (unsafe `gets`/`strcpy`-family, CWE-242/120).
- **Weak crypto / dangerous APIs** (`kind: dangerous-call`, non-dataflow call-site match — no taint) —
  Go and Java: weak hash (MD5/SHA-1) and broken cipher (DES/3DES/RC4) at CWE-327, plus insecure RNG
  (`math/rand` for secrets, CWE-338 — Go).

`validate` rejects rules with an empty ID or an unrecognized severity.

**Report & LLM (`internal/report/`, `internal/llm/`).** `report.WriteHTML` renders a self-contained,
auto-escaped HTML report with code snippets; `WriteJSON` and `WriteSARIF` (SARIF 2.1.0, severity→level) emit
machine-readable output for tooling / GitHub code scanning. `llm` is the pluggable reviewer: `review.go` is
dependency-free (interface, confidence-gated `Filter` with fail-open semantics, prompt builder, verdict
parser); `anthropic.go` is the Anthropic-SDK adapter (default `claude-haiku-4-5`, override via
`GODZILLA_LLM_MODEL`).

**CLI (`cmd/godzilla/main.go`).** `scan` dispatches to frontends by extension (or runs all on a directory and
merges modules), runs the engine + secrets scan, optionally LLM-reviews, prints findings, writes HTML, and
sets a severity-gated exit code.

## Conventions

- **Avoid touching gIR unless really necessary.** The gIR schema (`proto/*.proto` → `pkg/ir/v1/`) is a
  frozen cross-language contract: all frontends emit it and the single engine consumes it, so any schema
  change ripples across every frontend + the analyzer and risks regressions. Treat it as a **last
  resort**. Prefer, in order: (1) model the construct as an `OP_CODE_INTRINSIC` with a canonical name and
  teach the engine/rules about it; (2) add the source/sink/propagator/sanitizer as a YAML rule edit;
  (3) handle it in the frontend's lowering. Only change the proto when a genuinely new *structural*
  concept truly cannot be expressed by the existing opcodes + intrinsics — and say why in the change.
- **The proto schema is authoritative.** If a gIR change is unavoidable, start in `proto/*.proto`, then
  `go generate`. Never hand-edit `pkg/ir/v1/*.pb.go`.
- **Small core + intrinsics.** Do NOT add an opcode for a language-specific construct — model it as an
  `OP_CODE_INTRINSIC` with a canonical name and teach the engine/rules about that name.
- **Canonical names are the cross-language join.** Frontends must emit stable `<lang>:...` FQNs; rules match
  them with globs. Adding a sink/source is usually a YAML edit, not code.
- **Source mapping is mandatory** — every instruction/function/global populates `Pos`; it drives reporting.
- **Isolated sample modules.** Vulnerable test code lives under `test/{go,python,js,java,rust,ruby,c,cpp}/`;
  Go samples are isolated modules — never pollute the root `go.mod` with sample dependencies.
- **Instruction coverage is tested by absence of fallback comments** — an unhandled SSA/AST node yields a
  `comment`/intrinsic like `unsupported instruction`; converter tests fail if one appears.
- **Confidence drives triage.** Intra-procedural findings are High; cross-function are Medium. The LLM
  reviewer only adjudicates at/below Medium and fails open (never drops a finding on an API error).
