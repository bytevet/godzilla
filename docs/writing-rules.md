# Writing rules

Godzilla detections are **YAML rules** matched against **canonical fully-qualified
names** — stable `<lang>:module/path.Type.member` symbols every frontend emits, so
one rule can span languages. Built-in packs live in [`rulepacks/`](../rulepacks)
(one pack per CWE per language, embedded in the binary); `--rules <file-or-dir>`
merges yours on top.

```bash
godzilla scan --rules myrules.yaml ./project   # built-ins + yours
```

## Canonical names and globs

A pattern is a glob over canonical names; `*` matches across `/` and `.`:

```
go:net/http.(*Request).FormValue     # exact
go:*net/http*.Request*.FormValue     # glob
py:flask.request.args.get
js:express.Request.query
```

`godzilla scan --summary <path>` prints the exact names a frontend emits for your
code.

## Rule kinds

Two kinds. (Hardcoded **secrets** are a separate regex scanner, not a YAML rule.)

### Taint rules (default)

Untrusted data from a **source** reaching a **sink** is a finding — unless a
**sanitizer** cleans it, a **validator** guards the path, or no **propagator**
carries it across an intermediate call.

```yaml
rules:
  - id: my-sql-injection
    languages: [go]
    severity: high            # info | low | medium | high | critical
    cwe: CWE-89
    message: Untrusted input reaches a SQL query.
    sources:
      - "go:*net/http*.Request*.FormValue"
    sinks:
      - "go:*database/sql*.Query#0"   # #0: only the query string; bound params are safe
    sanitizers: []
    propagators:
      - "go:fmt.Sprintf"              # taint flows arg -> result
```

- **Sink pinning** `#<index>` fires only when taint reaches that logical
  (receiver-excluded) argument; a bare pattern treats every argument as an
  injection point. This keeps parameterized queries clean.
- **Sanitizers** return a cleaned value (taint stops); **validators** are boolean
  guards (e.g. `filepath.IsLocal`) that clear taint on the path they dominate;
  **propagators** pass taint arg → result (`+` and `fmt.Sprintf` propagate by
  default).

### Dangerous-call rules

A call-site check with no taint: **any call** to a banned API is a finding — for
zero-noise categories like weak crypto. Set `kind: dangerous-call`, list
`callees`, optionally gate on `const_arg`.

```yaml
rules:
  - id: java-weak-hash
    kind: dangerous-call
    languages: [java]
    severity: medium
    cwe: CWE-327
    message: Cryptographically weak hash.
    callees:
      - "java:*MessageDigest.getInstance"
    const_arg:                 # optional: only when the constant arg matches
      index: 0
      matches: "(?i)^(MD2|MD4|MD5|SHA-?0|SHA-?1)$"
```

Without `const_arg` every call fires; with it, only calls whose constant string
argument at `index` matches — `getInstance("MD5")`, not `("SHA-256")`.

## Dynamic guards (`when`)

A sink or callee entry can be a `{sink|callee, when}` mapping instead of a bare
string: `when` is an [expr-lang](https://expr-lang.org) expression that must be
true for the entry to fire. Use it when danger depends on an argument's *value* —
a sink only dangerous in a certain format, or a cipher only weak in a certain mode.

```yaml
sinks:
  - "go:*database/sql*.Query#0"           # static
  - sink: "go:*exec.Command#0"            # dynamic
    when: "arg[0].String startsWith 'cmd:'"
callees:                                  # dangerous-call
  - callee: "java:*Cipher.getInstance"
    when: "arg[0].String contains '/ECB/'"
```

`arg[i]` is the i-th logical (receiver-excluded) argument, with fields:

- `.String` — the argument's statically reconstructed value: constant runs
  verbatim, `<DYN>` for a dynamic run. `"cmd:" + x` → `"cmd:<DYN>"`, a fully
  dynamic argument → `"<DYN>"`. Incompleteness is encoded here, so
  `arg[0].String == 'cmd:'` is false for a partial constant while
  `arg[0].String startsWith 'cmd:'` is true.
- `.Complete` — the whole argument is a compile-time constant.
- `.Type` — `"string"`/`"int"`/`"float"`/`"bool"`, or `""` if unknown.

Write the condition with expr's native operators/builtins — `startsWith`,
`endsWith`, `contains`, `matches` (regexp), `in`, `==`, `hasPrefix` — combined
with `&&`, `||`, `!`:

```
arg[0].String startsWith 'cmd:'
arg[0].String contains '/ECB/'
arg[0].Complete && arg[0].String == 'MD5'
arg[0].String in ['DES', 'RC4', 'Blowfish']
```

A non-recoverable argument is `"<DYN>"`, so a prefix/exact check fails and the
entry is **suppressed** (confirm, don't guess). Because a wildcard `matches` can
span `<DYN>`, combine `matches`/`==` with `.Complete` when an exact match matters.
Guards compile once at load; a syntax, type, or regexp error fails `rules lint`,
and a guard that fails to compile suppresses its entry rather than firing.

A guard is evaluated in the frame where the sink appears. So if a dependency
*wrapper* forwards to a guarded sink (`func Run(c string) { exec.Command(c) }`),
the argument there is always `"<DYN>"` — the guard can't confirm, and the sink is
not reported through the wrapper. Guard sinks that user code calls directly.

## Fragments (`extend`)

Packs for a language often share pattern lists — the same request **sources**,
but also common **sinks** (e.g. the filesystem sinks shared by path-traversal and
zip-slip), **sanitizers** (the HTML sanitizers shared by the Vue and Svelte XSS
packs), or **propagators**. Rather than copy-paste them into every rule — where
they drift apart — put them in a **fragment** and `extend` it.

A fragment is a `_`-prefixed file holding a *partial rule* (any pattern-list
fields); it is never loaded as a rule itself. A rule pulls it in with `extend`,
and the loader merges each list field — fragment entries first, then the rule's
own, deduped — before matching.

```yaml
# rulepacks/_go-common.yaml   (fragment)
sources: ["go:@net/http.Request", "go:*gin-gonic/gin.Context*.Query", ...]
request_object_sources: ["go:@net/http.Request"]
propagators: ["go:strings.Join"]
```
```yaml
# a rule
- id: go-sql-injection
  extend: $_go-common.yaml            # one ref, or a list: [$_a.yaml, $_b.yaml]
  sinks: ["go:*database/sql*.Query#0"]
```

Builtin fragments are available to your `--rules` files too; a same-named fragment
in your rules dir overrides one. Extending an unknown fragment is a load error.

## Field reference

| Field | Kind | Meaning |
|---|---|---|
| `id` | both | Unique id; validation rejects an empty or duplicate id. |
| `extend` | both | One or more `$_fragment.yaml` refs merged into this rule. |
| `languages` | both | Language tags (`[go]`, `[c, cpp]`, …). |
| `severity` | both | `info`/`low`/`medium`/`high`/`critical` (drives the exit-code gate). |
| `cwe`, `message` | both | Reported metadata. |
| `sources`/`sinks`/`sanitizers`/`propagators`/`validators` | taint | Canonical-name globs; a sink may pin an arg with `#<index>`. |
| `request_object_sources` | taint | Sources whose value is an HTTP request *object* (e.g. `go:@net/http.Request`; also list in `sources`). Tags the flavor so the engine grants request-object provenance without a hardcoded name. |
| `callees` | dangerous-call | Globs whose call site is itself the finding. |
| `const_arg` | dangerous-call | Optional `{index, matches}` constant-argument condition. |

## Testing a rule

Add a vulnerable sample under `test/<lang>/<case>/` with an `expected.yaml`, plus
a `*_safe` control where precision matters. `go test ./test/corpus/` asserts both.
See [test/README.md](../test/README.md).
