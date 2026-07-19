# Writing rules

Godzilla's detections are **YAML rules** matched against **canonical
fully-qualified names** — stable `<lang>:module/path.Type.member` symbols that
every frontend emits, so one rule shape can cover multiple languages. The
built-in packs live in the top-level [`rulepacks/`](../rulepacks) directory and
are embedded into the binary; `--rules <file-or-dir>` merges your own rules on
top of them.

```bash
godzilla scan --rules myrules.yaml ./project      # built-ins + yours
```

## Canonical names and globs

A pattern is a glob over canonical names. `*` matches across `/` and `.`, so one
entry can span a package tree:

```
go:net/http.(*Request).FormValue     # exact
go:*net/http*.Request*.FormValue     # glob
py:flask.request.args.get
js:express.Request.query
```

Run `godzilla scan --summary <path>` to print the gIR summary and see the exact
canonical names a frontend produces for your target code.

## Rule kinds

Two rule kinds. (Hardcoded-**secrets** detection is a separate regex scanner over
string constants — *not* a YAML rule.)

### Taint rules (default)

A source→sink dataflow rule. Untrusted data from a **source** that reaches a
**sink** is a finding, unless a **sanitizer** cleans it, a **validator** guards
the path, or no **propagator** carries it across an intermediate call.

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
      - "go:*database/sql*.Query#0"        # only the query string; bound params are safe
      - "go:*database/sql*.QueryContext#1" # ctx is arg 0, query is arg 1
    sanitizers: []
    propagators:
      - "go:fmt.Sprintf"                   # taint flows through the format string
      - "go:strings.Join"
```

- **Sink argument pinning** — a sink may append `#<index>` to fire only when
  taint reaches that **logical** (receiver-excluded) argument. This keeps
  parameterized queries clean: for `...Query#0`, `db.Query("... = ?", userInput)`
  binds `userInput` at a later position, so it does not fire. A bare pattern (no
  `#`) treats every argument as an injection point.
- **Sanitizers** transform a value and return a cleaned result (e.g. an escaper);
  taint stops at their output.
- **Validators** are boolean guards (e.g. `go:path/filepath.IsLocal`) that clear
  taint on a path when they dominate the branch reaching a sink — the value is
  unchanged but the finding is neutralized by control flow.
- **Propagators** are calls that pass taint from an argument to their result.
  Common concatenation/formatting (`BIN_OP` `+`, `fmt.Sprintf`) propagates by
  default; list a propagator when a domain helper should too.

### Dangerous-call rules

A non-dataflow, call-site check: **any call** to a banned/weak API is a finding,
with no taint required. Use it for zero-noise categories like weak crypto. Set
`kind: dangerous-call` and list `callees`; optionally gate on a constant argument
with `const_arg`.

```yaml
rules:
  - id: java-weak-hash
    kind: dangerous-call
    languages: [java]
    severity: medium
    cwe: CWE-327
    message: Use of a cryptographically weak hash (MD2/MD4/MD5/SHA-1).
    callees:
      - "java:*MessageDigest.getInstance"
    const_arg:                 # optional: restrict to a matching constant argument
      index: 0                 # logical (receiver-excluded) argument index
      matches: "(?i)^(MD2|MD4|MD5|SHA-?0|SHA-?1)$"
```

Without `const_arg`, every call to a `callees` glob fires (e.g. Go
`crypto/md5.New`). With it, only calls whose constant string argument at `index`
matches the regexp fire — e.g. `MessageDigest.getInstance("MD5")`, not
`getInstance("SHA-256")`.

## Field reference

| Field | Kind | Meaning |
|---|---|---|
| `id` | both | Unique rule id (required; validation rejects an empty id). |
| `languages` | both | Language tags this rule applies to (`[go]`, `[c, cpp]`, …). |
| `severity` | both | `info`/`low`/`medium`/`high`/`critical` (drives the exit-code gate). |
| `cwe`, `message` | both | Reported metadata. |
| `sources`/`sinks`/`sanitizers`/`propagators`/`validators` | taint | Canonical-name globs; a sink may pin an arg with `#<index>`. |
| `request_object_sources` | taint | Source globs whose value is an untrusted HTTP request *object* (e.g. `go:@net/http.Request`). Also list them in `sources`; this tags the flavor so the engine grants request-object provenance (framework-agnostic accessor sugar) without a hardcoded source name. |
| `callees` | dangerous-call | Globs whose call site is itself the finding. |
| `const_arg` | dangerous-call | Optional `{index, matches}` constant-argument condition. |

## Testing a rule

Add a vulnerable sample under `test/<lang>/<case>/` with an `expected.yaml`
declaring what must fire, and — where precision matters — a `*_safe` control that
must stay clean. `go test ./test/corpus/` asserts both. See
[test/README.md](../test/README.md) for the sample layout and manifest format.
