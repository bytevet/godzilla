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

Three kinds, selected by `kind:` — a source→sink dataflow rule (the default), a
call-site check, and a pattern-over-constants check.

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

`severity` and `confidence` are independent dials here, and a heuristic
call-site rule usually wants them set apart: severity alone gates CI (`-fail-on`,
default `medium`), while confidence alone decides triage — the LLM reviewer only
adjudicates findings at or below `medium`, so the High default excludes a rule
from review. A rule that should be *reported and reviewable* without turning
builds red — `py-dynamic-code-exec` is the shipped example — sets
`severity: low` with `confidence: medium`.

### Secret rules

Not a call at all: `matches` is a regexp run over every string **constant** in
the lowered IR *and* over the lines of textual config files the frontends never
parse (`.env`, compose, Dockerfile, CI YAML), so one rule catches a credential
wherever it was written. See `rulepacks/secrets.yaml`.

```yaml
rules:
  - id: secret-acme-token
    kind: secret
    severity: high
    cwe: CWE-798
    message: Hardcoded ACME API token
    matches: '\bacme_[0-9A-Za-z]{32}\b'
```

Keep the regexp **specific** — a fixed vendor prefix or a structural marker.
Entropy-style detectors find more real secrets but produce the kind of noise that
gets a CI gate switched off. Omit `languages:` unless you mean to scope the rule
to one language's IR constants; config files have no language and are skipped by
a rule that declares any.

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
- `.Type` — `"string"`/`"int"`/`"float"`/`"bool"`, the container kinds
  `"aggregate"`/`"map"`, or `""` if unknown.
- `.Name` — the keyword the argument was passed under (`"shell"` for
  `subprocess.run(cmd, shell=True)`), or `""` for a positional argument or a
  frontend that does not record names (currently Python only). Without it a guard
  can only see that *some* boolean argument is true, which cannot tell the
  dangerous `shell=True` from an innocuous `check=True`.
- `.Tainted` — untrusted data reaches the sink through *this* argument. Lets a
  rule ask **where** the taint arrived rather than only that it did: an element
  of an argv list is not the command string. Always false for a
  `dangerous-call` rule, which has no flow behind it.
- `.Elems` — for a container built in place (`.Type == "aggregate"`), its
  elements in order, so `arg[0].Elems[0]` is `argv[0]`. Empty when the container
  was not reconstructed (see below).
- `.Entries` — the same for a keyed container (`.Type == "map"`), indexed by its
  constant keys: `arg[0].Entries.mode`. An entry whose key is computed is absent,
  since a rule cannot name it. Only the Python frontend currently produces
  addressable container structure.
- `.TaintInChildren` — reading `.Elems`/`.Entries` will actually find the taint.
  A value can be `.Tainted` with this **false**: the container was mutated after
  it was built (`d = {}` then `d[k] = tainted`), the taint sits in a non-constant
  key, it came from elsewhere (`tainted.split(",")`), or the structure was never
  reconstructed. Ask for it whenever a guard reasons element-by-element — walking
  the children in those cases finds nothing and would wrongly read as safe.

A keyword can appear at any position, so address it through `kwargs`, which
indexes the same arguments by the keyword they were passed under — this is how
the security-config rules are written:

```yaml
    when: 'kwargs.verify.String == "false"'
```

A keyword the call does not pass yields the zero argument, so the guard simply
reads false; it is never an error.

**Container structure is best-effort, so demand positive evidence.** The engine
bounds how much of a container it rebuilds, and a container that does not fit
contributes *no* structure rather than partial structure. Write the guard so an
absent or unreachable structure keeps the finding — ask for `.TaintInChildren`
and `.Complete` before concluding anything is safe:

```yaml
    when: 'not (arg[0].TaintInChildren and arg[0].Elems[0].Complete
                and arg[0].Elems[0].String == "ls")'
```

The shipped rules are `rulepacks/py-command-injection.yaml` and the guard it
shares with the JS and Rust packs, `rulepacks/_shell-argv.yaml`.


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
entry is **suppressed** (confirm, don't guess). A guard that *raises* is
suppressed too — an out-of-range `arg[i]` or `.Elems[i]` is an eval error, which
reads as "not confirmed" and silently hides the finding. Prove an index exists
before using it (`len(.Elems) > 0` before `.Elems[0]`) rather than relying on the
error. Because a wildcard `matches` can
span `<DYN>`, combine `matches`/`==` with `.Complete` when an exact match matters.
Guards compile once at load; a syntax, type, or regexp error fails `rules lint`,
and a guard that fails to compile suppresses its entry rather than firing.

A guard is evaluated in the frame where the sink appears. So if a dependency
*wrapper* forwards to a guarded sink (`func Run(c string) { exec.Command(c) }`),
the argument there is always `"<DYN>"` — the guard can't confirm, and the sink is
not reported through the wrapper. Guard sinks that user code calls directly.

### A rule-level default `when`

When a guard expresses what the *whole rule* means rather than something about
one sink, put it at the rule level: every sink (and dangerous-call callee) that
declares no `when` of its own inherits it — including sinks merged in from a
fragment, so a sink added later cannot silently opt out. The shipped SSRF and
open-redirect packs use this for `not hostFixed()`, which is a statement about
the rule, not about any particular HTTP client:

```yaml
- id: js-ssrf
  when: 'not hostFixed()'      # default for every sink below
  sinks:
    - "js:*http.get"
    - "js:*axios*"
    - sink: "js:*fetch"
      when: 'true'             # this one opts out
```

An entry's own `when` always wins, so `when: 'true'` is the per-sink opt-out.
`hostFixed()` is an engine-supplied FACT about how the tainted URL string was
built (a constant `scheme://host` prefix ahead of the taint means the attacker
controls only the path/query) — the rule decides what to do with it, the engine
does not decide for the rule.

It takes an optional argument. Prefer the **zero-arg** `hostFixed()`: it reuses
the sink's own `#idx` pinning, so it cannot drift out of sync with it. The URL is
not always argument 0 (`py:*requests.request#1` pins `#1`) and some sinks take a
request *object* rather than a URL string (`net/http` `Client.Do`), so restating
the index — `hostFixed(arg[0])` — risks checking the HTTP method instead of the
URL. The explicit form exists for rules that want the check spelled out or need a
non-injection argument; `hostFixed(a, b)` requires all of them to be host-fixed.

In a `dangerous-call` guard there is no taint state, so `hostFixed()` reports
not-host-fixed and the entry fires. `not hostFixed()` is therefore a no-op there —
fail open, never silently suppress.

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

A fragment merges its pattern lists into the rule, and may also carry a `when:`
guard — the one scalar it contributes — so packs sharing a predicate keep it in
one file (`$_shell-argv.yaml` holds the argv-vs-shell test used by the JS and
Rust command-injection packs). A rule declaring its own `when:` keeps it.

Builtin fragments are available to your `--rules` files too; a same-named fragment
in your rules dir overrides one. Extending an unknown fragment is a load error.

## Field reference

| Field | Kind | Meaning |
|---|---|---|
| `id` | all | Unique id; validation rejects an empty or duplicate id. |
| `extend` | all | One or more `$_fragment.yaml` refs merged into this rule: its pattern lists, plus its `when:` if the rule declares none. |
| `languages` | all | Language tags (`[go]`, `[c, cpp]`, …). |
| `severity` | all | `info`/`low`/`medium`/`high`/`critical` (drives the exit-code gate). |
| `confidence` | dangerous-call, secret | `low`/`medium`/`high`; omit for the default `high`. `medium` makes the finding LLM-reviewable. Ignored by taint rules, whose confidence comes from the flow (intra-procedural high, cross-function medium). |
| `cwe`, `message` | all | Reported metadata. |
| `sources`/`sinks`/`sanitizers`/`propagators`/`validators` | taint | Canonical-name globs; a sink may pin an arg with `#<index>`. |
| `when` | both | Rule-level default dynamic guard, inherited by every sink/callee that declares none of its own (fragment-merged entries included). An entry's own `when` wins; `when: 'true'` opts out. |
| `request_object_sources` | taint | Sources whose value is an HTTP request *object* (e.g. `go:@net/http.Request`; also list in `sources`). Tags the flavor so the engine grants request-object provenance without a hardcoded name. |
| `callees` | dangerous-call | Globs whose call site is itself the finding. |
| `const_arg` | dangerous-call | Optional `{index, matches}` constant-argument condition. |
| `matches` | secret | The detector regexp, run over IR string constants and config-file lines. |

## Testing a rule

Add a vulnerable sample under `test/<lang>/<case>/` with an `expected.yaml`, plus
a `*_safe` control where precision matters.

```bash
godzilla rules lint rulepacks/*.yaml   # schema, globs, guards, #idx specs
godzilla rules test test/python/       # run samples against their expected.yaml
```

Both work against the built binary, so authoring a rule needs neither a repo
clone nor `go test`. In CI the same samples are asserted by
`go test ./test/corpus/`. See [test/README.md](../test/README.md).
