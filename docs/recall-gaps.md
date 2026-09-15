# Recall gaps found by auditing a real application

A manual security review of one real Go service (a ~200-handler ticketing API,
gin + gorm) found **7 critical and 7 high** issues. Godzilla, scanning the same
tree, reported **4 findings, none of them these**. This document is the difference:
what was missed, why, and what each miss would cost to close.

It is a companion to [recall-modeling-plan.md](recall-modeling-plan.md), which
tracks recall against public CVEs. That campaign measures breadth of *modeling*
against known-vulnerable library versions. This one measures something the CVE
corpus structurally cannot: a bespoke application where the vulnerability is in
the application's own authorization logic, not in a dependency.

The two sources disagree in a useful way. The CVE track keeps concluding "the
rules-first lever is largely exhausted." This audit found the opposite — **the
single largest tier here is pure YAML** — because CVE fixes cluster on
library-mediated injection, and hand-written business logic does not.

---

## The scoreboard

| Tier | Findings covered | Cost |
|---|---|---|
| 1 — Rules only | 3 of 14 | One YAML pack, no engine change |
| 2 — Rule model + frontend | 4 of 14 | Needs maintainer sign-off (public API) |
| 3 — Out of reach today | 7 of 14 | New detector shapes; not dataflow |

Nothing in tier 1 or 2 requires a gIR change.

---

## Tier 1 — reachable with YAML alone

### 1a. `text/template` / handlebars with attacker-controlled template text (SSTI)

Two findings (one critical, one high) are the same shape:

```go
t, _ := template.New("content").Parse(content)   // content from config/request
t.Execute(&b, map[string]interface{}{"Ticket": ticket})
```

Go's `text/template` invokes **exported methods on the bound data**. The bound
`*Ticket` had 33, two of which reached a raw cross-tenant `UPDATE`. So this is not
"template injection might leak a field" — it is arbitrary method invocation on
whatever you bind.

There is no `go-ssti` pack today. This is a plain dataflow rule: source is the
existing HTTP/config set, sink is `text/template.Template.Parse#0`,
`html/template.Template.Parse#0`, `Must`, and the handlebars equivalents
(`raymond.MustParse#0`, `raymond.Parse#0`). Sink pinning already expresses the
argument. `template.New("x").Parse(y)` is a method call on a receiver, which is
exactly what `#0` receiver-excluded pinning is for.

**Precision note.** The overwhelmingly common safe pattern is a *constant*
template string, and constants are not tainted, so the rule is naturally quiet.
The risk is a template read from a config file — which is a true positive under
this engine's own threat model, since `configs.GetString` is reachable from
request data in this application.

### 1b. goja / JS-engine eval sinks

Five call sites do `vm.RunString(script)` / `jsengine.Eval(...)` where `script`
descends from a client-supplied parameter. `goja` is not modeled at all. Adding
`github.com/dop251/goja.Runtime.RunString#0`, `.RunProgram#0`, `goja.Compile#1`
and the project's `jsengine.Eval#0` wrapper to a `go-code-injection` pack covers
it with no engine work.

The generalization worth making: **`go-command-injection` models `os/exec` but
nothing else that executes.** An embedded interpreter is the same sink class.
Same for the Python-subprocess-manager shape in 1c.

### 1c. Non-`exec` process execution

The application runs Python through its own sandbox manager
(`codesandbox.Manager.RunCode(ctx, "python3", src)`), not `os/exec` directly. The
engine saw `exec.CommandContext` deeper in, which is why it did produce a
command-injection finding here — but only the one, and the interesting sink (the
*script source* argument, not the interpreter name) is a project-local wrapper.

This is a user-rules problem, not a built-in-pack problem, and it is worth
documenting as such in `writing-rules.md`: **a project with its own execution
wrapper must model the wrapper.** The built-in packs can only know the standard
library and popular dependencies.

---

## Tier 2 — rule-model changes, maintainer sign-off required

Per `CLAUDE.md`, the `Rule` model and the `when:` DSL are public API and every
change needs explicit approval. These are proposals, not work items.

### 2a. Binder out-parameter sources

This is the biggest single cause of misses, and it is architectural.

Go web frameworks deliver request data by **filling a caller-allocated struct**:

```go
var params defs.ActionReq
c.ShouldBind(&params)      // every field of params is now attacker-controlled
```

`sources:` matches a call's **return value**. `ShouldBind` returns only `error`.
The taint is in the argument. The engine models `*http.Request` parameters
directly (`addHTTPRequestSource`) but has no concept of "this call taints the
object its argument points at."

Everything downstream of a bound struct is therefore invisible, which in a gin or
echo application is most of the request surface. Four of the seven criticals
enter through a bound struct field.

**The mechanism already half-exists.** `paramMemTaint` — the through-parameter
memory summary — is precisely "a call taints memory reachable from argument N."
What is missing is a way for a *rule* to assert it for a modeled (unlowered)
stdlib/framework function. Concretely: a source glob that pins an argument
index the way sinks already do —

```yaml
sources:
  - "go:*github.com/gin-gonic/gin*.Context.ShouldBind#0"   # taints *through* arg 0
```

— reusing the existing `#<idx>` parser rather than adding new syntax. That is a
semantic overload of `#idx` (on a sink it selects; on a source it would inject),
which is exactly the kind of thing to decide deliberately rather than sneak in.
The alternative, a separate `outSources:` key, is more honest and more churn.

Affected APIs are numerous and stable: gin `ShouldBind*`/`Bind*`/`ShouldBindUri`,
`encoding/json.Unmarshal#1`, `gopkg.in/yaml.Unmarshal#1`, `xml.Unmarshal#1`,
`echo.Context.Bind#0`, `mapstructure.Decode#1`.

`encoding/json.Unmarshal` deserves separate emphasis: it is the single most
common untrusted-data entry point in Go, it is stdlib, and today it is a taint
dead end in every Go scan this engine performs.

### 2b. Environment and process-level sources

A script receiving `SWP_INTERNAL_API_KEY` in its environment is a real finding
(privilege escalation to the system account), but `os.Getenv` is not a source and
probably should not be unconditionally. A `kind:`-scoped rule that treats
`os.Environ()` propagation into a child process's `Env` as a *disclosure* sink —
rather than treating the environment as a source — is the shape that fits. That
is a new finding class (CWE-214, information exposure through process
environment), not a new source.

---

## Tier 3 — structurally out of reach

Seven findings are missing authorization checks. **No taint engine finds these,
because there is no taint.** The data flows exactly where the developer intended;
the bug is that nothing stopped the caller.

Listing them as "recall gaps" is only meaningful if there is a detector shape
that would catch them. Two exist, and both are worth taking seriously because
neither is dataflow and neither needs gIR to change.

### 3a. Peer inconsistency ("your siblings all check, and you don't")

The strongest signal in the entire audit. Three separate findings had this exact
shape:

- `admin/ticket.go` — seven handlers call `checkTicketAdminPermission`; the eighth
  (`SyncTickets`) does not. It reads any ticket by ID.
- `bo/template/write.go` — `UpdateEmailNotificationConfig` checks,
  `DisableEmailNotification` checks, `GetEmailNotificationRenderedTemplate`
  between them does not. It renders an attacker-supplied template.
- `bo/automation_plugin/write.go` gates the `is_delegate` backdoor field on
  `IsAdminBot`; `bo/ticket/advance_write.go` reads the same field with no gate.

The detector: **group functions by peer set** (same file, or same route group, or
same receiver type), find the check-like call that the majority make — a call
whose name matches a configurable pattern and whose failure leads to an early
return — and report the minority that skip it. Report confidence scales with the
majority ratio: 7-of-8 is a near-certain finding; 3-of-5 is noise.

This is a **structural/statistical** detector, and it fits the existing
architecture better than it first appears:

- The call graph is already built (`callgraph.go`).
- "Leads to an early return" is a dominator query on the CFG, and the engine
  already does dominator reasoning for guard-based sanitization (`guards.go`).
- It is language-neutral: the same shape catches a missing `@login_required`, a
  missing `before_action`, a missing Spring `@PreAuthorize`.
- It needs **no source and no sink**, so it does not inherit any of the modeling
  breadth problems in `recall-modeling-plan.md`.

The obvious objection is that the "check" is project-specific. That is fine — it
is *discovered*, not configured. The detector does not need to know what
`checkTicketAdminPermission` means; it only needs to observe that 7 of 8 peers
call it.

> **This paragraph is wrong, and the measurement is in the postscript.** Pure
> structural discovery yields 205 candidates on this codebase. A name glob is
> needed to decide whether a callee is a check at all; only *which* check and
> *who skips it* are discovered.

This would have caught 3 of the 14 findings, including one critical. That is a
better hit rate than any single rule pack has on this codebase.

### 3b. Report at the convergent sink, not at the entry point

The sandbox executes arbitrary Python by design. The vulnerability is that four
routes reach the configuration for it without an authorization check. The engine
has no way to say "this sink is dangerous *unless* every path to it passes a
guard."

The generalized shape: for a designated `kind: privileged-sink`, enumerate entry
points (already available: the HTTP source seeding knows which functions are
handlers) that reach it in the call graph, and report the ones whose path
contains no check-like call. This is 3a's machinery pointed at reachability
instead of peer sets.

### 3c. What is genuinely not reachable

Recorded so the list is honest:

- **Group-inherits-no-middleware.** Three route groups were created before
  `api.Use(...)` and so carry no authentication — a gin semantics bug
  (`Group()` snapshots the parent chain; `Use()` only appends to the parent).
  Catching it means modeling one framework's registration order. Narrow, real,
  and probably worth a dedicated gin check rather than a general mechanism.
- **Mutate-then-check.** A permission check was defeated by a helper that appended
  the caller to the object's reviewer list *before* the check read that list. Only
  a human reading both functions together finds this.
- **Missing revocation / capability URLs.** Unguessable S3 keys handed out in
  email and never revoked. Not a code property.
- **Config-flag-gated TLS verification.** `InsecureSkipVerify: true` under a
  config condition, currently unreachable. A constant-propagation question about
  deployment config, not about code.

---

## An unrelated bug this audit exposed

**`-strict` reports clean on a failed package load.** `converters/go/converter.go:445`:

```go
if packages.PrintErrors(initial) > 0 {
    fmt.Fprintln(os.Stderr, "warning: some Go packages failed to load cleanly; ...")
}
```

A warning to stderr, and nothing else. `LangCoverage` still says `go=ok`, the scan
reports 0 findings, and `-strict` exits 0. On this machine an expired Xcode
license broke cgo type-checking, and a scan of a known-vulnerable tree came back
clean and green. In CI that is the worst possible failure: a gate that passes
because it saw nothing.

The converter already has the channel to report it — `degradedNote`, used for the
dependency budget and consumed at `internal/scan/scan.go:656` via `c.Degraded()`.
A load failure should use it, so the scan says `go=DEGRADED` and names the cause
instead of `go=ok`.

**Correction to an earlier draft of this document**, which claimed that would make
`-strict` fire. It would not. `Result.Failed()` (`internal/scan/scan.go:222-230`)
tests **only** `Detected && !Converted`; neither `Degraded` nor `Skipped` is
consulted, and `cmd/godzilla/main_test.go:197` (`TestStrict_DegradedIsNotAFailure`)
pins that deliberately — the dependency budget rescues large scans from OOM, and
failing those would defeat it. So reporting and gating are two separate changes,
and only the first is being made.

The gate half is therefore still open, and it is wider than the Go converter:
`converters/java/converter.go:52-61` counts the `.java` files a whole-directory
compile dropped, and a Java scan that lowered 1 of 50 files still exits 0 under
`-strict` for exactly the same reason. Closing it needs a coverage state distinct
from budget-degradation, so the budget's exemption survives.

### On `CGO_ENABLED=0`

Setting it would have made this particular scan work, and it is tempting as a
default. **It should not be hard-coded.** It changes which files are analyzed —
build constraints exclude cgo-guarded files — so forcing it silently drops recall
on any project with real cgo. That trades a loud bug (a scan that fails) for a
quiet one (a scan that passes having skipped code), which is the wrong direction
for a security gate.

The defensible version is a *fallback*: attempt the normal load; on failure, retry
with `CGO_ENABLED=0`, mark the result **degraded**, and name the files that were
excluded. The user then sees both that the scan completed and what it did not
cover.

(For the audited application specifically it makes no difference: it has zero
files with `import "C"` of its own — only a `gopsutil` dependency does, and that
ships non-cgo counterparts.)

---

## What to take from this

1. **Ship a `go-ssti` pack and extend the code-execution sinks.** Pure YAML, three
   findings, no approval needed.
2. **Decide on binder out-parameter sources.** `encoding/json.Unmarshal` being a
   taint dead end is the highest-leverage single gap in Go coverage, and the
   engine's `paramMemTaint` already does the hard half.
3. **Report the failed package load.** Small, and until it is done a `-strict` run
   can report clean having analysed nothing. Note the correction above: this makes
   the scan *say* it is degraded; making the gate *fail* is a separate change.
4. **The peer-inconsistency detector is measured and deferred**, not rejected —
   see below.

## Postscript — the peer detector, measured

Written up before the idea was measured; the numbers changed it, so they are
recorded here rather than left to be re-derived.

Peer set = exported functions in one file sharing the same first parameter type.
That grouping is expressible today (Go populates `Function.Signature`); grouping
by route *group* is not, because `c.routeHandlers` is converter-internal and never
lowered into gIR. On the audited service:

| Detector form | Candidates | Real findings among them |
|---|---|---|
| Structural majority only, no name glob (≥5 peers, ≥80%) | **205** | — unusable |
| Majority + check-name glob, ≥80% | **5** | **3** — H7 `SyncTickets`, C3's `SaveTemplate` + `Import` |
| Majority + check-name glob, ≥70% | 8 | 3 |
| Majority + check-name glob, ≥60% | 11 | 3 |

Godzilla's own tree yields **0** at every threshold.

This **refutes the "discovered, not configured" claim** made in §3a above. Go's
`if err != nil { return }` idiom makes "a call whose failure returns early"
ubiquitous, so structure alone cannot pick the check out of 205 candidates. The
workable split is narrower than claimed: a name glob decides *whether* a callee is
a check, and the majority decides *which* one and who skips it. That is still
per-project-configuration-free — the glob is `*[Pp]ermission*`-shaped, not
`checkTicketAdminPermission` — but it is not discovery.

Signature grouping is what makes it precise: file-wide grouping flags
`parseFunctionName`/`parseFunctionParameter` as noise, while signature grouping
leaves `admin/ticket.go` a clean 7/8 with `SyncTickets` the only miss.

Shape, if built: a fourth pass `ScanPeerConsistency(prog, rs) []Finding` in
`internal/analysis`, a goroutine in `runAnalyses` (`internal/scan/scan.go:318`,
`wg.Add(5)`) and both `slices.Concat` sites. `kind:` is a free-form string with no
allowlist, so a new value needs only an `Is…()` predicate; a sink-less rule is
already excluded from the taint worklist by `canProduceFinding`
(`internal/analysis/interproc.go:129-132`). It must set
`Package: fn.GetPackageName()`, or every lowered dependency's peer sets leak past
`scopeFindings` — and a dependency closure is where "most peers call the check"
patterns are densest.
