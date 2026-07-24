# SSA/CFG lowering for the Python / JS / Ruby frontends

## Goal

Replace the **straight-line, single-block, env-map** lowering in the Python,
JavaScript, and Ruby frontends with real **CFG + SSA** emission, matching what the
Go frontend already produces. The gIR schema and the taint engine already support
full CFG+SSA (blocks, `preds`/`succs`, `OP_CODE_IF`/`JUMP`/`PHI`, a reverse-post-order
fixpoint, dominator-based guard analysis) — the Go path proves it end-to-end. **This
is a frontend-emission change only: no `proto/` / gIR / engine-core change.**

## Why (recall + precision)

- **Ruby has an outright recall bug**: `if`/`elsif`/`while`/`unless`/`until` have no
  handler and fall through to a `ruby.unsupported` intrinsic — the branch body is
  **never traversed**, so sources/sinks inside them are invisible (`converters/ruby/lower.go`).
- **Loop-carried taint** is not modeled anywhere (loops "execute once", no back-edges).
- The three frontends always hit the engine's single-block **linear fast path**, so
  the **dominator-based sanitizer/guard precision** (`internal/analysis/guards.go`)
  can never run for them — real CFGs unlock it and let us safely broaden rules later.

Honest scope: full CFG+SSA directly recovers Ruby's dropped branches, loop-carried
taint, and flow-sensitive precision. The larger SSRF/deserialization recall misses
also need source-breadth + inter-procedural work — a **separate** track. This is the
foundation that makes that track safe.

## Design — AST-directed SSA (Braun et al.)

The frontends lower from **structured ASTs** (Python `ast`, goja AST, Ripper sexp),
so use Braun, Buchwald, Hack et al. *"Simple and Efficient Construction of SSA Form"*
— it builds SSA during AST traversal with no dominance-frontier pass, and its
**sealed-block** mechanism handles loop back-edges. This generalizes the existing
per-function `env` map (one block, name→value) into per-block current definitions.

### Shared package `converters/ssabuild`

Generic over the frontends' uniform value type (`*ir.Value` / `*ir.Instruction`):

- `NewBuilder(fn)`, `NewBlock() BlockID`, `Seal(BlockID)` (all preds known),
- `Write(name string, b BlockID, v *ir.Value)`, `Read(name string, b BlockID) *ir.Value`
  (inserts trivial-PHI-eliminated PHIs on demand),
- `SetIf(b, cond, tBlk, fBlk)`, `SetJump(b, target)`, terminator helpers,
- `Finish() []*ir.BasicBlock` — emits `OP_CODE_IF`/`JUMP`/`PHI`, populates `preds`/`succs`,
  **deterministic** block + value numbering.

The existing `converters/lowerutil/merge.go` `MergeBranchEnvs` (the current if/else PHI
patch used by Python/JS) becomes a special case of `Read` and is retired.

Single-block functions with no branches must still emit **one** block so they keep the
engine's linear fast path (no perf regression on straight-line handlers).

## Phases (each independently shippable; gated before commit)

- [ ] **Phase 0 — `converters/ssabuild`** package + table-driven unit tests
      (straight-line, if/else diamond → PHI, while back-edge → loop PHI via sealed
      block, nested if-in-loop, self-referential PHI elimination, determinism). No
      frontend wired yet.
- [ ] **Phase 1 — Ruby** (smallest; proving ground)
      - [ ] 1a: flatten the currently-dropped `if`/`while`/`unless`/`until` bodies
            (immediate recall win, near-zero risk) + corpus samples.
      - [ ] 1b: adopt `ssabuild` for real blocks/PHI/back-edges.
- [ ] **Phase 2 — Python** (biggest surface): if/for/while/try/with/bool-ops/
      comprehensions → real CFG; retire `lowerIfMerge`. Measure CVE-recall delta.
- [ ] **Phase 3 — JavaScript**: if/for/while/do-while/switch/try/labelled → real CFG;
      retire its `lowerIfMerge`.
- [ ] **Phase 4 — turn on precision**: loop-carried-taint + sanitizer-dominates-sink
      corpus samples (per language, positive + safe control); confirm loops fire and
      dominator guards suppress; relax any rule scoping that compensated for
      straight-line imprecision.

## Acceptance gate (every phase, before commit)

1. `go build ./...` clean; `gofmt`, `go vet` clean.
2. Converter tests pass with **no new `unsupported`/fallback comments** (the repo's
   instruction-coverage convention).
3. `go test ./test/corpus/` **FP=0** (precision guard) + new per-language samples.
4. CVE recall campaign (parse-only py/js/ruby) delta recorded — the real-world number.
5. Quality-gate perf: `Scan_Python`/`Scan_JS`/`Scan_Ruby` within +10% (real CFG runs
   the engine fixpoint instead of the linear fast path — must measure).
6. Determinism: stable block/value numbering across runs.

## Progress log

(updated as phases land — newest first)

- _pending_ — Phase 0 kicked off.
