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

- [x] **Phase 0 — `converters/ssabuild`** package + table-driven unit tests
      (straight-line, if/else diamond → PHI, while back-edge → loop PHI via sealed
      block, nested if-in-loop, self-referential PHI elimination, determinism). No
      frontend wired yet. **DONE.**
- [ ] **Phase 1 — Ruby** (smallest; proving ground)
      - [x] 1a: flatten the currently-dropped `if`/`while`/`unless`/`until` bodies
            (immediate recall win, near-zero risk) + corpus samples. **DONE.**
      - [x] 1b: adopt `ssabuild` for real blocks/PHI/back-edges. **DONE.**
- [x] **Phase 2 — Python** (biggest surface): if/for/while/try/with/bool-ops/
      comprehensions → real CFG; retire `lowerIfMerge`. **DONE.**
- [x] **Phase 3 — JavaScript**: if/for/while/do-while/switch/try/labelled → real CFG;
      retire its `lowerIfMerge`. **DONE.**
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

- **Phase 3 DONE** — JavaScript lowering now drives `converters/ssabuild`: real CFG
  blocks + PHI + loop back-edges for if/else, for/for-in/for-of, while/do-while,
  switch (per-case blocks with conservative fall-through edges), try/catch/finally
  (exception edge into the catch block), labelled/block unwrapped; ternary/`&&`/`||`/`??`
  keep their BIN_OP/PHI merges through the builder. Retired the JS `lowerIfMerge`/
  `MergeBranchEnvs` path. Straight-line funcs still emit one block (linear fast path).
  Inter-procedural surface (lowerCall/syntacticCallee/emitCallRecv/opaque-base reads/
  funcRefValue/collect.go) untouched. New samples: `loop_carried_command_injection`
  fires js-command-injection (loop-carried taint the old model missed),
  `try_catch_command_injection` fires across the exception edge, `loop_carried_safe`
  silent. Corpus TP=189 FP=0 FN=0 (262 samples). Adversarial SSA-review passed. Perf:
  same-machine benchstat (n=15) Scan_JS time `~` (p=0.51, no significant change),
  B/op+allocs +5.6% (well under +10%). All three straight-line frontends now on SSA.
- **Phase 2 DONE** — Python lowering now drives `converters/ssabuild`: real CFG
  blocks + PHI + loop back-edges for if/elif/else, while(+else), for(+else),
  try/except/finally; `with`/bool-ops/ternary/comprehensions emit through the
  builder (comprehensions stay in the current block). Retired `lowerIfMerge` +
  the `lowerutil.MergeBranchEnvs` path and the `env`/`instrs` maps (now
  Builder `ReadVariable`/`WriteVariable`/`AddInstr` + an `assigned` set + a
  `terminated` flag). Construct→block mapping: **if** = diamond (cond block →
  then/else → merge, sealed after both arms; elif is a nested If in `orelse`);
  **while/for** = header/body/exit with a body→header back-edge, header sealed
  after the back-edge (loop-carried taint via the header PHI); a for-loop binds
  its target to the iterable in the body block; **try** = try body inline, then
  an exception edge (bodyEnd → single handler block, else → after) so try-body
  taint reaches except/finally (conservative may-analysis, no exception typing);
  **with** = inline (VAR=EXPR + body). The inter-procedural surface (lowerCall,
  INVOKE/CHA/UntypedDispatch, opaque-base subscripts, thread/process dispatch,
  param/handler sources, import aliasing) is untouched. Straight-line functions
  still emit exactly ONE block (linear fast path preserved). New samples:
  `loop_carried_command_injection` fires (loop-carried taint the old model
  missed), `try_except_command_injection` fires (taint across the exception
  edge), `loop_carried_safe` silent. Also fixed a pre-existing gap surfaced by the
  now-lowered `while`-guards: Python **`Compare`** (`a < b`, `x == y`, `k in d`) had
  no lowering (→ `py.unsupported`); now `pyast.py` emits its operands and `lower.go`
  lowers them (so a source/sink/validator inside a comparison fires) behind an inert
  `builtin.compare` intrinsic — which also gives branch conditions a def-use edge for
  Phase 4's guard analysis. Corpus FP=0 FN=0 (259 samples, TP=187); python converter
  + analysis tests green. Perf: same-machine benchstat Scan_Python `~` (p=0.063, no
  significant change, well under +10%). Gate: build/gofmt/vet/python-tests/corpus clean.
- **Phase 1b DONE** — Ruby lowering now drives `converters/ssabuild`: real CFG
  blocks + PHI + loop back-edges (if/elsif/else/while/until/case), retiring the
  single-block + manual `MergeBranchEnvs` model. Straight-line funcs still emit one
  block (linear fast path kept). New samples: `loop_carried_command_injection` fires
  (loop-carried taint the old model missed), `loop_carried_safe` silent,
  `nested_if_in_loop`. Corpus TP=185 FP=0 FN=0. Adversarial SSA-review stage passed.
  **Perf: same-machine benchstat Scan_Ruby −5.27% vs Phase 1a — no regression** (an
  agent's crude cross-runner number falsely read +19%; only same-machine back-to-back
  is valid, as the gate itself measures). ssabuild adoption pattern proven → Python/JS next.
- **Phase 1a DONE** — Ruby `if`/`elsif`/`else`/`unless`/`while`/`until` (+ modifier
  forms) now lower their bodies (were dropped to `ruby.unsupported`, bodies never
  traversed — a recall bug). Flattened into the current block (single-block, linear
  fast path preserved), `lowerutil.MergeBranchEnvs` for if/else assigned-var PHI.
  Samples control_flow_if / control_flow_while fire ruby-command-injection; safe
  control silent. Corpus TP=183 FP=0 FN=0. Gate: build/gofmt/vet/ruby-tests/corpus green.
- **Phase 0 DONE** — `converters/ssabuild` (Braun SSA over `*ir.Value`): `NewBuilder`/
  `NewBlock`/`Seal`/`WriteVariable`/`ReadVariable`/`SetIf`/`SetJump`/`AddInstr`/`Finish`,
  with `readVariableRecursive` + `incompletePhis` (loop headers) + `removeTrivialPhi`,
  deterministic numbering. Tests: diamond PHI, while-header loop PHI, nested if-in-loop,
  trivial-PHI elimination, determinism — all green. Pure additive package, no frontend
  wired yet → corpus unaffected. Gate: build/gofmt/vet/test clean.
- _pending_ — Phase 0 kicked off.
