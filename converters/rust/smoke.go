package rust_converter

import (
	"fmt"
	"os"
	"sync"

	ir "godzilla/pkg/ir/v1"
)

// FE-10: rustc's textual MIR is an explicitly unstable format that this frontend
// regex-scrapes. A rustc upgrade can silently change it so calls or taint
// disappear and the gate stays green on unanalyzed code. The smoke check below
// compiles a tiny snippet with the discovered rustc, lowers it, and verifies the
// shapes taint analysis depends on are still recovered — surfacing MIR-format
// drift as a loud warning instead of a silent zero-findings scan.

// smokeSnippet exercises the two structures the lowering must recover: a CALL
// to a source-level API (env::var) whose result flows to another CALL
// (Command::new), each carrying a span (Pos). If a rustc release changes the
// MIR text enough to break these, the check fails.
const smokeSnippet = `pub fn __godzilla_smoke(key: &str) {
    let v = std::env::var(key).unwrap();
    let _ = std::process::Command::new(&v);
}
`

// verifyMIRShape reports whether a lowered program still contains the shapes the
// taint engine relies on: at least one CALL instruction that carries a source
// position. It is the pure, testable core of the smoke check.
func verifyMIRShape(prog *ir.Program) bool {
	if prog == nil {
		return false
	}
	for _, mod := range prog.Modules {
		if mod == nil {
			continue
		}
		for _, fn := range mod.Functions {
			if fn == nil {
				continue
			}
			for _, blk := range fn.Blocks {
				if blk == nil {
					continue
				}
				for _, inst := range blk.Instrs {
					if inst == nil {
						continue
					}
					if inst.Op == ir.OpCode_OP_CODE_CALL && inst.GetPos() != nil {
						return true
					}
				}
			}
		}
	}
	return false
}

var (
	smokeOnce sync.Once
	smokeOK   bool
)

// warnIfMIRDrifted runs the smoke check once per process and, if the installed
// rustc's MIR no longer lowers to the expected shapes, prints a prominent
// warning. It never fails the scan (a transient rustc issue must not block an
// otherwise-working run); it converts silent fidelity decay into a visible
// signal. The check is skipped if the smoke compile itself can't run (no rustc,
// offline) — that condition is already reported by the per-file path.
func warnIfMIRDrifted() {
	smokeOnce.Do(func() {
		tmp, err := os.CreateTemp("", "godzilla-rust-smoke-*.rs")
		if err != nil {
			smokeOK = true // can't check; don't cry wolf
			return
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.WriteString(smokeSnippet); err != nil {
			smokeOK = true
			return
		}
		tmp.Close()

		mir, err := emitMIR(tmp.Name())
		if err != nil {
			smokeOK = true // compile failed (no/old rustc) — surfaced elsewhere
			return
		}
		prog := &ir.Program{Mode: "mir", Modules: []*ir.Module{lowerMIR(mir, tmp.Name())}}
		smokeOK = verifyMIRShape(prog)
		if !smokeOK {
			fmt.Fprintf(os.Stderr, "warning: rust: this rustc's MIR did not lower to the expected shapes — "+
				"the MIR text format may have changed and Rust findings could be silently incomplete; "+
				"please report the rustc version (rustc --version).\n")
		}
	})
}
