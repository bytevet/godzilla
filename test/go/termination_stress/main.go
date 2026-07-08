// termination_stress packs every cyclic shape that could non-terminate a naive
// fixpoint analyzer into one sample. The DETECTIONS matter less than the fact
// that conversion + analysis COMPLETE: if any termination guard regresses (the
// worklist's set-once summary merges, the block fixpoint's stop condition, a
// seen-set on a def-use walk, the recursive-type cache), this sample hangs the
// corpus test and fails the suite on its timeout.
//
// Shapes and the guard each one exercises:
//   - spin:          direct recursion carrying taint (paramTaint set-once merge
//                    + queued dedup; a recursive callEffect must not re-enqueue
//                    forever)
//   - ping/pong:     mutual recursion (call-graph cycle through two summaries)
//   - loopConcat:    CFG back-edge with a PHI whose operands include itself via
//                    the loop (block fixpoint convergence + reconstructPath's
//                    seen-guard on the PHI def-use cycle)
//   - flipFlop:      a loop that alternately taints and strong-update-cleans the
//                    same local — the adversarial case for the non-monotone
//                    block transfer (statesEqual stop + maxPasses backstop)
//   - viaList:       a self-referential recursive type and a cyclic heap value
//                    (convertType's pre-insertion recursion guard + container
//                    taint walks)
//   - storeAndCall / readAndCall: a global publish/read cycle woven into mutual
//                    recursion (globalTaint set-once + reader re-enqueue)
package main

import (
	"net/http"
	"os/exec"
)

// spin recurses directly, growing the tainted value each step.
func spin(cmd string, n int) string {
	if n <= 0 {
		return cmd
	}
	return spin(cmd+"x", n-1)
}

// ping/pong recurse mutually, both taint-returning.
func ping(cmd string, n int) string {
	if n <= 0 {
		return cmd
	}
	return pong(cmd+"p", n-1)
}

func pong(cmd string, n int) string {
	if n <= 0 {
		return cmd
	}
	return ping(cmd+"q", n-1)
}

// loopConcat accumulates taint around a back-edge: out's PHI depends on itself.
func loopConcat(cmd string) string {
	out := ""
	for i := 0; i < 4; i++ {
		out += cmd
	}
	return out
}

// flipFlop alternately taints and cleanly overwrites the same local inside a
// loop — taint appears and disappears across iterations, the worst case for a
// strong-update transfer function iterated to fixpoint. The union join keeps
// the tainted path, so the flow to the sink is a true positive.
func flipFlop(cmd string) string {
	v := "safe"
	for i := 0; i < 3; i++ {
		if i%2 == 0 {
			v = cmd
		} else {
			v = "safe"
		}
	}
	return v
}

// node is a self-referential type; viaList builds a CYCLIC value of it.
type node struct {
	val  string
	next *node
}

func viaList(cmd string) string {
	head := &node{val: cmd}
	head.next = head // cycle: head.next.next.next... never nil
	return head.next.val
}

// shared + storeAndCall/readAndCall: taint published through a global inside a
// mutual-recursion cycle, so the global's readers and the callers re-enqueue
// machinery chase each other.
var shared string

func storeAndCall(cmd string, n int) string {
	shared = cmd
	if n <= 0 {
		return shared
	}
	return readAndCall(n - 1)
}

func readAndCall(n int) string {
	if n <= 0 {
		return shared
	}
	return storeAndCall(shared+"g", n-1)
}

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	exec.Command("sh", "-c", spin(cmd, 3)).Run()
	exec.Command("sh", "-c", ping(cmd, 3)).Run()
	exec.Command("sh", "-c", loopConcat(cmd)).Run()
	exec.Command("sh", "-c", flipFlop(cmd)).Run()
	exec.Command("sh", "-c", viaList(cmd)).Run()
	exec.Command("sh", "-c", storeAndCall(cmd, 2)).Run()
}

func main() {
	http.HandleFunc("/run", handler)
	_ = http.ListenAndServe(":8080", nil)
}
