// A comparison on tainted data yields a BOOLEAN, which carries influence but not
// content: `user == "admin"` has exactly two possible values, so nothing the
// attacker supplies survives into it and no command can be injected through it.
//
// Control for a real false positive: BIN_OP used to propagate taint regardless
// of kind, so the bool below reached exec.Command and was reported as a
// CRITICAL, high-confidence command injection. The genuine flow in the same
// handler (the raw parameter, concatenated) must still fire — that is what
// distinguishes this fix from simply weakening BIN_OP.
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")

	// SAFE: both are booleans — two possible values, no payload. (Only the
	// equality test actually fired before the fix; `len()` does not forward taint
	// into the length test, so it is here as a second shape, not a second repro.)
	isAdmin := user == "admin"
	isLong := len(user) > 32
	_ = exec.Command("/bin/echo", fmt.Sprint(isAdmin)).Run()
	_ = exec.Command("/bin/echo", fmt.Sprint(isLong)).Run()

	// STILL VULNERABLE: concatenation (BIN_OP_ADD) carries the raw value.
	_ = exec.Command("/bin/sh", "-c", "echo "+user).Run()
	_ = w
}

func main() { http.HandleFunc("/", handler) }
