// A comparison on tainted data yields a BOOLEAN, which carries influence but not
// content, so it must not propagate taint. Control for a real false positive: the
// bool below reached exec.Command and was reported as a CRITICAL, high-confidence
// command injection. The genuine flow in the same handler must still fire.
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")

	// SAFE: a bool has two possible values, no payload.
	isAdmin := user == "admin"
	_ = exec.Command("/bin/echo", fmt.Sprint(isAdmin)).Run()

	// STILL VULNERABLE: concatenation (BIN_OP_ADD) carries the raw value.
	_ = exec.Command("/bin/sh", "-c", "echo "+user).Run()
	_ = w
}

func main() { http.HandleFunc("/", handler) }
