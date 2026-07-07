package main

import (
	"net/http"
	"os/exec"
)

// The request is read by a HELPER, not by the handler itself, so detecting this
// depends on request-object provenance crossing the call boundary (PR4) — not on
// the handler-local method-sugar rule, and not on an enumerated FormValue source
// glob (which PR4 removes).
func name(r *http.Request) string {
	return r.FormValue("name")
}

func handler(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", name(r)).Run() // command injection
}

func main() {
	http.HandleFunc("/run", handler)
	_ = http.ListenAndServe(":8080", nil)
}
