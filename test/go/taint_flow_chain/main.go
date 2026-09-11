// Two HTTP handlers reach ONE exec sink through a three-call chain. Both routes
// are exploitable, and the chain is long enough that reporting only the
// endpoints tells a reader nothing about how the value travelled.
//
// The oracle is in expected.yaml: TWO findings at the one sink. A single
// finding here means a summary channel collapsed the two entrypoints onto
// whichever the worklist reached first — which used to make the /safe route the
// only one anybody was told about, and /vuln silently exploitable.
package main

import (
	"net/http"
	"os/exec"
)

func listHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	dispatch(name)
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	dispatch(term)
}

// The three hops exist so the reconstructed path has a middle to lose.
func dispatch(s string) {
	forward("prefix-" + s)
}

func forward(s string) {
	run(s)
}

func run(s string) {
	_ = exec.Command("sh", "-c", s)
}

func main() {
	http.HandleFunc("/list", listHandler)
	http.HandleFunc("/search", searchHandler)
	_ = http.ListenAndServe(":8080", nil)
}
