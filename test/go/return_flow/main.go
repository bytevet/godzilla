package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// readInput RETURNS untrusted data: the taint leaves this function through its
// return value rather than being passed down as an argument. The caller then
// sinks the returned value, so the flow is inter-procedural via a return
// summary and must be reported at Medium confidence (see
// internal/analysis/return_flow_test.go, the ENG-7 regression guard).
func readInput(r *http.Request) string {
	return r.URL.Query().Get("cmd")
}

func main() {
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		cmd := readInput(r)                  // taint arrives via return
		exec.Command("sh", "-c", cmd).Run()  // sink
		fmt.Fprintln(w, "ok")
	})
	http.ListenAndServe(":8087", nil)
}
