package main

// The SINK (exec.Command) lives inside a DEPENDENCY wrapper
// (example.com/cmdutil.Run), not in user code. internal/scan scopeFindings drops
// any finding whose sink sits in a library, so without the sink-parameter summary
// channel the real user vulnerability -- passing untrusted request input into a
// dependency function that reaches a command sink -- is a false negative. This
// guards that fix: the finding must surface at the USER call site (cmdutil.Run).

import (
	"net/http"

	"example.com/cmdutil"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host") // untrusted request input
	cmdutil.Run(host)                 // flows into a command sink INSIDE the dep
}

func main() {
	http.HandleFunc("/ping", handler)
	_ = http.ListenAndServe(":8080", nil)
}
