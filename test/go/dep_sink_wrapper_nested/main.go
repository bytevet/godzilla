package main

// NESTED dependency sink wrappers: user -> svc.Fetch -> cmdutil.Run -> exec.Command.
// The command sink is two dependency layers deep, and each middle layer forwards
// its STRING parameter down the chain. Guards that the sink-parameter summary
// propagates up through a chain of string-param wrappers until it reaches user
// code, where the finding is reported (svc.Fetch call site).

import (
	"net/http"

	"example.com/svc"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host") // untrusted request input
	svc.Fetch(host)                   // user -> svc -> cmdutil -> exec
}

func main() {
	http.HandleFunc("/ping", handler)
	_ = http.ListenAndServe(":8080", nil)
}
