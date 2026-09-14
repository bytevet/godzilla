// A NUMBER cannot carry an injection payload: its rendering is digits.
//
// FALSE-POSITIVE CONTROL for the result-type gate (carriesPayload). Handing a
// struct with one tainted field to another function seeds that function's
// parameter WHOLESALE — the any-field marker names no index — so inside the
// callee every field of the record reads as tainted, the uint64 primary key
// with it. Formatting that key into a shell command then reported a CRITICAL
// command injection on a value no metacharacter can reach.
//
// The id is a literal, so nothing but that whole-struct widening can explain
// its taint. Both halves build a SHELL command rather than one argv element,
// so nothing but the value's own type can tell them apart.
//
// The string half must keep firing: a control that only proved the sink went
// quiet would pass equally if os/exec stopped being a sink at all.
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// Record is what a lookup returns. Only Name is request data; ID is the
// database's own key.
type Record struct {
	ID   uint64
	Name string
}

// SAFE: a uint64 renders as digits, whatever the request asked for.
func restart(rec *Record) {
	_ = exec.Command("/bin/sh", "-c", "systemctl restart worker@"+fmt.Sprint(rec.ID)).Run()
}

// VULNERABLE: the same struct's string field reaches the same shell.
func announce(rec *Record) {
	_ = exec.Command("/bin/sh", "-c", "logger -t "+rec.Name).Run()
}

func handler(_ http.ResponseWriter, r *http.Request) {
	rec := &Record{ID: 4242, Name: r.URL.Query().Get("name")}
	restart(rec)
	announce(rec)
}

func main() {
	http.HandleFunc("/", handler)
	_ = http.ListenAndServe(":8080", nil)
}
