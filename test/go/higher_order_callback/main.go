// ENG: higher-order-callback taint in Go. A tainted value is passed to a generic
// helper that invokes a callback (a func-typed parameter); the callback runs a
// command with the tainted argument. Go's frontend already lowers `fn(x)` (fn a
// param) to an indirect call, so this exercises the engine's function-value
// resolution with NO Go frontend change.
package main

import (
	"net/http"
	"os/exec"
)

func runCmd(c string) {
	exec.Command("sh", "-c", c).Run() // command-injection sink
}

func apply(data string, fn func(string)) {
	fn(data) // indirect call through the callback parameter
}

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	apply(q, runCmd)
}

func main() {
	http.HandleFunc("/run", handler)
	http.ListenAndServe(":8080", nil)
}
