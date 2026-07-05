// False-positive control for ENG-6: the package-level global holds only a
// constant (request data is never stored into it), so the shell exec that reads
// it is safe and MUST NOT be flagged.
package main

import (
	"net/http"
	"os/exec"
)

// stashed is only ever a constant; the handler reads a request param but does
// not store it into the global.
var stashed = "ls"

func saveHandler(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("cmd")
	_ = w
}

func runHandler(w http.ResponseWriter, r *http.Request) {
	_ = exec.Command("sh", "-c", stashed).Run()
	_ = w
}

func main() {
	http.HandleFunc("/save", saveHandler)
	http.HandleFunc("/run", runHandler)
	_ = http.ListenAndServe(":0", nil)
}
