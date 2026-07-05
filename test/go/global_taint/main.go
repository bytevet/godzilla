// Sample: taint stashed in a package-level global in one handler and read back
// in another, then passed to a shell exec (ENG-6 — taint through globals). The
// flow crosses a function boundary via the global, so the finding is Medium
// confidence.
package main

import (
	"net/http"
	"os/exec"
)

// stashed holds request data written by saveHandler and read by runHandler — a
// package-level global carrying taint between two functions.
var stashed string

func saveHandler(w http.ResponseWriter, r *http.Request) {
	stashed = r.URL.Query().Get("cmd")
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
