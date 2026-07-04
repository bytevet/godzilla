package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

// The untrusted value passes through strings.TrimSpace — a stdlib transform no
// rule lists as a propagator — before reaching the sink. Without the built-in
// default propagators, taint drops at TrimSpace and this vulnerability is a
// silent false negative (ENG-4). It must fire.
func main() {
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		cmd := strings.TrimSpace(r.URL.Query().Get("cmd")) // taint through a stdlib transform
		exec.Command("sh", "-c", cmd).Run()                // sink
		fmt.Fprintln(w, "ok")
	})
	http.ListenAndServe(":8091", nil)
}
