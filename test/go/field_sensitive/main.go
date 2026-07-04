package main

import (
	"net/http"
	"os/exec"
)

// Field-sensitivity FP guard (ENG-3): only field A is tainted; the sink reads
// the CLEAN field B, so tainting one struct field must not taint a read of a
// different field. Expect ZERO findings.
type Req struct{ A, B string }

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var p Req
		p.A = r.URL.Query().Get("x") // taint field A only
		p.B = "safe-constant"        // field B is clean
		exec.Command("sh", "-c", p.B).Run()
	})
	http.ListenAndServe(":9100", nil)
}
