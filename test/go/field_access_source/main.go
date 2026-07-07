package main

import (
	"net/http"
	"os"
)

// Field-access source: the untrusted value is read as a STRUCT FIELD off the
// request (r.URL.Path), not via a method accessor. Method sources like
// r.FormValue(...) match a rule by their Callee, but a field read lowers to
// FIELD/INDEX with no Callee, so this was previously unmatchable. The frontend's
// synthetic request-object source (addHTTPRequestSource) taints the whole
// *http.Request, so the field read carries taint into the path-traversal sink.
func main() {
	http.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path       // field-access source (no Callee)
		f, err := os.Open(name)  // path-traversal sink
		if err != nil {
			return
		}
		defer f.Close()
		w.Write([]byte("ok"))
	})
	http.ListenAndServe(":8080", nil)
}
