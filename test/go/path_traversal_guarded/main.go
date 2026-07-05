// False-positive control for ENG-9 (guard/barrier sanitization): the untrusted
// filename is checked with filepath.IsLocal, and the file read is reached only
// on the branch where the check passed. Because the validator dominates the
// sink on the path taken, the path is proven contained and the read MUST NOT be
// flagged — this is the "validate, then use" idiom a flow-insensitive engine
// wrongly flags.
package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	if !filepath.IsLocal(name) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	data, _ := os.ReadFile(name)
	_, _ = w.Write(data)
}

func main() {
	http.HandleFunc("/f", handler)
	_ = http.ListenAndServe(":0", nil)
}
