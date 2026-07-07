package main

import (
	"net/http"
	"os"
	"path/filepath"
)

// Safe control for field_access_source: the request field is sanitized with
// filepath.Base (strips directory components) before reaching os.Open, so no
// path-traversal finding must fire — guards against the synthetic request
// source over-tainting.
func main() {
	http.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path) // sanitized
		f, err := os.Open(name)
		if err != nil {
			return
		}
		defer f.Close()
		w.Write([]byte("ok"))
	})
	http.ListenAndServe(":8080", nil)
}
