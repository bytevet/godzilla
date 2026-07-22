// Path traversal where the tainted string passes through net/url.Parse before
// reaching the file sink (minio CVE-2022-35919 shape). url.Parse is a bodyless
// stdlib call, so without a propagator for it the taint died at the parse and
// the os.ReadFile(u.Path) sink was missed. url.Parse builds the *url.URL wholly
// from its input string, so forwarding taint to u.Path is exact.
package main

import (
	"net/http"
	"net/url"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("target")
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	data, _ := os.ReadFile(u.Path) // path traversal (sink)
	w.Write(data)
}

func main() {
	http.HandleFunc("/x", handler)
	http.ListenAndServe(":8080", nil)
}
