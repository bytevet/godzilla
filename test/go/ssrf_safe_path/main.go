package main

import (
	"fmt"
	"io"
	"net/http"
)

// Safe: the untrusted value only reaches the PATH of a fixed host, so the request
// cannot be redirected to an attacker-controlled host — not exploitable SSRF.
// Both the concatenation and the Sprintf form must be suppressed (zero findings).
func main() {
	http.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		userPath := r.URL.Query().Get("path")

		resp, _ := http.Get("https://api.internal.example.com/v1/" + userPath)
		io.Copy(w, resp.Body)

		resp2, _ := http.Get(fmt.Sprintf("https://api.internal.example.com/items/%s", userPath))
		io.Copy(w, resp2.Body)
	})
	http.ListenAndServe(":8085", nil)
}
