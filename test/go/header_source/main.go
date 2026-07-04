package main

import (
	"net/http"
	"os/exec"
)

// The untrusted value comes from a request HEADER (not a query parameter);
// header-sourced injection was previously missed (COV-6).
func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cmd := r.Header.Get("X-Run") // untrusted header
		exec.Command("sh", "-c", cmd).Run()
	})
	http.ListenAndServe(":8092", nil)
}
