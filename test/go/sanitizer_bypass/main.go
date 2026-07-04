package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// Sanitize is a project-local input sanitizer. It returns a value derived from
// its argument, so taint flows through it structurally. A rule set that
// registers "go:*Sanitize" as a sanitizer must NOT let taint reach the sink
// through it (see internal/analysis/sanitizer_test.go). The built-in rules do
// not know Sanitize is a sanitizer, so they conservatively still flag the flow
// — which is why this sample's expected.yaml lists go-command-injection.
func Sanitize(s string) string {
	return "safe:" + s
}

func main() {
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd") // untrusted
		safe := Sanitize(cmd)           // neutralized here (under a sanitizer rule)
		exec.Command("sh", "-c", safe).Run()
		fmt.Fprintln(w, "ok")
	})
	http.ListenAndServe(":8086", nil)
}
