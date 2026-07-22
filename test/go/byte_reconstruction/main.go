package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

// snakeString rebuilds its input one byte at a time — the common
// normalize/snake_case idiom found in real code (e.g. casdoor's
// util.SnakeString). It is NOT a sanitizer: it only lower-cases and inserts
// underscores, so SQL/shell metacharacters pass through unchanged. The engine
// must carry taint through the `data = append(data, s[i])` reconstruction and
// the `string(data)` conversion — indexing and the []byte->string CONVERT
// already propagate, so this exercises the `builtin.append` propagator that
// bridges them. Without it the flow silently dies inside this helper.
func snakeString(s string) string {
	data := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		data = append(data, s[i])
	}
	return strings.ToLower(string(data))
}

func main() {
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		field := r.URL.Query().Get("field") // untrusted
		cmd := snakeString(field)            // taint must survive the byte loop
		// Vulnerable: normalized-but-not-sanitized input reaches os/exec.
		exec.Command("sh", "-c", cmd).Run()
		fmt.Fprintln(w, "done")
	})
	http.ListenAndServe(":8090", nil)
}
