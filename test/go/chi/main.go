// Chi handler with command injection: a URL route parameter read via
// chi.URLParam is formatted into a shell command.
package main

import (
	"fmt"
	"net/http"
	"os/exec"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()

	r.Get("/ping/{host}", func(w http.ResponseWriter, req *http.Request) {
		host := chi.URLParam(req, "host")
		_ = exec.Command("sh", "-c", fmt.Sprintf("ping -c1 %s", host)).Run()
		_, _ = w.Write([]byte("ok"))
	})

	_ = http.ListenAndServe(":8080", r)
}
