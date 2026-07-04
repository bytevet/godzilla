// Sample: a helper writes request data into the caller's out-pointer, and the
// caller passes that (now tainted) local to a shell exec (ENG-6b — taint
// through a callee's side effect on a pointer parameter). The taint reaches the
// caller across a function boundary, so the finding is Medium confidence.
package main

import (
	"net/http"
	"os/exec"
)

// fill writes request-derived data into the memory its out-pointer names.
func fill(r *http.Request, out *string) {
	*out = r.URL.Query().Get("cmd")
}

func handler(w http.ResponseWriter, r *http.Request) {
	var cmd string
	fill(r, &cmd)
	_ = exec.Command("sh", "-c", cmd).Run()
	_ = w
}

func main() {
	http.HandleFunc("/x", handler)
	_ = http.ListenAndServe(":0", nil)
}
