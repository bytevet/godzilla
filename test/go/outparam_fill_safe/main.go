// False-positive control for ENG-6b: the helper writes a CONSTANT into the
// out-pointer (it never uses the request), so the shell exec that reads the
// filled local is safe and MUST NOT be flagged.
package main

import (
	"net/http"
	"os/exec"
)

// fill writes a constant into the out-pointer; the request is ignored.
func fill(r *http.Request, out *string) {
	_ = r
	*out = "ls"
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
