package main

import (
	"net/http"
	"os/exec"

	"example.com/util"
)

// Safe control: the request value is passed to util.Constant, a dependency
// function that IGNORES its input and returns a constant. Because the dependency
// body is analyzed, the engine sees the taint does not flow through, so no
// finding must fire — dep-lowering is precise, not a blanket propagator.
func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	out := util.Constant(cmd)
	exec.Command("sh", "-c", out).Run()
}

func main() {
	http.HandleFunc("/run", handler)
	_ = http.ListenAndServe(":8080", nil)
}
