package main

import (
	"net/http"
	"os/exec"

	"example.com/util"
)

// The request value flows through util.Transform — a function in a DEPENDENCY
// module that no rule models. It reaches the command sink only because
// dependency bodies are lowered (taint flows through the library). Under the old
// LoadSyntax behavior this was a false negative.
func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	out := util.Transform(cmd)
	exec.Command("sh", "-c", out).Run()
}

func main() {
	http.HandleFunc("/run", handler)
	_ = http.ListenAndServe(":8080", nil)
}
