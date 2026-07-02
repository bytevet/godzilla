package main

import (
	"net/http"
	"os/exec"
)

// Runner is an interface; the call site below dispatches dynamically (INVOKE),
// so taint must flow through the interface into the concrete implementation.
type Runner interface{ Run(cmd string) }

type shellRunner struct{}

func (s *shellRunner) Run(cmd string) {
	exec.Command("sh", "-c", cmd).Run() // sink (command injection)
}

// newRunner returns the interface type, keeping r.Run() a dynamic dispatch.
func newRunner() Runner { return &shellRunner{} }

func main() {
	r := newRunner()
	http.HandleFunc("/x", func(w http.ResponseWriter, req *http.Request) {
		cmd := req.URL.Query().Get("cmd") // source (untrusted input)
		r.Run(cmd)                        // interface dispatch -> shellRunner.Run
	})
	http.ListenAndServe(":0", nil)
}
