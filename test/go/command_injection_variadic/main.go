// Command injection where the untrusted value sits in the VARIADIC argument of
// exec.Command ("sh -c <tainted>"), the canonical shell-RCE shape. This
// exercises taint propagation into a variadic (...string) parameter — distinct
// from test/go/command_injection, which taints the command-NAME argument.
package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")         // source
	_ = exec.Command("sh", "-c", cmd).Run() // tainted arg in the variadic position
	_ = w
}

func main() {
	http.HandleFunc("/run", handler)
	_ = http.ListenAndServe(":8080", nil)
}
