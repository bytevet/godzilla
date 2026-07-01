package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// runCommand is a separate top-level helper containing the actual dangerous
// sink. The vulnerable flow spans two functions: the HTTP handler in main()
// reads the untrusted "cmd" query parameter and passes it as an argument to
// runCommand, which is where the tainted value finally reaches exec.Command.
// A sound inter-procedural taint analysis must track the parameter `c`
// across this function-call boundary to flag the vulnerability.
func runCommand(c string) {
	// Vulnerable: OS command injection - tainted parameter reaches exec sink
	// in a different function than the one that read the untrusted input.
	exec.Command("sh", "-c", c).Run()
}

func main() {
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		// Untrusted input crosses into runCommand() here; the sink itself
		// lives in that separate function, not in this handler.
		runCommand(cmd)
		fmt.Fprintln(w, "command dispatched")
	})
	fmt.Println("Server starting on :8085")
	http.ListenAndServe(":8085", nil)
}
