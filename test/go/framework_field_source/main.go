package main

import (
	"os/exec"

	"example.com/beegostub"
)

// The dependency accessor Input reads *http.Request through a field INTERNALLY
// (no tainted arg), so the demand-driven scope would never enqueue it; it fires
// only because reqSourceHosts seeds a dep function that (a) contains a planted
// request source and (b) is directly called by user code (c.Input here).
func main() {
	beegostub.Serve(func(c *beegostub.Controller) {
		id := c.Input("id")                 // dep accessor, reads request internally
		exec.Command("sh", "-c", id).Run() // command injection (sink)
	})
}
