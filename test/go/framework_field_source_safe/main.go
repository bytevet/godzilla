package main

import (
	"os/exec"

	"example.com/beegostub"
)

// Safe control: SafeInput reads the request internally but returns a CONSTANT.
// reqSourceHosts seeds its body, and precise body analysis sees no tainted
// return, so nothing fires — this is why the mechanism seeds+analyzes rather
// than blindly tainting the accessor's result.
func main() {
	beegostub.Serve(func(c *beegostub.Controller) {
		id := c.SafeInput("id")
		exec.Command("sh", "-c", id).Run()
	})
}
