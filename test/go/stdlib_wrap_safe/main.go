package main

import (
	"os/exec"

	"example.com/webctx"
)

// Safe control: the framework accessor returns a constant (never reads the
// request), so the value reaching the command sink is not attacker-controlled
// and no finding is expected. Confirms the request-accessor propagators only
// forward EXISTING taint and do not fabricate it.
func main() {
	r := webctx.NewRouter()
	r.GET("/run", func(c *webctx.Ctx) {
		cmd := c.Query("cmd")               // constant, untainted
		exec.Command("sh", "-c", cmd).Run() // no finding
	})
}
