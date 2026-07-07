package main

import (
	"os/exec"

	"example.com/webctx"
)

// webctx is an UNKNOWN web framework (zero rulepack entries) whose request
// accessor is a lowered dependency body that parses the request via the stdlib
// (c.Request.URL.Query()). The handler's *webctx.Ctx is tainted because it is
// registered via a routing verb (r.GET); the query value then flows through the
// framework's stdlib parsing into a command sink. This fires only because the
// net/http+net/url request accessors are default propagators.
func main() {
	r := webctx.NewRouter()
	r.GET("/run", func(c *webctx.Ctx) {
		cmd := c.Query("cmd")               // untrusted via lowered framework + stdlib
		exec.Command("sh", "-c", cmd).Run() // command injection
	})
}
