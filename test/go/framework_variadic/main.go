package main

import (
	"database/sql"
	"os/exec"

	"example.com/varweb"
)

var db *sql.DB

// varweb is an unmodeled framework registering handlers VARIADICALLY. The handler
// is recognized only because collectRouteHandlers unwraps the variadic slice, so
// the frontend taints the *varweb.Ctx request object; request taint then flows
// through the lowered framework body into the sinks. Without variadic-handler
// recognition the context is never seeded and nothing fires.
func main() {
	r := varweb.New()
	r.GET("/run", func(c *varweb.Ctx) {
		cmd := c.Query("cmd")               // request-object accessor
		exec.Command("sh", "-c", cmd).Run() // command injection (sink)

		var name string
		c.Bind(&name)                                                // out-param taint
		_, _ = db.Query("SELECT * FROM t WHERE n = '" + name + "'") // SQL injection (sink)
	})
}
