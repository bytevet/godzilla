package main

import (
	"database/sql"
	"os/exec"

	"example.com/miniweb"
)

var db *sql.DB

// miniweb is an external web framework Godzilla has NO rules for. The handler is
// recognized only because it is registered via a routing verb (r.GET), so the
// frontend taints its *miniweb.Ctx context; the engine then treats c.Query() and
// c.Bind(&name) — external methods on the request object — as untrusted, which is
// the framework-agnostic accessor coverage.
func main() {
	r := miniweb.NewRouter()
	r.GET("/run", func(c *miniweb.Ctx) {
		cmd := c.Query("cmd")               // request-object method sugar
		exec.Command("sh", "-c", cmd).Run() // command injection

		var name string
		c.Bind(&name)                                                // out-param taint
		_, _ = db.Query("SELECT * FROM t WHERE n = '" + name + "'") // SQL injection
	})
}
