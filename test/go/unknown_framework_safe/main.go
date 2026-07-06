package main

import (
	"database/sql"

	"example.com/miniweb"
)

var db *sql.DB

// Safe control for unknown_framework: the request-object accessor value reaches
// only the BOUND parameter of a parameterized query (arg #1), never the query
// text (arg #0), so no SQL-injection finding must fire — verifies the
// method-sugar taint still respects sink argument pinning.
func main() {
	r := miniweb.NewRouter()
	r.GET("/ok", func(c *miniweb.Ctx) {
		id := c.Query("id")
		_, _ = db.Query("SELECT * FROM t WHERE id = ?", id) // parameterized: id is bound
	})
}
