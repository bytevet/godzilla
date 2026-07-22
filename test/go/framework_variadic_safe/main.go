package main

import (
	"database/sql"

	"example.com/varweb"
)

var db *sql.DB

// Safe control: the handler IS recognized (variadic registration) and its
// request value IS tainted, but it reaches only the BOUND parameter of a
// parameterized query (arg #1), never the query text (arg #0), so no finding
// must fire — verifies variadic-handler seeding still respects sink arg pinning.
func main() {
	r := varweb.New()
	r.GET("/ok", func(c *varweb.Ctx) {
		id := c.Query("id")
		_, _ = db.Query("SELECT * FROM t WHERE id = ?", id) // parameterized: id is bound
	})
}
