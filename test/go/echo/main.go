// Echo handler with SQL injection: a query parameter read via Echo's
// c.QueryParam is formatted straight into a database/sql query.
package main

import (
	"database/sql"
	"fmt"

	"github.com/labstack/echo/v4"
)

var db *sql.DB

func main() {
	e := echo.New()

	e.GET("/user", func(c echo.Context) error {
		id := c.QueryParam("id")
		query := fmt.Sprintf("SELECT name FROM users WHERE id = '%s'", id)
		rows, err := db.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close()
		return c.String(200, "ok")
	})

	_ = e.Start(":8080")
}
