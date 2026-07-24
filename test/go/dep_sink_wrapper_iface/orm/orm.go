package orm

import (
	"database/sql"
	"fmt"
)

// Find mimics an ORM query method: it takes an interface{} "bean" and builds a
// query via reflection/formatting. The engine over-approximates and believes the
// bean's taint reaches the query string, firing database/sql.Query#0 INSIDE this
// dependency. Because the tainted value entered through an interface{} (not a
// string) parameter, no sink-parameter summary is formed -- the precision fix.
func Find(db *sql.DB, bean interface{}) {
	q := fmt.Sprintf("SELECT * FROM t WHERE c = %v", bean)
	rows, err := db.Query(q)
	if err == nil {
		_ = rows.Close()
	}
}
