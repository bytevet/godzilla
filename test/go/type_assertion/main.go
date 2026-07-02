// Type-assertion taint flow: an untrusted string is boxed into an interface{}
// and then type-asserted back to a string before reaching a SQL sink. Taint
// must survive the assertion (a pure value-derivation), or this SQL injection
// is silently missed.
package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	var boxed interface{} = r.URL.Query().Get("id") // tainted string in an interface{}
	id := boxed.(string)                             // type assertion (taint must survive)
	rows, err := db.Query("SELECT name FROM users WHERE id = '" + id + "'")
	if err != nil {
		return
	}
	defer rows.Close()
	_ = w
}

func main() {
	http.HandleFunc("/user", handler)
	_ = http.ListenAndServe(":8080", nil)
}
