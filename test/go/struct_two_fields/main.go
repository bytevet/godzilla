// A builder stores request data into ONE field of a struct and returns it; the
// caller reads a DIFFERENT field into a sink. A return summary that taints the
// struct as a whole makes every field of it untrusted, which is how a database
// primary key read off a returned record reached an exec() argument.
//
// test/go/return_struct_field pins the other direction — reading the TAINTED
// field must still fire — but its struct has a single field, so it cannot tell
// a field-precise return from a whole-value one. Two fields can.
package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

type query struct {
	Filter string // request-derived
	Table  string // fixed by the server
}

func build(r *http.Request) *query {
	q := &query{}
	q.Filter = r.FormValue("name")
	q.Table = "users"
	return q
}

func handler(w http.ResponseWriter, r *http.Request) {
	q := build(r)
	_, _ = db.Query("SELECT id FROM " + q.Table)
}

func main() { http.HandleFunc("/", handler) }
