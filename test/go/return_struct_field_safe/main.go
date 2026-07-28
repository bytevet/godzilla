// Control for return_struct_field: the returned struct's field holds only a
// constant, so making the RETURN path field-aware must not invent taint. This is
// the direction the change could go wrong — a struct reported as taint-returning
// because it HAS fields rather than because a field carries taint.
package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

type Query struct{ SQL string }

func build(_ *http.Request) *Query {
	q := &Query{}
	q.SQL = "SELECT id FROM users WHERE name = ?"
	return q
}

func handler(w http.ResponseWriter, r *http.Request) {
	q := build(r)
	_, _ = db.Query(q.SQL, r.FormValue("name"))
}

func main() { http.HandleFunc("/", handler) }
