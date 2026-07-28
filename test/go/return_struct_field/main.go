// A builder stores untrusted input into a STRUCT FIELD and returns the struct;
// the caller reads that field at a sink. Every argument site treats a struct with
// a tainted field as tainted, but the RETURN path used a plain-register check —
// and a field store marks the field path, never the base — so the two directions
// of the same boundary disagreed and the flow died at the return.
package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

type Query struct{ SQL string }

func build(r *http.Request) *Query {
	q := &Query{}
	q.SQL = "SELECT id FROM users WHERE name = '" + r.FormValue("name") + "'"
	return q
}

func handler(w http.ResponseWriter, r *http.Request) {
	q := build(r)
	_, _ = db.Query(q.SQL)
}

func main() { http.HandleFunc("/", handler) }
