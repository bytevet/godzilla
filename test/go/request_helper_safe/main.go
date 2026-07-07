package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func name(r *http.Request) string {
	return r.FormValue("name")
}

// Safe control: the request value crosses into the handler via a helper but
// reaches only the BOUND parameter of a parameterized query (arg #1), never the
// query text (#0), so no finding must fire even with inter-proc provenance.
func handler(w http.ResponseWriter, r *http.Request) {
	_, _ = db.Query("SELECT * FROM t WHERE name = ?", name(r))
}

func main() {
	http.HandleFunc("/run", handler)
	_ = http.ListenAndServe(":8080", nil)
}
