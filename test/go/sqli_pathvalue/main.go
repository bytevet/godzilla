// SQL injection sourced from a Go 1.22+ path parameter (r.PathValue). A
// path segment like /users/{id} is fully attacker-controlled, so PathValue
// is an untrusted source; here it flows unparameterized into a query.
package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id") // source: Go 1.22+ path parameter
	rows, err := db.Query("SELECT name FROM users WHERE id = '" + id + "'")
	if err != nil {
		return
	}
	defer rows.Close()
	_ = w
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{id}", handler)
	_ = http.ListenAndServe(":8080", mux)
}
