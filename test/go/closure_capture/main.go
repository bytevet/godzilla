// Taint captured into a goroutine closure: the request value `id` is read in the
// handler and used, inside a `go func(){...}()`, in a SQL query. The closure
// captures `id` as a free variable, so taint must flow from the capture into the
// goroutine body for the sink to be flagged.
package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id") // source, captured by the goroutine below
	go func() {
		_, _ = db.Query("SELECT * FROM users WHERE id = '" + id + "'") // sink
	}()
	_ = w
}

func main() {
	http.HandleFunc("/u", handler)
	_ = http.ListenAndServe(":8080", nil)
}
