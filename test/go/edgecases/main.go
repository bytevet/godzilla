package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

var db *sql.DB

func main() {
	// C1: a deferred sink — the tainted query must be detected even though the
	// call is wrapped in `defer`.
	http.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		q := r.FormValue("q")
		defer db.Query("SELECT * FROM t WHERE x = '" + q + "'")
	})
	// C4: taint written into a map and read back out into a command sink.
	http.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		m := make(map[string]string)
		m["cmd"] = r.FormValue("cmd")
		_ = exec.Command(m["cmd"])
	})
	http.ListenAndServe(":0", nil)
}
