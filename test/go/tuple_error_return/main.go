// A helper returning (value, error) where only the VALUE half is request-derived.
// A callee's return taint used to land on the whole call-result register, and
// EXTRACT propagated it blanket-wise, so the error half inherited it — and an
// error string is laundered into everything a program formats from it, which is
// how six false SSRF findings on one real service all began at one `err`.
//
// Both halves are exercised: the error half must stay clean, the value half must
// still reach the sink. A control that only proves the negative would pass just
// as well if the return channel stopped working altogether.
package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
)

var db *sql.DB

func lookup(r *http.Request) (string, error) {
	name := r.FormValue("name")
	if name == "" {
		return "", errors.New("name is required")
	}
	return name, nil
}

// safeHandler sinks the ERROR half: element 1 of the tuple, which nothing
// request-derived ever reached.
func safeHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := lookup(r); err != nil {
		_, _ = db.Query(fmt.Sprintf("INSERT INTO audit(reason) VALUES('%v')", err))
	}
}

// vulnHandler sinks the VALUE half: element 0, which is the request parameter.
func vulnHandler(w http.ResponseWriter, r *http.Request) {
	name, _ := lookup(r)
	_, _ = db.Query("SELECT id FROM users WHERE name = '" + name + "'") // SQL injection (sink)
}

func main() {
	http.HandleFunc("/safe", safeHandler)
	http.HandleFunc("/vuln", vulnHandler)
}
