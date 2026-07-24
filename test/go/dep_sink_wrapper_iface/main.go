package main

// PRECISION CONTROL for the sink-parameter summary (mirrors an ORM like xorm).
// The dependency method orm.Find takes an interface{} "bean", and the engine's
// taint model OVER-APPROXIMATES the reflective query building inside it: taint on
// the bean appears to reach database/sql.Query#0, even though a real ORM binds the
// value as a parameter placeholder rather than concatenating it into the query.
// Because that flow enters through an interface{} (not a string) parameter, the
// sink-parameter summary is deliberately NOT formed, so this must yield NO finding.
// Without the string-parameter restriction, orm.Find would be reported at every
// call site -- the false-positive flood this control locks out. See taintsParamSink.

import (
	"database/sql"
	"net/http"

	"example.com/orm"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	cond := r.URL.Query().Get("cond") // untrusted request input
	orm.Find(db, cond)                // passed into an interface{} bean param
}

func main() {
	http.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {})
	_ = http.ListenAndServe(":8080", nil)
}
