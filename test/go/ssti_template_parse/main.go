// Server-side template injection: the query parameter becomes the TEMPLATE
// SOURCE text/template compiles and executes, not merely data substituted
// into a fixed template.
package main

import (
	"net/http"
	"text/template"
)

func handler(w http.ResponseWriter, r *http.Request) {
	tplSrc := r.URL.Query().Get("tpl")
	tmpl, err := template.New("t").Parse(tplSrc)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = tmpl.Execute(w, nil)
}

func main() {
	http.HandleFunc("/render", handler)
	_ = http.ListenAndServe(":8080", nil)
}
