// A reflected XSS via html/template's trusted-string conversion: the request
// value is wrapped in template.HTML, which BYPASSES the package's auto-escaping,
// so it renders unescaped in the response (gosec G203). template.HTML(x) is a
// type CONVERSION, not a call — the Go frontend synthesizes a sink CALL for it.
package main

import (
	"html/template"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	tmpl := template.Must(template.New("t").Parse(`<div>{{.}}</div>`))
	// Marking attacker input as trusted HTML defeats the auto-escaping.
	_ = tmpl.Execute(w, template.HTML(term))
}

func main() {
	http.HandleFunc("/search", handler)
	_ = http.ListenAndServe(":8080", nil)
}
