// Safe control: the request value is rendered through html/template WITHOUT a
// trusted-type conversion, so the package auto-escapes it by context — no XSS.
// The only template.HTML conversion here wraps a compile-time constant, which is
// untainted and must not fire.
package main

import (
	"html/template"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	tmpl := template.Must(template.New("t").Parse(`<div>{{.}}</div>`))
	_ = tmpl.Execute(w, term)             // auto-escaped: safe
	_ = template.HTML("<b>static</b>")    // constant arg: untainted, must not fire
}

func main() {
	http.HandleFunc("/search", handler)
	_ = http.ListenAndServe(":8080", nil)
}
