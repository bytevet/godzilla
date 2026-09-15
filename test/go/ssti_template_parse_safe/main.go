// Safe control: the template SOURCE is a compile-time CONSTANT and the
// request value is only passed as Execute CONTEXT — the normal, safe path —
// so the go-ssti #0 pin on Parse must not fire.
//
// html/template, not text/template: rendering the value into the response is
// then auto-escaped, so the sample is clean for ONE reason (the pin) rather
// than silently asserting that an unescaped render is fine too.
package main

import (
	"html/template"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	tmpl, err := template.New("t").Parse("Hello, {{.}}!")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = tmpl.Execute(w, name)
}

func main() {
	http.HandleFunc("/greet", handler)
	_ = http.ListenAndServe(":8080", nil)
}
