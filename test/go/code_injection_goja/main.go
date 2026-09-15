// Code injection via an embedded JS interpreter: the query parameter reaches
// goja's Runtime.RunString, which compiles and executes it as JavaScript.
package main

import (
	"net/http"

	"github.com/dop251/goja"
)

func handler(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("expr")
	vm := goja.New()
	_, _ = vm.RunString(expr)
}

func main() {
	http.HandleFunc("/eval", handler)
	_ = http.ListenAndServe(":8080", nil)
}
