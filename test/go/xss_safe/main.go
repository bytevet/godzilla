package main

import (
	"fmt"
	"html"
	"net/http"
)

func main() {
	http.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		// Safe: input is HTML-escaped before being written into the response,
		// so no reflected XSS - this must produce ZERO findings.
		fmt.Fprintf(w, "<h1>Hello %s</h1>", html.EscapeString(name))
	})
	fmt.Println("Server starting on :8084")
	http.ListenAndServe(":8084", nil)
}
