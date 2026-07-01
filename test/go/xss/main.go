package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		// Vulnerable: reflected XSS - untrusted input written unescaped into HTML response
		fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
	})
	fmt.Println("Server starting on :8083")
	http.ListenAndServe(":8083", nil)
}
