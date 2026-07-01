package main

import (
	"fmt"
	"io"
	"net/http"
)

func main() {
	http.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		userURL := r.URL.Query().Get("url")
		// Vulnerable: server-side request forgery - untrusted URL used directly in outbound request
		resp, err := http.Get(userURL)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	})
	fmt.Println("Server starting on :8084")
	http.ListenAndServe(":8084", nil)
}
