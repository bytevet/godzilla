package main

import "net/http"

func main() {
	http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")             // untrusted input
		http.Redirect(w, r, target, http.StatusFound)  // open redirect (url is arg 2)
	})
	http.ListenAndServe(":8080", nil)
}
