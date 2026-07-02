// Path traversal via http.ServeFile: an untrusted query parameter is spliced
// into the path served over HTTP, so "../../etc/passwd" escapes the intended
// directory. http.ServeFile(w, r, name) is the textbook Go path-traversal
// sink; its path is logical argument 2.
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")       // source
	http.ServeFile(w, r, "/var/data/"+name) // sink: path is arg 2
}

func main() {
	http.HandleFunc("/download", handler)
	_ = http.ListenAndServe(":8080", nil)
}
