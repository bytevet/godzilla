// Safe control: url.Parse operates on a constant URL, so the parsed URL's path
// carries no taint and the file read must not fire. Proves the url.Parse
// propagator only FORWARDS existing taint and never manufactures it.
package main

import (
	"net/http"
	"net/url"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse("https://cdn.internal/assets/logo.png")
	if err != nil {
		return
	}
	data, _ := os.ReadFile(u.Path)
	w.Write(data)
}

func main() {
	http.HandleFunc("/x", handler)
	http.ListenAndServe(":8080", nil)
}
