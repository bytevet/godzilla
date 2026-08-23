package main

import (
	"net/http"
	"net/url"
	"regexp"
)

var rePrefix = regexp.MustCompile(`^(?:/\\|/+)`)

func main() {
	// A rule-declared sanitizer still wins over the regexp propagator.
	http.HandleFunc("/escaped", func(w http.ResponseWriter, r *http.Request) {
		target := rePrefix.ReplaceAllString(r.URL.Path, "/")
		http.Redirect(w, r, url.PathEscape(target), http.StatusFound)
	})

	// The subject is a constant, so the regexp has nothing to carry.
	http.HandleFunc("/constant", func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, nil, rePrefix.ReplaceAllString("//home/", "/"), http.StatusFound)
	})

	http.ListenAndServe(":8080", nil)
}
