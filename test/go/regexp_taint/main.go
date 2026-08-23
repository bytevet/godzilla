package main

import (
	"fmt"
	"net/http"
	"regexp"
)

// The shape of grafana CVE-2025-4123: a regexp meant to collapse a leading "//"
// or "/\" into "/" is the only guard on the redirect target, and a pattern that
// misses a case leaves the open redirect reachable.
var rePrefix = regexp.MustCompile(`^(?:/\\|/+)`)

func main() {
	http.HandleFunc("/replace", func(w http.ResponseWriter, r *http.Request) {
		target := fmt.Sprintf("%s/", r.URL.Path)
		target = rePrefix.ReplaceAllString(target, "/")
		http.Redirect(w, r, target, http.StatusFound)
	})

	// Extraction, not replacement: the result is a substring of the subject.
	http.HandleFunc("/find", func(w http.ResponseWriter, r *http.Request) {
		target := rePrefix.FindString(r.URL.Query().Get("next"))
		http.Redirect(w, r, target, http.StatusFound)
	})

	http.ListenAndServe(":8080", nil)
}
