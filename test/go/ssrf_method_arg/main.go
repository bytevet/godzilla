// FALSE-POSITIVE CONTROL for the SSRF injection point.
//
// Every argument of a request builder carries user data here EXCEPT the URL,
// which is a constant. An SSRF sink that does not pin its injection point reads
// the HTTP method and the request body as a tainted destination and fires on
// both — which is how a header value routed through a request builder was
// reported as server-side request forgery.
//
// expected.yaml declares no findings: nothing attacker-controlled reaches a
// destination URL.
package main

import (
	"net/http"
	"strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Query().Get("method") // into arg 0 of NewRequest
	body := r.URL.Query().Get("body")     // into arg 2

	req, err := http.NewRequest(method, "https://api.internal.example.com/v1/run", strings.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("X-Cluster", r.URL.Query().Get("cluster")) // a header, not a URL
	_, _ = http.DefaultClient.Do(req)
	_ = w
}

func main() {
	http.HandleFunc("/run", handler)
	_ = http.ListenAndServe(":8080", nil)
}
