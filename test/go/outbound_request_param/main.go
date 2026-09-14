// An OUTBOUND *http.Request passed as a parameter is not attacker-controlled.
//
// `sendVia` has the shape every HTTP helper takes: it receives a request to SEND.
// Seeding a request parameter on its type alone marks that request
// attacker-controlled and reports `client.Do(req)` as SSRF at HIGH confidence —
// on the program's own outbound call. A server hands a handler a ResponseWriter
// alongside the request; an outbound path never carries one.
//
// The sample is deliberately BOTH halves. `safeSend` must stay clean, and
// `vulnSend` must still fire: a control that only proves the sink went quiet
// would equally pass if Do stopped being a sink at all.
package main

import (
	"net/http"
)

// sendVia receives an outbound request. Nothing here is attacker-controlled.
func sendVia(client *http.Client, req *http.Request) {
	_, _ = client.Do(req)
}

// safeSend builds a request against a constant URL and sends it.
func safeSend(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("GET", "https://api.internal.example.com/v1/status", nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Trace", r.URL.Query().Get("trace")) // a header: not a destination
	sendVia(http.DefaultClient, req)
	_ = w
}

// vulnSend puts request data in the URL, which IS server-side request forgery.
func vulnSend(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	req, err := http.NewRequest("GET", target, nil) // sink: tainted destination
	if err != nil {
		return
	}
	sendVia(http.DefaultClient, req)
	_ = w
}

func main() {
	http.HandleFunc("/safe", safeSend)
	http.HandleFunc("/vuln", vulnSend)
	_ = http.ListenAndServe(":8080", nil)
}
