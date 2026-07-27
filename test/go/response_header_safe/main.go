// Response-header read is NOT untrusted input: `w.Header()` is the handler's own
// outbound header map, populated by this server, and `resp.Header` on a client
// response is likewise not request data. Neither may seed taint.
//
// This is the control for a real false positive: the shared Go source fragment
// used to list `go:*net/http.Header*.Get` and `go:*net/url*.Get` as SOURCES, so
// every Go rule inherited them and reported a critical, high-confidence command
// injection here — with no attacker-controlled input anywhere in the file. Those
// accessors are default PROPAGATORS instead, which carries real request taint
// through the stdlib without inventing any.
package main

import (
	"net/http"
	"net/url"
	"os/exec"
)

func handler(w http.ResponseWriter, _ *http.Request) {
	// The server's OWN response header — server-controlled.
	ct := w.Header().Get("Content-Type")
	_ = exec.Command("/bin/echo", ct).Run()

	// A url.Values the server built itself — no request involved.
	own := url.Values{}
	own.Set("mode", "batch")
	_ = exec.Command("/bin/echo", own.Get("mode")).Run()
}

func main() { http.HandleFunc("/", handler) }
