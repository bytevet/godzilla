// Neither the handler's own response headers nor a self-built url.Values is
// untrusted input, so neither may seed taint. Control for the false positive
// caused by listing the net/http and net/url accessors as sources: every Go rule
// inherited them and fired critical here, with no attacker input in the file.
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
